/* Native single-instruction executor for the CPU differential tests (lift/test/cpu).
 *
 *   wine harness.exe <image.bin> <tests.bin> <results.bin> [first]
 *
 * Runs under 32-bit Wine, so every test instruction executes natively on the host CPU (the
 * CPU the oracle runs on). The rct.exe image (image.bin: the mapped image with the IAT filled
 * with host addresses, written by cpudiff.py from the user's rct.exe) is placed at 0x400000
 * with the section protections of the lift; scratch memory at 0x02000000-0x02900000.
 *
 * Each test: copy the input memory regions, load all registers and EFLAGS (with TF set) with
 * an IRETD to the instruction, which executes exactly one instruction (REP string
 * instructions: until done) and traps. A vectored handler captures the CONTEXT and resumes the
 * harness. Output per test: exception code, fault address, registers, eip, eflags, and the
 * regions' bytes after the instruction.
 *
 * File formats: lift/test/cpu/README.md. Nothing here reads or writes game data except the
 * image and test files given on the command line (all under out/, git-ignored).
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, eflags; } Regs;

Regs g_in;
volatile Regs g_out;
volatile uint32_t g_code, g_faddr;
volatile uint32_t g_saved_esp;
volatile int g_in_test, g_rep;
volatile int g_steps;

void run_one(void);
__asm__(".section .rctimg,\"bwx\"\n.globl _rctimg\n_rctimg:\n.space 0x5C3000\n.text\n");
extern uint8_t rctimg[];
void resume_point(void);

__asm__(
    ".intel_syntax noprefix\n"
    ".globl _run_one\n"
    "_run_one:\n"
    "  pushad\n"
    "  pushfd\n"
    "  mov [_g_saved_esp], esp\n"
    "  mov eax, offset _g_in\n"
    "  mov ecx, [eax+16]\n"
    "  sub ecx, 12\n"
    "  mov edx, [eax+32]\n"
    "  mov [ecx], edx\n"
    "  xor edx, edx\n"
    "  mov dx, cs\n"
    "  mov [ecx+4], edx\n"
    "  mov edx, [eax+36]\n"
    "  mov [ecx+8], edx\n"
    "  mov esp, ecx\n"
    "  mov ecx, [eax+4]\n"
    "  mov edx, [eax+8]\n"
    "  mov ebx, [eax+12]\n"
    "  mov ebp, [eax+20]\n"
    "  mov esi, [eax+24]\n"
    "  mov edi, [eax+28]\n"
    "  mov eax, [eax+0]\n"
    "  iretd\n"
    ".globl _resume_point\n"
    "_resume_point:\n"
    "  mov esp, [_g_saved_esp]\n"
    "  popfd\n"
    "  popad\n"
    "  ret\n"
    ".att_syntax prefix\n");

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
    if (!g_in_test) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT *c = ep->ContextRecord;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    g_steps++;
    if (code == EXCEPTION_SINGLE_STEP && g_rep && c->Eip == g_in.eip && c->Ecx != 0 && g_steps < 100000) {
        c->EFlags |= 0x100;               /* REP: one trap per iteration; keep going */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    g_out.eax = c->Eax; g_out.ecx = c->Ecx; g_out.edx = c->Edx; g_out.ebx = c->Ebx;
    g_out.esp = c->Esp; g_out.ebp = c->Ebp; g_out.esi = c->Esi; g_out.edi = c->Edi;
    g_out.eip = c->Eip; g_out.eflags = c->EFlags;
    g_code = code;
    g_faddr = ep->ExceptionRecord->NumberParameters >= 2 ? (uint32_t)ep->ExceptionRecord->ExceptionInformation[1] : 0;
    g_in_test = 0;
    c->Eip = (DWORD)(uintptr_t)resume_point;
    c->Esp = g_saved_esp;
    c->EFlags = 0x202;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void die(const char *m) { fprintf(stderr, "harness: %s (err %lu)\n", m, GetLastError()); exit(2); }

static void *xalloc(uint32_t a, uint32_t n, DWORD prot) {
    void *p = VirtualAlloc((void *)(uintptr_t)a, n, MEM_RESERVE | MEM_COMMIT, prot);
    if (p != (void *)(uintptr_t)a) { fprintf(stderr, "harness: cannot map %08x+%x\n", a, n); exit(2); }
    return p;
}

/* rct.exe section layout (page-aligned spans) and the lift's protections */
static const struct { uint32_t lo, hi; DWORD prot; } SECT[] = {
    {0x400000, 0x401000, PAGE_READONLY},           /* headers */
    {0x401000, 0x41C000, PAGE_EXECUTE_READ},       /* .text */
    {0x41C000, 0x5E7000, PAGE_EXECUTE_READ},       /* CODESEG */
    {0x5E7000, 0x5E9000, PAGE_READONLY},           /* .rdata */
    {0x5E9000, 0x9B3000, PAGE_READWRITE},          /* .data DATASEG DataSeg */
    {0x9B3000, 0x9BD000, PAGE_EXECUTE_READ},       /* CodeSeg (code: read-only in the lift) */
    {0x9BD000, 0x9C4000, PAGE_READONLY},           /* .rsrc */
};

static uint8_t *readall(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) die(path);
    fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*n);
    if (fread(b, 1, *n, f) != *n) die("short read");
    fclose(f);
    return b;
}

#define RD(p) (*(uint32_t *)(p))

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: harness image.bin tests.bin results.bin [first]\n"); return 2; }
    size_t ni, nt;
    uint8_t *img = readall(argv[1], &ni);
    if (ni != 0x5C4000) die("image.bin size");
    /* .rctimg (this executable's own uninitialised section) spans 0x401000-0x9C4000; the
       harness's PE header page at 0x400000 stays (rct.exe's headers are not test inputs). */
    if ((uintptr_t)rctimg != 0x401000) die("harness not linked with .rctimg at 0x401000");
    { DWORD old; if (!VirtualProtect(rctimg, 0x5C3000, PAGE_EXECUTE_READWRITE, &old)) die("VirtualProtect rw"); }
    memcpy(rctimg, img + 0x1000, ni - 0x1000);
    for (unsigned k = 1; k < sizeof SECT / sizeof SECT[0]; k++) {
        DWORD old;
        if (!VirtualProtect((void *)(uintptr_t)SECT[k].lo, SECT[k].hi - SECT[k].lo, SECT[k].prot, &old)) die("VirtualProtect");
    }
    xalloc(0x02000000, 0x00100000, PAGE_READWRITE);          /* data scratch */
    xalloc(0x02100000, 0x00300000, PAGE_READWRITE);          /* stack scratch */
    xalloc(0x02800000, 0x00100000, PAGE_EXECUTE_READWRITE);  /* synthetic code */

    uint8_t *t = readall(argv[2], &nt);
    if (memcmp(t, "CPT1", 4)) die("tests.bin magic");
    uint32_t count = RD(t + 4);
    uint32_t first = argc > 4 ? (uint32_t)atoi(argv[4]) : 0;
    FILE *out = fopen(argv[3], first ? "ab" : "wb");
    if (!out) die(argv[3]);
    if (!first) {
        uint16_t cs; __asm__ volatile("mov %%cs, %0" : "=r"(cs));
        uint32_t hdr[4] = {0x31525043 /* CPR1 */, count, cs, 0};
        fwrite(hdr, 4, 4, out);
    }
    AddVectoredExceptionHandler(1, veh);

    uint8_t *p = t + 8;
    for (uint32_t k = 0; k < count; k++) {
        uint8_t *rec = p;
        uint32_t addr = RD(p), flags = RD(p + 4);
        p += 8;
        Regs in;
        memcpy(&in, p, 32); p += 32;
        in.eflags = RD(p); p += 4;
        in.eip = addr;
        uint32_t ncode = RD(p); p += 4;
        uint8_t *code = p; p += (ncode + 3) & ~3u;
        uint32_t nreg = RD(p); p += 4;
        uint8_t *regs = p;
        for (uint32_t r = 0; r < nreg; r++) { uint32_t len = RD(p + 4); p += 12 + ((len + 3) & ~3u); }
        if (k < first) continue;
        (void)rec;
        /* inputs */
        if (ncode) memcpy((void *)(uintptr_t)addr, code, ncode);
        uint8_t *q = regs;
        for (uint32_t r = 0; r < nreg; r++) {
            uint32_t a = RD(q), len = RD(q + 4), rf = RD(q + 8);
            if (!(rf & 1)) memcpy((void *)(uintptr_t)a, q + 12, len);     /* bit0: read-only region, keep */
            q += 12 + ((len + 3) & ~3u);
        }
        g_in = in;
        g_in.eflags = in.eflags | 0x100 | 0x200 | 0x2;
        g_rep = (flags & 1) != 0;
        g_steps = 0;
        g_code = 0;
        g_in_test = 1;
        run_one();
        /* outputs */
        uint32_t res[12] = {g_code, g_faddr, g_out.eax, g_out.ecx, g_out.edx, g_out.ebx, g_out.esp, g_out.ebp,
                            g_out.esi, g_out.edi, g_out.eip, g_out.eflags};
        fwrite(res, 4, 12, out);
        q = regs;
        for (uint32_t r = 0; r < nreg; r++) {
            uint32_t a = RD(q), len = RD(q + 4);
            fwrite((void *)(uintptr_t)a, 1, len, out);
            static const uint8_t z[4];
            fwrite(z, 1, ((len + 3) & ~3u) - len, out);
            q += 12 + ((len + 3) & ~3u);
        }
        if ((k & 1023) == 0) fflush(out);
    }
    fclose(out);
    return 0;
}
