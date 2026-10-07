/* Measurement modes for scoping later stages. Off unless RCTHOOK_SPIKE is set; never used by a
 * gate. RCTHOOK_SPIKE is a comma-separated list of:
 *
 *   codewatch     compare .text, CODESEG and CodeSeg with their previous contents every frame and
 *                 log every changed range (self-modifying code detection)
 *   apicount      count every call through rct.exe's IAT, every procedure it resolves with
 *                 GetProcAddress, and every DirectDraw COM method; written to api_counts.txt
 *   heapshift=N   before the game starts, allocate and leak N bytes from the process heap, the
 *                 global heap and VirtualAlloc, and 7 OS handles, shifting where later
 *                 allocations land and which handle values the game receives
 *   memmap        at quit, write the process's committed memory regions (memmap.txt) with the
 *                 module owning each, to size the lift's memory model
 *   cover=FILE    one-shot int3 at every address listed in FILE (little-endian uint32, e.g. the
 *                 basic-block starts of a static CFG); at quit write cover_hits.bin (the addresses
 *                 that executed, uint32). Addresses inside this DLL's inline-hook patches are
 *                 skipped (they run every tick or frame).
 *   istep=A:B     single-step every instruction rct.exe executes from the start of tick A to the
 *                 start of tick B+1: per-tick instruction counts (istep_ticks.txt) and an
 *                 executed-instruction bitmap over 0x401000-0x9BD000 (istep_cov.bin, 1 bit/byte).
 *                 Game code entered from outside while stepping (the window procedure, routines
 *                 called by script actions) is stepped too.
 *   regs          with istep: every stepped game instruction's eip, registers and flags, and the
 *                 memory it wrote, to istep_regs.bin (format: oracle/README.md)
 *   wmem=LO-HI    with regs: record only writes to [LO, HI); wmem=none records no writes
 *   apitrace      every OS call, COM method call and OS-to-game callback, to apitrace.txt
 *                 (apitrace.c; format: oracle/README.md); RCTHOOK_PERTURB experiments
 *   ptrscan       every tick, state dwords (2-byte steps) holding an address of OS memory -> ptrscan.txt
 *   watch=FILE    every tick, every listed state address whose dword changed -> watch.bin
 *                 (ptrscan + watch on clean and heapshift runs audit oracle/mask.h: tools/maskaudit.py)
 * heapshift=N also shifts USER and GDI handle numbers (windows, cursors, pens, brushes, a DC).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spike.h"

static int s_codewatch, s_apicount, s_istep, s_memmap, s_apitrace;
static uint32_t s_cur_frame;
static char s_cover_path[MAX_PATH];
static uint32_t s_heapshift, s_step_from, s_step_to;

/* ------------------------------------------------------------------ codewatch */
static const struct { uint32_t lo, hi; const char *name; } code_sections[] = {
    {0x401000, 0x41B1A6, ".text"}, {0x41C000, 0x5E6C5D, "CODESEG"}, {0x9B3000, 0x9BC562, "CodeSeg"},
};
static uint8_t *s_code_copy[3];
static uint32_t s_code_changes;

static void codewatch_snapshot(void)
{
    for (int i = 0; i < 3; i++) {
        uint32_t n = code_sections[i].hi - code_sections[i].lo;
        if (!s_code_copy[i]) s_code_copy[i] = malloc(n);
        memcpy(s_code_copy[i], (void *)code_sections[i].lo, n);
    }
}
static void codewatch_check(uint32_t frame, uint32_t tick)
{
    for (int i = 0; i < 3; i++) {
        const uint8_t *now = (const uint8_t *)code_sections[i].lo;
        uint8_t *old = s_code_copy[i];
        uint32_t n = code_sections[i].hi - code_sections[i].lo;
        if (!memcmp(now, old, n)) continue;
        for (uint32_t j = 0; j < n; j++) {
            if (now[j] == old[j]) continue;
            uint32_t k = j;
            while (k < n && (now[k] != old[k] || (k + 1 < n && now[k + 1] != old[k + 1]))) k++;
            if (s_code_changes < 2000)
                spike_log("codewatch: frame %u tick %u %s %#x len %u old %02x%02x%02x%02x new %02x%02x%02x%02x\n",
                          frame, tick, code_sections[i].name, code_sections[i].lo + j, k - j,
                          old[j], old[j + 1], old[j + 2], old[j + 3], now[j], now[j + 1], now[j + 2], now[j + 3]);
            s_code_changes++;
            memcpy(old + j, now + j, k - j);
            j = k;
        }
    }
}

/* ------------------------------------------------------------------ apicount */
typedef struct { char name[64]; volatile uint32_t count; void *orig; } apistat_t;
#define MAX_API 1024
static apistat_t s_api[MAX_API];
static int s_napi;
static uint8_t *s_thunks; static uint32_t s_thunk_used;

static apistat_t *api_new(const char *name, void *orig)
{
    if (s_napi >= MAX_API) return NULL;
    apistat_t *a = &s_api[s_napi++];
    snprintf(a->name, sizeof a->name, "%s", name);
    a->orig = orig;
    return a;
}
/* thunk: inc dword [count] ; jmp dword [orig] -- registers and stack untouched */
static void *count_thunk(const char *name, void *orig)
{
    apistat_t *a = api_new(name, orig);
    if (!a) return orig;
    uint8_t *p = s_thunks + s_thunk_used;
    p[0] = 0xFF; p[1] = 0x05; *(uint32_t *)(p + 2) = (uint32_t)&a->count;
    p[6] = 0xFF; p[7] = 0x25; *(uint32_t *)(p + 8) = (uint32_t)&a->orig;
    s_thunk_used += 16;
    return p;
}

/* DirectDraw: method names per interface (vtable order) */
static const char *dd_names[] = {"QueryInterface", "AddRef", "Release", "Compact", "CreateClipper",
    "CreatePalette", "CreateSurface", "DuplicateSurface", "EnumDisplayModes", "EnumSurfaces",
    "FlipToGDISurface", "GetCaps", "GetDisplayMode", "GetFourCCCodes", "GetGDISurface",
    "GetMonitorFrequency", "GetScanLine", "GetVerticalBlankStatus", "Initialize", "RestoreDisplayMode",
    "SetCooperativeLevel", "SetDisplayMode", "WaitForVerticalBlank"};
static const char *surf_names[] = {"QueryInterface", "AddRef", "Release", "AddAttachedSurface",
    "AddOverlayDirtyRect", "Blt", "BltBatch", "BltFast", "DeleteAttachedSurface", "EnumAttachedSurfaces",
    "EnumOverlayZOrders", "Flip", "GetAttachedSurface", "GetBltStatus", "GetCaps", "GetClipper",
    "GetColorKey", "GetDC", "GetFlipStatus", "GetOverlayPosition", "GetPalette", "GetPixelFormat",
    "GetSurfaceDesc", "Initialize", "IsLost", "Lock", "ReleaseDC", "Restore", "SetClipper",
    "SetColorKey", "SetOverlayPosition", "SetPalette", "Unlock", "UpdateOverlay", "UpdateOverlayDisplay",
    "UpdateOverlayZOrder"};
static const char *pal_names[] = {"QueryInterface", "AddRef", "Release", "GetCaps", "GetEntries",
    "Initialize", "SetEntries"};
static const char *clip_names[] = {"QueryInterface", "AddRef", "Release", "GetClipList", "GetHWnd",
    "Initialize", "IsClipListChanged", "SetClipList", "SetHWnd"};

static void *s_patched_vt[32]; static int s_npatched;
static HRESULT (WINAPI *o_CreateSurface)(void *, void *, void **, void *);
static HRESULT (WINAPI *o_CreatePalette)(void *, DWORD, void *, void **, void *);
static HRESULT (WINAPI *o_CreateClipper)(void *, DWORD, void **, void *);
static HRESULT (WINAPI *o_GetAttached)(void *, void *, void **);
static HRESULT (WINAPI *o_DDQI)(void *, REFIID, void **);
static apistat_t *c_CreateSurface, *c_CreatePalette, *c_CreateClipper, *c_GetAttached, *c_DDQI;

static void patch_vtable(void *obj, const char *iface, const char **names, int n);
static HRESULT WINAPI w_CreateSurface(void *t, void *desc, void **out, void *u)
{
    c_CreateSurface->count++;
    HRESULT h = o_CreateSurface(t, desc, out, u);
    if (h == 0 && out && *out) patch_vtable(*out, "IDirectDrawSurface", surf_names, 36);
    return h;
}
static HRESULT WINAPI w_GetAttached(void *t, void *caps, void **out)
{
    c_GetAttached->count++;
    HRESULT h = o_GetAttached(t, caps, out);
    if (h == 0 && out && *out) patch_vtable(*out, "IDirectDrawSurface", surf_names, 36);
    return h;
}
static HRESULT WINAPI w_CreatePalette(void *t, DWORD f, void *e, void **out, void *u)
{
    c_CreatePalette->count++;
    HRESULT h = o_CreatePalette(t, f, e, out, u);
    if (h == 0 && out && *out) patch_vtable(*out, "IDirectDrawPalette", pal_names, 7);
    return h;
}
static HRESULT WINAPI w_CreateClipper(void *t, DWORD f, void **out, void *u)
{
    c_CreateClipper->count++;
    HRESULT h = o_CreateClipper(t, f, out, u);
    if (h == 0 && out && *out) patch_vtable(*out, "IDirectDrawClipper", clip_names, 9);
    return h;
}
static HRESULT WINAPI w_DDQI(void *t, REFIID r, void **out)
{
    c_DDQI->count++;
    HRESULT h = o_DDQI(t, r, out);
    spike_log("apicount: IDirectDraw::QueryInterface {%08lx-%04x-%04x} -> %#lx\n",
              r->Data1, r->Data2, r->Data3, (unsigned long)h);
    return h;
}

static void patch_vtable(void *obj, const char *iface, const char **names, int n)
{
    void **vt = *(void ***)obj;
    for (int i = 0; i < s_npatched; i++) if (s_patched_vt[i] == vt) return;
    if (s_npatched < 32) s_patched_vt[s_npatched++] = vt;
    DWORD old; VirtualProtect(vt, n * 4, PAGE_READWRITE, &old);
    for (int i = 0; i < n; i++) {
        char nm[64]; snprintf(nm, sizeof nm, "%s::%s", iface, names[i]);
        void *w = NULL;
        if (!strcmp(iface, "IDirectDraw")) {
            if (i == 6) { c_CreateSurface = api_new(nm, vt[i]); o_CreateSurface = vt[i]; w = w_CreateSurface; }
            if (i == 5) { c_CreatePalette = api_new(nm, vt[i]); o_CreatePalette = vt[i]; w = w_CreatePalette; }
            if (i == 4) { c_CreateClipper = api_new(nm, vt[i]); o_CreateClipper = vt[i]; w = w_CreateClipper; }
            if (i == 0) { c_DDQI = api_new(nm, vt[i]); o_DDQI = vt[i]; w = w_DDQI; }
        }
        if (!strcmp(iface, "IDirectDrawSurface") && i == 12) {
            c_GetAttached = api_new(nm, vt[i]); o_GetAttached = vt[i]; w = w_GetAttached;
        }
        vt[i] = w ? w : count_thunk(nm, vt[i]);
    }
    VirtualProtect(vt, n * 4, old, &old);
    spike_log("apicount: patched %s vtable %p (%d methods)\n", iface, vt, n);
}

static HRESULT (WINAPI *o_DirectDrawCreate)(void *, void **, void *);
static apistat_t *c_DirectDrawCreate;
static HRESULT WINAPI w_DirectDrawCreate(void *guid, void **out, void *u)
{
    c_DirectDrawCreate->count++;
    HRESULT h = o_DirectDrawCreate(guid, out, u);
    if (h == 0 && out && *out) patch_vtable(*out, "IDirectDraw", dd_names, 23);
    return h;
}
static FARPROC (WINAPI *o_GetProcAddress)(HMODULE, LPCSTR);
static FARPROC WINAPI w_GetProcAddress(HMODULE m, LPCSTR name)
{
    FARPROC f = o_GetProcAddress(m, name);
    char mod[MAX_PATH] = "?"; GetModuleFileNameA(m, mod, sizeof mod);
    const char *base = strrchr(mod, '\\'); base = base ? base + 1 : mod;
    char nm[64];
    if (HIWORD(name)) snprintf(nm, sizeof nm, "%s!%s", base, name);
    else snprintf(nm, sizeof nm, "%s!#%u", base, LOWORD(name));
    spike_log("apicount: GetProcAddress(%s) -> %p\n", nm, f);
    if (!f) return f;
    if (HIWORD(name) && !strcmp(name, "DirectDrawCreate")) {
        o_DirectDrawCreate = (void *)f; c_DirectDrawCreate = api_new(nm, f);
        return (FARPROC)w_DirectDrawCreate;
    }
    return (FARPROC)count_thunk(nm, (void *)f);
}

static void apicount_install(void)
{
    s_thunks = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    /* walk rct.exe's import descriptors (IAT 0x5E7000..) and wrap every slot */
    uint8_t *base = (uint8_t *)0x400000;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR *imp = (void *)(base + d.VirtualAddress); imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        IMAGE_THUNK_DATA *names = (void *)(base + imp->OriginalFirstThunk);
        void **slots = (void **)(base + imp->FirstThunk);
        for (int i = 0; names[i].u1.AddressOfData; i++) {
            char nm[64];
            if (names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                snprintf(nm, sizeof nm, "%s!#%lu", dll, (unsigned long)(names[i].u1.Ordinal & 0xFFFF));
            else
                snprintf(nm, sizeof nm, "%s!%s", dll,
                         ((IMAGE_IMPORT_BY_NAME *)(base + names[i].u1.AddressOfData))->Name);
            DWORD old; VirtualProtect(&slots[i], 4, PAGE_READWRITE, &old);
            if (!strcmp(nm, "KERNEL32.dll!GetProcAddress")) {
                o_GetProcAddress = slots[i];
                slots[i] = count_thunk(nm, (void *)w_GetProcAddress);
            } else {
                slots[i] = count_thunk(nm, slots[i]);
            }
            VirtualProtect(&slots[i], 4, old, &old);
        }
    }
}

static int cmp_api(const void *a, const void *b)
{
    const apistat_t *x = a, *y = b;
    return x->count != y->count ? (x->count < y->count) - (x->count > y->count) : strcmp(x->name, y->name);
}
static void apicount_write(void)
{
    qsort(s_api, s_napi, sizeof *s_api, cmp_api);
    HANDLE f = spike_open("api_counts.txt"); DWORD w; char line[160];
    for (int i = 0; i < s_napi; i++) {
        int n = snprintf(line, sizeof line, "%10u %s\n", s_api[i].count, s_api[i].name);
        WriteFile(f, line, n, &w, NULL);
    }
    CloseHandle(f);
}

/* ------------------------------------------------------------------ istep */
/* Single-stepping (trap flag) through game code, with optional register and memory-write capture
 * (RCTHOOK_SPIKE=istep=A:B,regs[,wmem=LO-HI|none]) into istep_regs.bin; format in oracle/README.md
 * ("Register capture"). Leaving game code by call/jmp pauses stepping until a one-shot int3 at
 * the return address fires; game code entered from outside (the window procedure while stepping,
 * routines called by script actions) is announced by spike_guest_call and stepped too. Instructions
 * the inline hooks displaced into their stubs are recorded at their original addresses. */
#define IMG_LO 0x401000u
#define IMG_HI 0x9BD000u
static uint8_t *s_cov;                  /* 1 bit per byte of the image range */
static volatile int s_stepping;
static int s_paused;                    /* stepping, but executing outside game code */
static uint64_t s_steps, s_outside_calls;
static uint32_t s_stub_lo, s_stub_hi;
static HANDLE s_regfile = INVALID_HANDLE_VALUE;
static char *s_tickbuf; static uint32_t s_ticklen;
static uint64_t s_steps_at_tick;
static uint32_t s_unknown_eips, s_bp_conflicts;
static int s_regs;                      /* register capture on */
static uint32_t s_wlo = 0, s_whi = 0xFFFFFFFFu;
static uint8_t *s_rbuf; static uint32_t s_rlen; static uint64_t s_rrecs, s_wrecs;
#define RBUF_SIZE (256u << 20)   /* written at quit; flushed early (opening the file) only if full */

typedef struct { uint32_t orig, len, disp, reloc_stub, reloc_orig; } hookmap_t;
static hookmap_t s_hookmap[8]; static int s_nhookmap;
void spike_add_hook(uint32_t orig, uint32_t len, uint32_t disp, uint32_t reloc_stub, uint32_t reloc_orig)
{
    if (s_nhookmap < 8) s_hookmap[s_nhookmap++] = (hookmap_t){orig, len, disp, reloc_stub, reloc_orig};
}

static int steppable(uint32_t eip)
{
    return (eip >= IMG_LO && eip < IMG_HI) || (eip >= s_stub_lo && eip < s_stub_hi);
}
/* the game address an executed instruction stands for; *rec = 0 for hook artefacts */
static uint32_t map_eip(uint32_t eip, int *rec)
{
    for (int i = 0; i < s_nhookmap; i++) {
        const hookmap_t *h = &s_hookmap[i];
        if (eip >= h->orig && eip < h->orig + h->len) { *rec = 0; return eip; }   /* the patched jmp */
        if (eip >= h->disp && eip < h->disp + h->len) { *rec = 1; return h->orig + (eip - h->disp); }
    }
    *rec = eip >= IMG_LO && eip < IMG_HI;
    return eip;
}

/* ---- capture buffer */
static void rflush(void)
{
    DWORD w;
    if (s_regfile == INVALID_HANDLE_VALUE) s_regfile = spike_open("istep_regs.bin");
    if (s_rlen && s_regfile != INVALID_HANDLE_VALUE) WriteFile(s_regfile, s_rbuf, s_rlen, &w, NULL);
    s_rlen = 0;
}
static void rput(const void *p, uint32_t n)
{
    if (s_rlen + n > RBUF_SIZE) rflush();
    memcpy(s_rbuf + s_rlen, p, n); s_rlen += n;
}
enum { RF_REP = 1, RF_AFTER_OS = 2, RF_GUEST_ENTRY = 4, RF_CALLBACK = 8 };
static void emit_R(uint32_t eip, const uint32_t r[8], uint32_t eflags, uint8_t flags)
{
    uint32_t b[11];
    b[0] = 'R' | (uint32_t)flags << 8; b[1] = eip;
    memcpy(b + 2, r, 32); b[10] = eflags & ~0x10100u;     /* TF (ours) and RF masked */
    rput(b, 44); s_rrecs++;
}
static void emit_W(uint32_t addr, uint32_t size, uint32_t value)
{
    if (addr < s_wlo || addr > s_whi) return;
    uint32_t b[3] = {'W' | size << 8, addr, value};
    rput(b, 12); s_wrecs++;
}
static void emit_T(uint32_t tick) { uint32_t b[2] = {'T', tick}; rput(b, 8); }
static void emit_O(uint32_t slot, uint32_t ret) { uint32_t b[3] = {'O', slot, ret}; rput(b, 12); }

/* ---- instruction decoding: kind of control transfer, and the memory it will write */
enum { K_OTHER, K_CALL, K_JMP, K_RET };
typedef struct { uint32_t addr, size; } wr_t;
typedef struct {
    uint8_t kind, rep, pushf, valid;
    int nw; wr_t w[2];
    uint32_t slot;            /* IAT slot of call/jmp [disp32] */
    uint32_t eip;             /* recorded (mapped) address, 0 if not recorded */
} pred_t;
static pred_t s_pred;
static uint32_t s_last_rec_eip;
static uint8_t s_carry_flags;          /* R flags waiting for the next recorded instruction */
static int s_need_first;

static uint32_t ctx_reg(const uint32_t r[8], int i) { return r[i]; }
static void ctx_regs(const CONTEXT *c, uint32_t r[8])
{
    r[0] = c->Eax; r[1] = c->Ecx; r[2] = c->Edx; r[3] = c->Ebx; r[4] = c->Esp; r[5] = c->Ebp; r[6] = c->Esi; r[7] = c->Edi;
}
/* effective address of the ModRM memory operand at p (p points at the ModRM byte) */
static uint32_t modrm_ea(const uint8_t *p, const uint32_t r[8], int adsz, uint32_t segbase)
{
    uint8_t m = p[0], mod = m >> 6, rm = m & 7;
    uint32_t ea = 0;
    p++;
    if (adsz == 2) {
        static const int8_t b1[8] = {3, 3, 5, 5, 6, 7, 5, 3}, b2[8] = {6, 7, 6, 7, -1, -1, -1, -1};
        if (mod == 0 && rm == 6) ea = *(uint16_t *)p;
        else {
            ea = (uint16_t)ctx_reg(r, b1[rm]) + (b2[rm] >= 0 ? (uint16_t)ctx_reg(r, b2[rm]) : 0);
            if (mod == 1) ea += (int8_t)p[0]; else if (mod == 2) ea += *(uint16_t *)p;
        }
        return segbase + (ea & 0xFFFF);
    }
    if (rm == 4) {
        uint8_t sib = *p++, sc = sib >> 6, idx = (sib >> 3) & 7, base = sib & 7;
        if (idx != 4) ea = ctx_reg(r, idx) << sc;
        if (base == 5 && mod == 0) { ea += *(uint32_t *)p; p += 4; }
        else ea += ctx_reg(r, base);
    } else if (rm == 5 && mod == 0) { ea = *(uint32_t *)p; p += 4; }
    else ea = ctx_reg(r, rm);
    if (mod == 1) ea += (int32_t)(int8_t)p[0];
    else if (mod == 2) ea += *(uint32_t *)p;
    return segbase + ea;
}
static void decode(uint32_t eip, const uint32_t r[8], pred_t *d)
{
    const uint8_t *p = (const uint8_t *)eip;
    int opsz = 4, adsz = 4; uint32_t seg = 0;
    memset(d, 0, sizeof *d);
    for (int i = 0; i < 15; i++, p++) {
        uint8_t b = *p;
        if (b == 0x66) opsz = 2; else if (b == 0x67) adsz = 2;
        else if (b == 0x64) __asm__ volatile("movl %%fs:0x18, %0" : "=r"(seg));   /* fs base = TEB */
        else if (b == 0xF2 || b == 0xF3) d->rep = 1;
        else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x65 || b == 0xF0) ;
        else break;
    }
    uint8_t op = *p++;
    uint32_t esp = r[4];
    int mw = 0; uint32_t size = 0; uint8_t reg = (p[0] >> 3) & 7, mod = p[0] >> 6;
#define PUSH(n) do { d->w[d->nw].addr = esp - (n); d->w[d->nw].size = (n); d->nw++; } while (0)
    if (op != 0x0F) {
        switch (op) {
        case 0x00: case 0x08: case 0x10: case 0x18: case 0x20: case 0x28: case 0x30: case 0x86: case 0x88:
        case 0xC0: case 0xD0: case 0xD2: case 0xC6: mw = 1; size = 1; break;
        case 0x01: case 0x09: case 0x11: case 0x19: case 0x21: case 0x29: case 0x31: case 0x87: case 0x89:
        case 0xC1: case 0xD1: case 0xD3: case 0xC7: mw = 1; size = opsz; break;
        case 0x80: case 0x82: if (reg != 7) { mw = 1; size = 1; } break;
        case 0x81: case 0x83: if (reg != 7) { mw = 1; size = opsz; } break;
        case 0x8C: mw = 1; size = 2; break;
        case 0x8F: mw = 1; size = opsz; break;
        case 0xF6: if (reg == 2 || reg == 3) { mw = 1; size = 1; } break;
        case 0xF7: if (reg == 2 || reg == 3) { mw = 1; size = opsz; } break;
        case 0xFE: if (reg <= 1) { mw = 1; size = 1; } break;
        case 0xFF:
            if (reg <= 1) { mw = 1; size = opsz; }
            else if (reg == 2 || reg == 3) { d->kind = K_CALL; PUSH(reg == 2 ? 4 : 8); if (mod == 0 && (p[0] & 7) == 5) d->slot = *(uint32_t *)(p + 1); }
            else if (reg == 4 || reg == 5) { d->kind = K_JMP; if (mod == 0 && (p[0] & 7) == 5) d->slot = *(uint32_t *)(p + 1); }
            else if (reg == 6) PUSH(opsz);
            break;
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x68: case 0x6A: case 0x06: case 0x0E: case 0x16: case 0x1E: PUSH(opsz); break;
        case 0x9C: PUSH(opsz); d->pushf = 1; break;
        case 0x60: PUSH(8 * opsz); break;
        case 0xC8: PUSH(4); break;
        case 0xE8: d->kind = K_CALL; PUSH(4); break;
        case 0x9A: d->kind = K_CALL; PUSH(8); break;
        case 0xE9: case 0xEB: case 0xEA: d->kind = K_JMP; break;
        case 0xC3: case 0xC2: case 0xCB: case 0xCA: case 0xCF: d->kind = K_RET; break;
        case 0xA2: d->w[0].addr = seg + *(uint32_t *)p; d->w[0].size = 1; d->nw = 1; break;
        case 0xA3: d->w[0].addr = seg + *(uint32_t *)p; d->w[0].size = opsz; d->nw = 1; break;
        case 0xA4: case 0xAA: case 0xA5: case 0xAB:
            /* one element per step (a rep instruction traps after each iteration); none if the
             * repeat count is already 0 */
            if (d->rep && (adsz == 2 ? (r[1] & 0xFFFF) : r[1]) == 0) break;
            d->w[0].addr = adsz == 2 ? (r[7] & 0xFFFF) : r[7];   /* es:edi; no override */
            d->w[0].size = (op == 0xA4 || op == 0xAA) ? 1 : opsz; d->nw = 1; break;
        case 0xD9: if (mod != 3) { if (reg == 2 || reg == 3) size = 4; else if (reg == 7) size = 2; else if (reg == 6) size = 28; mw = size != 0; } break;
        case 0xDD: if (mod != 3) { if (reg == 2 || reg == 3) size = 8; else if (reg == 7) size = 2; else if (reg == 6) size = 108; mw = size != 0; } break;
        case 0xDB: if (mod != 3) { if (reg == 2 || reg == 3) size = 4; else if (reg == 7) size = 10; mw = size != 0; } break;
        case 0xDF: if (mod != 3) { if (reg == 2 || reg == 3) size = 2; else if (reg == 7) size = 8; mw = size != 0; } break;
        default: break;
        }
    } else {
        op = *p++; reg = (p[0] >> 3) & 7; mod = p[0] >> 6;
        if (op >= 0x90 && op <= 0x9F) { mw = 1; size = 1; }
        else if (op == 0xA4 || op == 0xA5 || op == 0xAC || op == 0xAD || op == 0xAB || op == 0xB3 || op == 0xBB) { mw = 1; size = opsz; }
        else if (op == 0xBA && reg >= 5) { mw = 1; size = opsz; }
        else if (op == 0xB0 || op == 0xC0) { mw = 1; size = 1; }
        else if (op == 0xB1 || op == 0xC1) { mw = 1; size = opsz; }
        else if (op == 0xC7 && reg == 1) { mw = 1; size = 8; }
        if (mw && mod != 3 && (op == 0xAB || op == 0xB3 || op == 0xBB)) {
            /* bit string with a register bit offset (signed): the operand-size unit holding the
             * bit, at ea + (offset >> 4) * 2 for 16-bit operands, ea + (offset >> 5) * 4 for 32 */
            uint32_t ea = modrm_ea(p, r, adsz, seg);
            if (opsz == 2) { int32_t off = (int16_t)r[reg]; ea += (uint32_t)((off >> 4) * 2); }
            else { int32_t off = (int32_t)r[reg]; ea += (uint32_t)((off >> 5) * 4); }
            d->w[0].addr = ea; d->w[0].size = opsz; d->nw = 1; mw = 0;
        }
    }
#undef PUSH
    if (mw && mod != 3) {
        uint32_t ea = modrm_ea(p, r, adsz, seg);
        if (op == 0x8F && (p[0] & 7) == 4 && ((p[1] & 7) == 4)) ea += opsz;    /* pop [esp+...]: esp after the pop */
        d->w[d->nw].addr = ea; d->w[d->nw].size = size; d->nw++;
    }
    d->valid = 1;
}
static uint32_t fix_value(uint32_t v)
{
    for (int i = 0; i < s_nhookmap; i++)       /* a hook stub's relocated call pushed its own return address */
        if (s_hookmap[i].reloc_stub && v == s_hookmap[i].reloc_stub) return s_hookmap[i].reloc_orig;
    return v;
}
/* after the predicted instruction executed: its writes, read back from memory */
static void finish_writes(void)
{
    if (!s_regs || !s_pred.valid || !s_pred.eip) { s_pred.valid = 0; return; }
    for (int i = 0; i < s_pred.nw; i++) {
        uint32_t a = s_pred.w[i].addr, n = s_pred.w[i].size;
        while (n) {
            uint32_t k = n >= 4 ? 4 : n >= 2 ? 2 : 1, v = 0;
            memcpy(&v, (void *)a, k);
            if (k == 4) { v = fix_value(v); if (s_pred.pushf) v &= ~0x100u; }
            emit_W(a, k, v);
            a += k; n -= k;
        }
    }
    s_pred.valid = 0;
}
static void step_record(uint32_t eip, const uint32_t r[8], uint32_t eflags, uint8_t flags)
{
    int rec; uint32_t a = map_eip(eip, &rec);
    decode(eip, r, &s_pred);
    s_pred.eip = rec ? a : 0;
    flags |= s_carry_flags;
    if (!rec) { s_carry_flags = flags & (RF_AFTER_OS | RF_GUEST_ENTRY | RF_CALLBACK); return; }
    s_carry_flags = 0;
    if (a >= IMG_LO && a < IMG_HI) {
        s_steps++;
        uint32_t o = a - IMG_LO;
        s_cov[o >> 3] |= 1 << (o & 7);
        if (a >= 0x5E7000 && a < 0x9B3000 && s_unknown_eips++ < 50)
            spike_log("istep: executing outside code sections at %#x\n", a);
    }
    if (s_regs) {
        if (a == s_last_rec_eip && s_pred.rep) flags |= RF_REP;
        emit_R(a, r, eflags, flags);
    }
    s_last_rec_eip = a;
}

/* ---- pending one-shot breakpoints: OS-call return addresses and entries of called game code */
typedef struct { uint32_t addr; uint8_t orig, flags; } pbp_t;
static pbp_t s_pbp[64]; static int s_npbp;
static void arm_bp(uint32_t a, uint8_t flags)
{
    for (int i = 0; i < s_npbp; i++) if (s_pbp[i].addr == a) { s_bp_conflicts++; return; }
    if (s_npbp >= 64) { s_bp_conflicts++; return; }
    DWORD old; VirtualProtect((void *)a, 1, PAGE_EXECUTE_READWRITE, &old);
    s_pbp[s_npbp].addr = a; s_pbp[s_npbp].orig = *(uint8_t *)a; s_pbp[s_npbp].flags = flags; s_npbp++;
    *(uint8_t *)a = 0xCC;
    VirtualProtect((void *)a, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)a, 1);
}
/* game code about to be entered from outside: by a script action (callback 0) or by the OS (1) */
void spike_guest_call(uint32_t target, int callback)
{
    if (s_stepping && s_paused && steppable(target)) arm_bp(target, callback ? RF_CALLBACK : RF_GUEST_ENTRY);
}

static LONG CALLBACK istep_veh(EXCEPTION_POINTERS *e)
{
    DWORD code = e->ExceptionRecord->ExceptionCode;
    CONTEXT *c = e->ContextRecord;
    if (code == EXCEPTION_SINGLE_STEP) {
        if (!s_stepping) return EXCEPTION_CONTINUE_EXECUTION;
        finish_writes();
        uint32_t eip = c->Eip, r[8];
        ctx_regs(c, r);
        if (steppable(eip)) {
            s_paused = 0;
            step_record(eip, r, c->EFlags, 0);
            c->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        /* left game code: by call/jmp, resume at the return address; by ret, wait for the caller */
        if (s_pred.kind == K_CALL || s_pred.kind == K_JMP) {
            uint32_t ret = *(uint32_t *)c->Esp;
            if (s_regs && s_pred.eip) emit_O(s_pred.slot, ret);
            /* only the game's own calls mark the return; the hook stubs' calls into the hook do not */
            if (steppable(ret)) { arm_bp(ret, s_pred.eip ? RF_AFTER_OS : 0); s_outside_calls++; }
        }
        s_pred.valid = 0; s_pred.kind = 0; s_pred.eip = 0;
        s_paused = 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_BREAKPOINT) {
        int i = 0;
        for (; i < s_npbp; i++) if (c->Eip == s_pbp[i].addr || c->Eip == s_pbp[i].addr + 1) break;
        if (i == s_npbp) return EXCEPTION_CONTINUE_SEARCH;
        pbp_t b = s_pbp[i];
        s_pbp[i] = s_pbp[--s_npbp];
        DWORD old; VirtualProtect((void *)b.addr, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t *)b.addr = b.orig;
        VirtualProtect((void *)b.addr, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (void *)b.addr, 1);
        c->Eip = b.addr;
        if (s_stepping) {
            if (s_paused) {
                uint32_t r[8]; ctx_regs(c, r);
                s_paused = 0;
                step_record(b.addr, r, c->EFlags, b.flags);
            }
            c->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ------------------------------------------------------------------ ptrscan */
/* Every tick: which state dwords (any 2-byte-aligned offset) hold an address of OS-owned memory:
 * a mapped view, a private allocation (heap, VirtualAlloc, DIB), another module's image, or the
 * stack. Only words that changed since the previous tick are re-examined. At quit: ptrscan.txt. */
#define ST_LO 0x5F4000u
#define ST_HI 0x9A161Cu
#define ST2_LO 0x9A2000u
#define ST2_HI 0x9B2301u
static int s_ptrscan;
static uint8_t *s_ps_prev;                 /* previous state copy (DATASEG then DataSeg) */
typedef struct { uint32_t lo, hi; uint8_t cls; } psreg_t;
static psreg_t s_psr[512]; static int s_npsr;
typedef struct { uint32_t addr, first_tick, last_tick, first_val, last_val, hits; uint8_t cls; } pshit_t;
static pshit_t *s_ps; static uint32_t s_nps, s_ps_cap;
static uint32_t *s_ps_idx;                 /* addr -> index+1, for both ranges, 2-byte granularity */
static const char *ps_cls[] = {"none", "mapped", "private", "image", "stack"};
static uint32_t s_ps_scans;

static void ps_regions(void)
{
    MEMORY_BASIC_INFORMATION mi; s_npsr = 0;
    uint32_t stack_lo = 0, stack_hi = 0;
    __asm__ volatile("movl %%fs:4, %0" : "=r"(stack_hi));     /* TEB: StackBase, StackLimit */
    __asm__ volatile("movl %%fs:8, %0" : "=r"(stack_lo));
    for (uint8_t *p = (uint8_t *)0x10000; VirtualQuery(p, &mi, sizeof mi) == sizeof mi; p = (uint8_t *)mi.BaseAddress + mi.RegionSize) {
        uint32_t lo = (uint32_t)mi.BaseAddress, hi = lo + mi.RegionSize;
        if (hi < lo) break;
        if (mi.State != MEM_COMMIT || s_npsr >= 512) continue;
        if (lo >= 0x400000 && hi <= 0x9BD000) continue;          /* rct.exe */
        if (lo >= 0x10000000 && hi <= 0x40000000) continue;      /* the instruments' fixed arenas */
        uint8_t cls = mi.Type == MEM_MAPPED ? 1 : mi.Type == MEM_IMAGE ? 3 : 2;
        if (lo < stack_hi && hi > stack_lo - 0x100000) cls = 4;
        if (s_npsr && s_psr[s_npsr - 1].hi == lo && s_psr[s_npsr - 1].cls == cls) s_psr[s_npsr - 1].hi = hi;
        else s_psr[s_npsr++] = (psreg_t){lo, hi, cls};
    }
}
static uint8_t ps_class(uint32_t v)
{
    if (v < 0x10000) return 0;
    int lo = 0, hi = s_npsr - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (v < s_psr[m].lo) hi = m - 1; else if (v >= s_psr[m].hi) lo = m + 1; else return s_psr[m].cls;
    }
    return 0;
}
static uint32_t ps_off(uint32_t a) { return a < ST2_LO ? a - ST_LO : (ST_HI - ST_LO) + (a - ST2_LO); }
static void ps_note(uint32_t a, uint32_t v, uint8_t cls, uint32_t tick)
{
    uint32_t k = ps_off(a) >> 1;
    if (!s_ps_idx[k]) {
        if (s_nps == s_ps_cap) return;
        s_ps[s_nps] = (pshit_t){a, tick, tick, v, v, 0, cls};
        s_ps_idx[k] = ++s_nps;
    }
    pshit_t *h = &s_ps[s_ps_idx[k] - 1];
    h->last_tick = tick; h->last_val = v; h->hits++; if (cls > h->cls) h->cls = cls;
}
static void ps_scan_range(uint32_t lo, uint32_t hi, uint8_t *prev, int full, uint32_t tick)
{
    for (uint32_t pg = lo & ~0xFFFu; pg < hi; pg += 0x1000) {
        uint32_t a0 = pg < lo ? lo : pg, a1 = pg + 0x1000 > hi ? hi : pg + 0x1000;
        uint8_t *pv = prev + (a0 - lo);
        if (!full && !memcmp(pv, (void *)a0, a1 - a0)) continue;
        for (uint32_t a = (a0 + 1) & ~1u; a + 4 <= a1 + 2 && a + 4 <= hi; a += 2) {
            uint32_t v = *(uint32_t *)a;
            if (!full && *(uint32_t *)(prev + (a - lo)) == v) continue;
            uint8_t c = ps_class(v);
            if (c) ps_note(a, v, c, tick);
        }
        memcpy(pv, (void *)a0, a1 - a0);
    }
}
static void ptrscan(uint32_t tick, int full)
{
    ps_regions();
    ps_scan_range(ST_LO, ST_HI, s_ps_prev, full, tick);
    ps_scan_range(ST2_LO, ST2_HI, s_ps_prev + (ST_HI - ST_LO), full, tick);
    s_ps_scans++;
}
static void ptrscan_install(void)
{
    uint32_t n = (ST_HI - ST_LO) + (ST2_HI - ST2_LO);
    uint8_t *m = VirtualAlloc((void *)0x2C000000, 0x04000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) { spike_log("ptrscan: arena unavailable\n"); s_ptrscan = 0; return; }
    s_ps_prev = m; s_ps_idx = (uint32_t *)(m + 0x00800000); s_ps = (pshit_t *)(m + 0x01800000);
    s_ps_cap = (0x04000000 - 0x01800000) / sizeof(pshit_t);
    (void)n;
}
static void ptrscan_write(void)
{
    ptrscan(0xFFFFFFFF, 1);        /* final full scan: tick FFFFFFFF marks "still a pointer at quit" */
    HANDLE f = spike_open("ptrscan.txt"); DWORD w; char line[160];
    int n = snprintf(line, sizeof line, "# addr class first_tick last_tick hits first_value last_value (%u scans)\n", s_ps_scans);
    WriteFile(f, line, n, &w, NULL);
    for (uint32_t i = 0; i < s_nps; i++) {
        pshit_t *h = &s_ps[i];
        n = snprintf(line, sizeof line, "%08x %s %u %u %u %08x %08x\n", h->addr, ps_cls[h->cls], h->first_tick,
                     h->last_tick, h->hits, h->first_val, h->last_val);
        WriteFile(f, line, n, &w, NULL);
    }
    CloseHandle(f);
    spike_log("ptrscan: %u addresses, %u scans\n", s_nps, s_ps_scans);
}

/* ------------------------------------------------------------------ watch */
/* watch=FILE: at every tick, every listed address (uint32 LE list) whose dword changed since the
 * previous tick -> watch.bin records {tick, addr, value} (uint32 LE). Diffing the logs of a clean
 * and a heapshift run finds exactly the state values that depend on the memory layout. */
static char s_watch_path[MAX_PATH];
static uint32_t *s_w_addr, *s_w_prev, s_nw; static uint32_t *s_w_log; static uint32_t s_w_len, s_w_cap;
static HANDLE s_w_file = INVALID_HANDLE_VALUE;
static void watch_flush(void)
{
    DWORD w;
    if (s_w_file == INVALID_HANDLE_VALUE) s_w_file = spike_open("watch.bin");
    WriteFile(s_w_file, s_w_log, s_w_len * 4, &w, NULL); s_w_len = 0;
}
static void watch_install(void)
{
    HANDLE f = CreateFileA(s_watch_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { spike_log("watch: cannot open %s\n", s_watch_path); s_watch_path[0] = 0; return; }
    DWORD size = GetFileSize(f, NULL), r;
    uint8_t *m = VirtualAlloc((void *)0x2C000000, 0x08000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m || size > 0x01000000) { spike_log("watch: arena unavailable\n"); s_watch_path[0] = 0; CloseHandle(f); return; }
    s_w_addr = (uint32_t *)m; s_w_prev = (uint32_t *)(m + 0x01000000); s_w_log = (uint32_t *)(m + 0x02000000);
    s_w_cap = 0x06000000 / 4;
    ReadFile(f, s_w_addr, size, &r, NULL); CloseHandle(f);
    s_nw = size / 4;
    for (uint32_t i = 0; i < s_nw; i++) s_w_prev[i] = 0xA5A5A5A5u;  /* first tick logs everything */
    spike_log("watch: %u addresses\n", s_nw);
}
static void watch_tick(uint32_t tick)
{
    for (uint32_t i = 0; i < s_nw; i++) {
        uint32_t v = *(uint32_t *)s_w_addr[i];
        if (v == s_w_prev[i]) continue;
        s_w_prev[i] = v;
        if (s_w_len + 3 > s_w_cap) watch_flush();
        s_w_log[s_w_len++] = tick; s_w_log[s_w_len++] = s_w_addr[i]; s_w_log[s_w_len++] = v;
    }
}

/* ------------------------------------------------------------------ cover */
static uint32_t *s_bp_addr; static uint8_t *s_bp_orig, *s_bp_hit; static int s_nbp;
static const uint32_t (*s_hook_ranges)[2]; static int s_nhook_ranges;

/* rct.exe checksums 0x42EAE0-0x431510 once, during the first frame (0x5DF3BB, called from
 * 0x43862A), and keeps the result in game state at 0x6E2B76. Breakpoints in that range are
 * armed only after the first frame so the checksum sees the original bytes. */
#define CKSUM_LO 0x42EAE0u
#define CKSUM_HI 0x431510u
static int s_cover_deferred;

static int bp_find(uint32_t a)
{
    int lo = 0, hi = s_nbp - 1;
    while (lo <= hi) { int m = (lo + hi) / 2; if (s_bp_addr[m] == a) return m; if (s_bp_addr[m] < a) lo = m + 1; else hi = m - 1; }
    return -1;
}
static LONG CALLBACK cover_veh(EXCEPTION_POINTERS *e)
{
    CONTEXT *c = e->ContextRecord;
    if (e->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        static int n;
        if (n++ < 20)
            spike_log("cover: exception %#lx at eip %#lx (info %#lx %#lx) esp %#lx\n",
                      (unsigned long)e->ExceptionRecord->ExceptionCode, (unsigned long)c->Eip,
                      (unsigned long)e->ExceptionRecord->ExceptionInformation[0],
                      (unsigned long)e->ExceptionRecord->ExceptionInformation[1], (unsigned long)c->Esp);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    int i = bp_find(c->Eip);
    if (i < 0) i = bp_find(c->Eip - 1);
    if (i < 0 || s_bp_hit[i]) return EXCEPTION_CONTINUE_SEARCH;
    *(uint8_t *)s_bp_addr[i] = s_bp_orig[i];
    FlushInstructionCache(GetCurrentProcess(), (void *)s_bp_addr[i], 1);
    s_bp_hit[i] = 1; c->Eip = s_bp_addr[i];
    return EXCEPTION_CONTINUE_EXECUTION;
}
static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b; return (x > y) - (x < y);
}
static void cover_install(void)
{
    HANDLE f = CreateFileA(s_cover_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { spike_log("cover: cannot open %s\n", s_cover_path); return; }
    DWORD size = GetFileSize(f, NULL), r;
    s_bp_addr = malloc(size); ReadFile(f, s_bp_addr, size, &r, NULL); CloseHandle(f);
    int n = size / 4;
    qsort(s_bp_addr, n, 4, cmp_u32);
    s_bp_orig = malloc(n); s_bp_hit = calloc(n, 1);
    DWORD old;
    VirtualProtect((void *)0x401000, 0x9BD000 - 0x401000, PAGE_EXECUTE_READWRITE, &old);
    int skipped = 0;
    for (int i = 0; i < n; i++) {
        uint32_t a = s_bp_addr[i];
        int hooked = 0;
        for (int k = 0; k < s_nhook_ranges; k++)
            if (a >= s_hook_ranges[k][0] && a < s_hook_ranges[k][1]) hooked = 1;
        if (hooked || a < 0x401000 || a >= 0x9BD000) { s_bp_hit[i] = 2; skipped++; continue; }
        s_bp_orig[i] = *(uint8_t *)a;
        if (a >= CKSUM_LO && a < CKSUM_HI) { s_bp_hit[i] = 3; s_cover_deferred++; continue; }
        *(uint8_t *)a = 0xCC;
    }
    s_nbp = n;
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    AddVectoredExceptionHandler(1, cover_veh);
    spike_log("cover: %d breakpoints armed, %d deferred (checksummed code), %d skipped (hook patches)\n",
              n - skipped - s_cover_deferred, s_cover_deferred, skipped);
}
static void cover_arm_deferred(void)
{
    for (int i = 0; i < s_nbp; i++)
        if (s_bp_hit[i] == 3) { s_bp_hit[i] = 0; *(uint8_t *)s_bp_addr[i] = 0xCC; }
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    spike_log("cover: armed %d deferred breakpoints\n", s_cover_deferred);
    s_cover_deferred = 0;
}
static void cover_write(void)
{
    HANDLE f = spike_open("cover_hits.bin"); DWORD w; int hits = 0;
    for (int i = 0; i < s_nbp; i++)
        if (s_bp_hit[i] == 1) { WriteFile(f, &s_bp_addr[i], 4, &w, NULL); hits++; }
    CloseHandle(f);
    spike_log("cover: %d of %d addresses executed\n", hits, s_nbp);
}

/* ------------------------------------------------------------------ interface */
void spike_set_hook_ranges(const uint32_t (*r)[2], int n) { s_hook_ranges = r; s_nhook_ranges = n; }

void spike_install(uint32_t stub_lo, uint32_t stub_hi)
{
    char v[256];
    if (!GetEnvironmentVariableA("RCTHOOK_SPIKE", v, sizeof v)) {
        /* the register pin's thunks are part of every run's environment */
        if (!apitrace_install(0)) TerminateProcess(GetCurrentProcess(), 3);
        return;
    }
    for (char *t = strtok(v, ","); t; t = strtok(NULL, ",")) {
        if (!strcmp(t, "codewatch")) s_codewatch = 1;
        else if (!strcmp(t, "apicount")) s_apicount = 1;
        else if (!strcmp(t, "memmap")) s_memmap = 1;
        else if (!strncmp(t, "cover=", 6)) snprintf(s_cover_path, sizeof s_cover_path, "%s", t + 6);
        else if (!strncmp(t, "heapshift=", 10)) s_heapshift = strtoul(t + 10, NULL, 0);
        else if (!strncmp(t, "istep=", 6)) {
            s_istep = 1; s_step_from = strtoul(t + 6, &t, 0);
            s_step_to = *t == ':' ? strtoul(t + 1, NULL, 0) : s_step_from;
        }
        else if (!strcmp(t, "regs")) s_regs = 1;
        else if (!strcmp(t, "wmem=none")) { s_wlo = 1; s_whi = 0; }
        else if (!strncmp(t, "wmem=", 5)) {
            char *e; s_wlo = strtoul(t + 5, &e, 0); s_whi = *e == '-' ? strtoul(e + 1, NULL, 0) - 1 : 0xFFFFFFFFu;
        }
        else if (!strcmp(t, "apitrace")) s_apitrace = 1;
        else if (!strcmp(t, "ptrscan")) s_ptrscan = 1;
        else if (!strncmp(t, "watch=", 6)) snprintf(s_watch_path, sizeof s_watch_path, "%s", t + 6);
        else spike_log("spike: unknown mode '%s' ignored\n", t);
    }
    spike_log("spike: codewatch=%d apicount=%d heapshift=%u istep=%d (%u..%u) regs=%d wmem=%#x-%#x apitrace=%d\n",
              s_codewatch, s_apicount, s_heapshift, s_istep, s_step_from, s_step_to, s_regs, s_wlo, s_whi, s_apitrace);
    if (s_apicount && s_apitrace) { spike_log("spike: apicount and apitrace are exclusive; apicount off\n"); s_apicount = 0; }
    if (s_regs && !s_istep) spike_log("spike: regs needs istep=A:B\n");
    if (s_heapshift) {
        void *a = HeapAlloc(GetProcessHeap(), 0, s_heapshift);
        void *b = GlobalAlloc(GMEM_FIXED, s_heapshift);
        void *c = VirtualAlloc(NULL, s_heapshift * 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        void *m = malloc(s_heapshift);
        /* also shift OS handle numbers (file, event, ... handles are allocated from one table) */
        for (int i = 0; i < 7; i++) CreateEventA(NULL, FALSE, FALSE, NULL);
        /* and USER and GDI handle numbers (windows, cursors, icons; pens, brushes, DCs), which the
         * heap shift does not move: values the game keeps from them then differ too */
        HWND w[3]; HCURSOR cu[5]; int nw = 0;
        for (int i = 0; i < 3; i++) if ((w[i] = CreateWindowExA(0, "STATIC", "", 0, 0, 0, 1, 1, NULL, NULL, NULL, NULL))) nw++;
        static const BYTE andm[128] = {0}, xorm[128] = {0};
        for (int i = 0; i < 5; i++) cu[i] = CreateCursor(NULL, 0, 0, 32, 32, andm, xorm);
        for (int i = 0; i < 5; i++) { CreatePen(PS_SOLID, i + 1, RGB(i, 0, 0)); CreateSolidBrush(RGB(0, i, 0)); }
        HDC dc = CreateCompatibleDC(NULL);
        (void)cu;
        spike_log("heapshift: heap %p global %p virtual %p crt %p, 7 handles, %d windows, 5 cursors, 10 GDI objects, dc %p\n",
                  a, b, c, m, nw, dc);
    }
    if (s_apicount) apicount_install();
    if (s_ptrscan) ptrscan_install();
    if (s_watch_path[0]) watch_install();
    if (!apitrace_install(s_apitrace)) TerminateProcess(GetCurrentProcess(), 3);
    if (s_cover_path[0]) cover_install();
    if (s_codewatch) codewatch_snapshot();
    if (s_istep) {
        s_stub_lo = stub_lo; s_stub_hi = stub_hi;
        /* fixed high addresses, so that the instrument does not move memory the game allocates later */
        s_cov = VirtualAlloc((void *)0x24000000, 0x200000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!s_cov) s_cov = VirtualAlloc(NULL, 0x200000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        s_tickbuf = (char *)s_cov + 0x100000;     /* istep_ticks.txt, written at quit */
        AddVectoredExceptionHandler(1, istep_veh);
        if (s_regs) {
            s_rbuf = VirtualAlloc((void *)0x28000000, RBUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!s_rbuf) { spike_log("istep: capture buffer unavailable\n"); s_regs = 0; }
            else {
                uint32_t hdr[4] = {0x50545352 /* "RSTP" */, 1, 1 /* per instruction */, 0};
                rput(hdr, 16);
            }
        }
    }
}

void spike_frame(uint32_t frame, uint32_t tick)
{
    s_cur_frame = frame;
    if (s_apitrace) apitrace_time(frame, tick);
    if (s_codewatch) codewatch_check(frame, tick);
    if (s_cover_deferred && frame >= 2) cover_arm_deferred();
}

/* regs: the hooked code's registers, pushad order (edi esi ebp esp ebx edx ecx eax), eflags at [8];
 * pushad saw esp after the stub's pushfd, so the game's esp is regs[3] + 4 */
void spike_tick(uint32_t *regs, uint32_t tick, uint32_t tick_addr, uint32_t tick_disp)
{
    if (s_apitrace) apitrace_time(s_cur_frame, tick);
    if (s_ptrscan) ptrscan(tick, s_ps_scans == 0);
    if (s_watch_path[0]) watch_tick(tick);
    if (!s_istep) return;
    uint32_t *eflags = &regs[8];
    if (s_stepping && s_ticklen < 0x100000 - 128) {
        s_ticklen += snprintf(s_tickbuf + s_ticklen, 128, "tick %u instructions %llu outside_calls %llu\n", tick - 1,
                              (unsigned long long)(s_steps - s_steps_at_tick), (unsigned long long)s_outside_calls);
        s_outside_calls = 0;
    }
    s_steps_at_tick = s_steps;
    if (tick == s_step_from) {
        s_stepping = 1; s_last_rec_eip = 0; s_carry_flags = 0;
        s_paused = 1;     /* in hook code now: game code entered from here (script actions) is announced */
        spike_log("istep: on at tick %u\n", tick);
        if (s_regs) emit_T(tick);
        s_need_first = 1;        /* recorded by spike_tick_end, after the tick's script actions */
        (void)tick_addr; (void)tick_disp;
    } else if (s_stepping && s_regs && tick != s_step_to + 1) emit_T(tick);
    if (tick == s_step_to + 1) {
        s_stepping = 0; s_pred.valid = 0;
        spike_log("istep: off at tick %u\n", tick);
    }
    if (s_stepping) *eflags |= 0x100;   /* TF: trap after the stub's popfd */
    else *eflags &= ~0x100u;
}

static void memmap_write(void)
{
    HANDLE f = spike_open("memmap.txt"); DWORD w; char line[400];
    MEMORY_BASIC_INFORMATION mi;
    for (uint8_t *p = 0; VirtualQuery(p, &mi, sizeof mi) == sizeof mi; p = (uint8_t *)mi.BaseAddress + mi.RegionSize) {
        if (mi.State == MEM_COMMIT) {
            char mod[MAX_PATH] = "";
            if (mi.Type == MEM_IMAGE) GetModuleFileNameA((HMODULE)mi.AllocationBase, mod, sizeof mod);
            int n = snprintf(line, sizeof line, "%08lx %08lx %8lu KiB prot %03lx type %s alloc %08lx %s\n",
                             (unsigned long)mi.BaseAddress, (unsigned long)mi.RegionSize,
                             (unsigned long)(mi.RegionSize >> 10), (unsigned long)mi.Protect,
                             mi.Type == MEM_IMAGE ? "image" : mi.Type == MEM_MAPPED ? "mapped" : "private",
                             (unsigned long)mi.AllocationBase, mod);
            WriteFile(f, line, n, &w, NULL);
        }
        if ((uint32_t)mi.BaseAddress + mi.RegionSize < (uint32_t)mi.BaseAddress) break;
    }
    CloseHandle(f);
}

void spike_quit(void)
{
    if (s_memmap) memmap_write();
    if (s_cover_path[0]) cover_write();
    if (s_apicount) apicount_write();
    if (s_apitrace) apitrace_quit();
    if (s_apitrace || s_istep) apitrace_osmap();
    if (s_ptrscan) ptrscan_write();
    if (s_watch_path[0]) { watch_tick(0xFFFFFFFF); watch_flush(); CloseHandle(s_w_file); }
    if (s_istep) {
        s_stepping = 0;
        if (s_regs) {
            rflush(); CloseHandle(s_regfile);
            spike_log("istep: %llu register records, %llu write records, %u breakpoint conflicts\n",
                      (unsigned long long)s_rrecs, (unsigned long long)s_wrecs, s_bp_conflicts);
        }
        HANDLE f = spike_open("istep_cov.bin"); DWORD w;
        WriteFile(f, s_cov, (IMG_HI - IMG_LO) / 8, &w, NULL);
        CloseHandle(f);
        f = spike_open("istep_ticks.txt"); WriteFile(f, s_tickbuf, s_ticklen, &w, NULL); CloseHandle(f);
        spike_log("istep: %llu instructions stepped, %u executions outside code sections\n",
                  (unsigned long long)s_steps, s_unknown_eips);
    }
    if (s_codewatch) spike_log("codewatch: %u changed ranges\n", s_code_changes);
}

/* a fatal end of the run (modal dialog, script error, process detach): keep what was recorded */
void spike_abort(void)
{
    if (s_apitrace) apitrace_quit();
    if (s_istep && s_regs) rflush();
}

/* end of the tick hook (after the tick's script actions): when stepping just started, the trap after
 * the stub's popfd follows the first displaced instruction, so that instruction is recorded here */
void spike_tick_end(uint32_t *regs, uint32_t tick_disp)
{
    if (!s_need_first) return;
    s_need_first = 0;
    if (!s_stepping) return;
    uint32_t r[8] = {regs[7], regs[6], regs[5], regs[4], regs[3] + 4, regs[2], regs[1], regs[0]};
    s_paused = 0;
    step_record(tick_disp, r, regs[8], 0);
}
