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
 *                 Code called back from inside OS calls (e.g. the window procedure during
 *                 PeekMessage) is not stepped.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spike.h"

static int s_codewatch, s_apicount, s_istep, s_memmap;
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
#define IMG_LO 0x401000u
#define IMG_HI 0x9BD000u
static uint8_t *s_cov;                  /* 1 bit per byte of the image range */
static volatile int s_stepping;
static uint64_t s_steps, s_outside_calls;
static uint32_t s_pending_bp; static uint8_t s_pending_orig;
static uint32_t s_stub_lo, s_stub_hi;
static HANDLE s_tickfile;
static uint64_t s_steps_at_tick;
static uint32_t s_unknown_eips;

static int steppable(uint32_t eip)
{
    return (eip >= IMG_LO && eip < IMG_HI) || (eip >= s_stub_lo && eip < s_stub_hi);
}
static LONG CALLBACK istep_veh(EXCEPTION_POINTERS *e)
{
    DWORD code = e->ExceptionRecord->ExceptionCode;
    CONTEXT *c = e->ContextRecord;
    if (code == EXCEPTION_SINGLE_STEP) {
        if (!s_stepping) return EXCEPTION_CONTINUE_EXECUTION;
        uint32_t eip = c->Eip;
        if (steppable(eip)) {
            if (eip >= IMG_LO && eip < IMG_HI) {
                s_steps++;
                uint32_t o = eip - IMG_LO;
                s_cov[o >> 3] |= 1 << (o & 7);
                if (eip >= 0x5E7000 && eip < 0x9B3000 && s_unknown_eips++ < 50)
                    spike_log("istep: executing outside code sections at %#x\n", eip);
            }
            c->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        /* entered OS or hook code by call/jmp: resume stepping when it returns */
        uint32_t ret = *(uint32_t *)c->Esp;
        if (steppable(ret) && !s_pending_bp) {
            DWORD old; VirtualProtect((void *)ret, 1, PAGE_EXECUTE_READWRITE, &old);
            s_pending_orig = *(uint8_t *)ret; *(uint8_t *)ret = 0xCC;
            FlushInstructionCache(GetCurrentProcess(), (void *)ret, 1);
            s_pending_bp = ret; s_outside_calls++;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_BREAKPOINT && s_pending_bp &&
        (c->Eip == s_pending_bp || c->Eip == s_pending_bp + 1)) {
        *(uint8_t *)s_pending_bp = s_pending_orig;
        FlushInstructionCache(GetCurrentProcess(), (void *)s_pending_bp, 1);
        c->Eip = s_pending_bp; s_pending_bp = 0;
        if (s_stepping) {
            /* the instruction at the return address executes now: count it, then step on */
            uint32_t o = c->Eip - IMG_LO;
            if (c->Eip >= IMG_LO && c->Eip < IMG_HI) { s_steps++; s_cov[o >> 3] |= 1 << (o & 7); }
            c->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
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
    if (!GetEnvironmentVariableA("RCTHOOK_SPIKE", v, sizeof v)) return;
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
    }
    spike_log("spike: codewatch=%d apicount=%d heapshift=%u istep=%d (%u..%u)\n",
              s_codewatch, s_apicount, s_heapshift, s_istep, s_step_from, s_step_to);
    if (s_heapshift) {
        void *a = HeapAlloc(GetProcessHeap(), 0, s_heapshift);
        void *b = GlobalAlloc(GMEM_FIXED, s_heapshift);
        void *c = VirtualAlloc(NULL, s_heapshift * 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        void *m = malloc(s_heapshift);
        /* also shift OS handle numbers (file, event, ... handles are allocated from one table) */
        for (int i = 0; i < 7; i++) CreateEventA(NULL, FALSE, FALSE, NULL);
        spike_log("heapshift: heap %p global %p virtual %p crt %p, 7 handles\n", a, b, c, m);
    }
    if (s_apicount) apicount_install();
    if (s_cover_path[0]) cover_install();
    if (s_codewatch) codewatch_snapshot();
    if (s_istep) {
        s_stub_lo = stub_lo; s_stub_hi = stub_hi;
        s_cov = VirtualAlloc(NULL, (IMG_HI - IMG_LO) / 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        AddVectoredExceptionHandler(1, istep_veh);
        s_tickfile = spike_open("istep_ticks.txt");
    }
}

void spike_frame(uint32_t frame, uint32_t tick)
{
    if (s_codewatch) codewatch_check(frame, tick);
    if (s_cover_deferred && frame >= 2) cover_arm_deferred();
}

void spike_tick(uint32_t *eflags, uint32_t tick)
{
    if (!s_istep) return;
    if (s_stepping) {
        char line[96]; DWORD w;
        int n = snprintf(line, sizeof line, "tick %u instructions %llu outside_calls %llu\n", tick - 1,
                         (unsigned long long)(s_steps - s_steps_at_tick), (unsigned long long)s_outside_calls);
        WriteFile(s_tickfile, line, n, &w, NULL);
        s_outside_calls = 0;
    }
    s_steps_at_tick = s_steps;
    if (tick == s_step_from) { s_stepping = 1; spike_log("istep: on at tick %u\n", tick); }
    if (tick == s_step_to + 1) { s_stepping = 0; spike_log("istep: off at tick %u\n", tick); }
    if (s_stepping) *eflags |= 0x100;   /* TF: trap after the stub's popfd */
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
    if (s_istep) {
        s_stepping = 0;
        HANDLE f = spike_open("istep_cov.bin"); DWORD w;
        WriteFile(f, s_cov, (IMG_HI - IMG_LO) / 8, &w, NULL);
        CloseHandle(f); CloseHandle(s_tickfile);
        spike_log("istep: %llu instructions stepped, %u executions outside code sections\n",
                  (unsigned long long)s_steps, s_unknown_eips);
    }
    if (s_codewatch) spike_log("codewatch: %u changed ranges\n", s_code_changes);
}
