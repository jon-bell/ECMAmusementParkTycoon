/* rcthook.dll: pins the nondeterminism of rct.exe 1.08.183 (English) and records its behaviour.
 *
 * Built as dinput.dll, a proxy for the DirectInput DLL that rct.exe imports (DINPUT.dll:
 * DirectInputCreateA). The run copies it next to rct.exe and sets WINEDLLOVERRIDES=dinput=n, so
 * Wine's loader maps it while binding rct.exe's imports and runs DllMain after every import is
 * bound and before rct.exe's entry point. rct.exe itself is never modified. It
 *   1. replaces every nondeterministic OS input with a deterministic one (see PINS below),
 *   2. records a binary trace: every RNG draw (call site, value), every game tick (tick number,
 *      RNG state, hash of the static game state), every game command, every frame,
 *   3. replays a command-level input script (load scenario, game commands, keys, quit).
 *
 * PINS (each one is a nondeterminism source found in rct.exe's imports or code):
 *   timeGetTime, GetTickCount   virtual clock: starts at VT_BASE, advances RCTHOOK_QUANTUM ms per
 *                               query (busy-waits terminate; one logic tick per frame). The RNG
 *                               seed is timeGetTime() ^ srand0 (0x43054F), so this is required.
 *   Sleep                       advances the virtual clock, does not block.
 *   GetSystemTime               fixed 2000-01-13 12:00:00 + virtual elapsed time.
 *   SetTimer / KillTimer        no OS timer; WM_TIMER is synthesized from the virtual clock when
 *                               the message queue is empty.
 *   timeSetEvent                (sound streaming callback thread) not started; logged.
 *   DirectSoundCreate/Enumerate fail with DSERR_NODRIVER (no audio thread, no audio state).
 *   DirectInputCreateA          fake in-process DirectInput: keyboard/mouse state comes from the
 *                               script only (all zero by default).
 *   GetCursorPos / SetCursorPos fixed virtual cursor (script-controlled); SetCursorPos moves it.
 *   window procedure            mouse/keyboard window messages are dropped (logged).
 *   PeekMessageA                MSG.time = virtual clock, MSG.pt = virtual cursor (Wine: real ones).
 *   GetOpenFileNameA/GetSaveFileNameA  never shown: answered by the script's "file" action or cancelled.
 *   GetComputerName/GetUserName fixed strings. GlobalMemoryStatus, GetDiskFreeSpace fixed values.
 *   GetEnvironmentStrings(W)    a fixed environment block (the real one varies with the run).
 *   FindFirstFile/FindNextFile  results sorted by name (directory order is filesystem-dependent),
 *                               search handles 0x46490000 + 4*slot (lowest free slot),
 *                               timestamps fixed; on the CD drive D:, Windows-style 8.3 aliases
 *                               (the copy protection at 0x42F1D3 rejects Wine's hashed aliases).
 * Not pinned here but by the run environment (scripts/oracle-run.sh): a fresh copy of the
 * pristine prefix per run, a private 1024x768x24 Xvfb, the Wine build, no audio device.
 *
 * Configuration (environment, inherited through Wine):
 *   RCTHOOK_OUT      directory for trace.bin, hook.log, dumps (Windows path, e.g. Z:\...)
 *   RCTHOOK_SCRIPT   input script (see oracle/README.md); unreadable or malformed is fatal
 *   RCTHOOK_QUANTUM  virtual ms per time query (default 1)
 *   RCTHOOK_REALTIME =1 disables the time pins (a known-bad oracle for the gate's self-test)
 *   RCTHOOK_CHUNKS   =0 disables per-chunk state hashes
 *   RCTHOOK_PASSTHROUGH =1 real mouse and cursor, for interactive discovery only (never a gate)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <commdlg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trace.h"
#include "spike.h"
#ifndef ORACLE_BUILD_ID
#define ORACLE_BUILD_ID 0ULL   /* set by the Makefile */
#endif

/* ---------------------------------------------------------------- binary addresses */
#define A_RNG_STORE    0x5DF42Au   /* mov [srand1],eax  (eax = drawn value)            */
#define A_TICK         0x43888Eu   /* inc dword [0x88741C] : first insn of logic tick   */
#define A_FRAME        0x4385D8u   /* per-frame function, called from the main loop     */
#define A_FRAME_BODY   0x4386ECu   /* frame body, after the frame saved esp in [0x991F6C] */
#define A_DO_COMMAND   0x426F56u   /* game_do_command(esi=cmd, bl=flags, ...)            */
#define A_NEW_GAME     0x43054Eu   /* start scenario #ax (seeds RNG, loads, longjmps out) */
#define A_SRAND0       0x6E3B88u
#define A_SRAND1       0x6E3B8Cu
#define A_TICKCOUNT    0x6E3B84u   /* incremented every logic tick                       */
#define A_INITDONE     0x628CB8u   /* byte: game initialised (frame function)            */
#define A_TITLE        0x628CB9u   /* byte: title-sequence state (0 = playing a park)   */
#define STATE_LO       0x5F4000u   /* DATASEG start                                     */
#define STATE_HI       0x9A161Cu   /* DATASEG end                                       */
#define STATE2_LO      0x9A2000u   /* DataSeg start                                     */
#define STATE2_HI      0x9B2301u   /* DataSeg end                                       */
#define CHUNK          0x10000u

#define VT_BASE        5000000u

typedef struct { uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax, eflags; } regs_t;
/* pushad stores esp as it was after the stub's pushfd: the hooked code's esp is 4 higher */
#define ORIG_ESP(r) ((r)->esp + 4)

/* asm helper (callasm.S): call a game routine with a full register set, capture registers/flags */
extern void __cdecl call_asm(uint32_t target, regs_t *r);

/* ---------------------------------------------------------------- config and output */
static char g_out[MAX_PATH];
static int g_realtime, g_chunks = 1;
static int g_passthrough;   /* discovery only: real mouse/keyboard, real cursor; never for gates */
static int g_pt_buttons;    /* passthrough: buttons held, from window messages */
static uint32_t g_quantum = 1;
static HANDLE g_trace = INVALID_HANDLE_VALUE, g_log = INVALID_HANDLE_VALUE;
static uint8_t *g_tbuf; static uint32_t g_tlen;
#define TBUF_SIZE (1u << 22)

static void tflush(void)
{
    DWORD w;
    if (g_tlen && g_trace != INVALID_HANDLE_VALUE) WriteFile(g_trace, g_tbuf, g_tlen, &w, NULL);
    g_tlen = 0;
}
static void trec(uint32_t kind, uint32_t a, uint32_t b, uint32_t c)
{
    if (!g_tbuf) return;
    if (g_tlen + 16 > TBUF_SIZE) tflush();
    uint32_t *p = (uint32_t *)(g_tbuf + g_tlen);
    p[0] = kind; p[1] = a; p[2] = b; p[3] = c; g_tlen += 16;
}
static void logf_(const char *fmt, ...)
{
    char b[1024]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof b - 1) n = sizeof b - 1;
    DWORD w; if (g_log != INVALID_HANDLE_VALUE) WriteFile(g_log, b, n, &w, NULL);
}
static HANDLE open_out(const char *name)
{
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s\\%s", g_out, name);
    return CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
}
HANDLE spike_open(const char *name) { return open_out(name); }
void spike_log(const char *fmt, ...)
{
    char b[1024]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof b - 1) n = sizeof b - 1;
    DWORD w; if (g_log != INVALID_HANDLE_VALUE) WriteFile(g_log, b, n, &w, NULL);
}

/* ---------------------------------------------------------------- run state */
static uint32_t g_vt = VT_BASE;          /* virtual clock, ms */
static uint32_t g_frame, g_tick;         /* frames entered, logic ticks started */
static uint32_t g_rng_draws;
static int g_quitting;
static int g_loading;                    /* a scenario load is in progress (it longjmps out) */

/* ---------------------------------------------------------------- state hashing */
/* State bytes that hold values the OS chose (addresses of memory Wine allocated or mapped, handles):
 * oracle/mask.h, shared with the JS host. They read as 0 in the masked hash. g_mask holds, per
 * 32-bit word of the hashed ranges, the word's masked bits. */
#define NW1 ((STATE_HI - STATE_LO + 3) / 4)
#define NW2 ((STATE2_HI - STATE2_LO + 3) / 4)
static uint32_t *g_mask;    /* at a fixed address Wine leaves free: a 4 MiB .bss or a heap block would
                              move where Wine places the game's memory (DIB, CSG1 view, heaps) */
static void mask_bytes(uint32_t a, uint32_t n)
{
    for (uint32_t b = a; b < a + n; b++) {
        uint32_t i;
        if (b >= STATE_LO && b < STATE_HI) i = (b - STATE_LO) / 4;
        else if (b >= STATE2_LO && b < STATE2_HI) i = NW1 + (b - STATE2_LO) / 4;
        else continue;
        uint32_t base = b >= STATE2_LO ? STATE2_LO : STATE_LO;
        g_mask[i] |= 0xFFu << (8 * ((b - base) & 3));
    }
}
static uint32_t g_mask_dwords;
static void mask_build(void)
{
    g_mask = VirtualAlloc((void *)0x3E000000, 4 * (NW1 + NW2), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_mask) { logf_("FATAL: mask table not allocatable at 0x3E000000\n"); TerminateProcess(GetCurrentProcess(), 3); }
#define MASK_DWORD(a) do { mask_bytes((a), 4); g_mask_dwords++; } while (0);
#define MASK_STRIDE(b, s, n) do { for (uint32_t i_ = 0; i_ < (uint32_t)(n); i_++) mask_bytes((b) + i_ * (s), 4); g_mask_dwords += (n); } while (0);
#include "mask.h"
#undef MASK_DWORD
#undef MASK_STRIDE
}

/* FNV-1a over 32-bit words, 64-bit state: raw, and with masked bytes read as 0 */
static uint64_t hash_range(uint32_t lo, uint32_t hi, uint64_t *mh)
{
    uint64_t h = 0xcbf29ce484222325ull, m = *mh;
    const uint32_t *p = (const uint32_t *)lo, *e = (const uint32_t *)(hi & ~3u);
    const uint32_t *mk = g_mask + (lo >= STATE2_LO ? NW1 + (lo - STATE2_LO) / 4 : (lo - STATE_LO) / 4);
    for (; p < e; p++, mk++) {
        uint32_t w = *p;
        h ^= w; h *= 0x100000001b3ull;
        m ^= w & ~*mk; m *= 0x100000001b3ull;
    }
    for (const uint8_t *q = (const uint8_t *)e; q < (const uint8_t *)hi; q++) {
        h ^= *q; h *= 0x100000001b3ull; m ^= *q; m *= 0x100000001b3ull;
    }
    *mh = m;
    return h;
}
static void record_state(uint32_t kind)
{
    uint64_t total = 0xcbf29ce484222325ull, mtotal = 0xcbf29ce484222325ull;
    uint32_t idx = 0;
    static const uint32_t ranges[2][2] = {{STATE_LO, STATE_HI}, {STATE2_LO, STATE2_HI}};
    for (int r = 0; r < 2; r++)
        for (uint32_t a = ranges[r][0]; a < ranges[r][1]; a += CHUNK, idx++) {
            uint32_t b = a + CHUNK < ranges[r][1] ? a + CHUNK : ranges[r][1];
            uint64_t h = hash_range(a, b, &mtotal);
            if (g_chunks) trec(TR_CHUNK, idx, (uint32_t)h, (uint32_t)(h >> 32));
            total = (total ^ h) * 0x100000001b3ull;
        }
    trec(kind, g_tick, (uint32_t)total, (uint32_t)(total >> 32));
    trec(TR_MSTATE, g_tick, (uint32_t)mtotal, (uint32_t)(mtotal >> 32));
}
static void dump_state(const char *tag)
{
    char name[64]; snprintf(name, sizeof name, "dump_%s_t%u.bin", tag, g_tick);
    HANDLE h = open_out(name); DWORD w;
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, (void *)STATE_LO, STATE_HI - STATE_LO, &w, NULL);
    WriteFile(h, (void *)STATE2_LO, STATE2_HI - STATE2_LO, &w, NULL);
    CloseHandle(h);
    logf_("dump %s tick %u -> %s\n", tag, g_tick, name);
}

/* ---------------------------------------------------------------- inline hooks */
typedef void (__cdecl *hook_fn)(regs_t *);
static uint32_t g_tick_disp;     /* where the tick hook's stub runs the displaced instruction */
static uint8_t *g_stubs; static uint32_t g_stub_used;

/* Patch `len` bytes at `addr` with a jmp to a stub that saves all registers and flags, calls
 * fn(regs*), restores (possibly modified) registers, runs the displaced instructions and jumps
 * back. Displaced instructions must be position independent, except a leading call rel32. */
static void hook_at(uint32_t addr, uint32_t len, hook_fn fn)
{
    uint8_t *s = g_stubs + g_stub_used, *p = s;
    *p++ = 0x9C;                                   /* pushfd */
    *p++ = 0x60;                                   /* pushad */
    *p++ = 0x54;                                   /* push esp */
    *p++ = 0xE8; *(int32_t *)p = (int32_t)((uint32_t)fn - ((uint32_t)p + 4)); p += 4;
    *p++ = 0x83; *p++ = 0xC4; *p++ = 0x04;         /* add esp,4 */
    *p++ = 0x61;                                   /* popad */
    *p++ = 0x9D;                                   /* popfd */
    const uint8_t *o = (const uint8_t *)addr;
    uint32_t disp = (uint32_t)p, reloc_ret = 0;
    if (o[0] == 0xE8) {                            /* relocate call rel32 */
        uint32_t target = addr + 5 + *(int32_t *)(o + 1);
        *p++ = 0xE8; *(int32_t *)p = (int32_t)(target - ((uint32_t)p + 4)); p += 4;
        reloc_ret = (uint32_t)p;
        memcpy(p, o + 5, len - 5); p += len - 5;
    } else { memcpy(p, o, len); p += len; }
    spike_add_hook(addr, len, disp, reloc_ret, reloc_ret ? addr + 5 : 0);
    if (addr == A_TICK) g_tick_disp = disp;
    *p++ = 0xE9; *(int32_t *)p = (int32_t)((addr + len) - ((uint32_t)p + 4)); p += 4;
    g_stub_used += (uint32_t)(p - s + 15) & ~15u;

    DWORD old; VirtualProtect((void *)addr, len, PAGE_EXECUTE_READWRITE, &old);
    uint8_t *d = (uint8_t *)addr;
    d[0] = 0xE9; *(int32_t *)(d + 1) = (int32_t)((uint32_t)s - (addr + 5));
    for (uint32_t i = 5; i < len; i++) d[i] = 0x90;
    VirtualProtect((void *)addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)addr, len);
}

static void patch_iat(uint32_t slot, void *fn, void **orig)
{
    DWORD old; VirtualProtect((void *)slot, 4, PAGE_READWRITE, &old);
    if (orig) *orig = *(void **)slot;
    *(void **)slot = fn;
    VirtualProtect((void *)slot, 4, old, &old);
}

/* ---------------------------------------------------------------- script */
enum { W_FRAME, W_TICK };
enum { A_QUIT, A_CMD, A_LOAD, A_KEY, A_CURSOR, A_DUMP, A_CALL, A_POKE, A_SHOT, A_FB, A_MOUSE, A_FILE, A_CHAR, A_DIMOUSE, A_MOVE };
typedef struct {
    int when_kind; uint32_t when; int action; regs_t r; uint32_t arg, arg2; char text[MAX_PATH];
    int done; int line; int rel;
} action_t;
static uint32_t g_load_frame;            /* frame at which the last scenario load completed */
static action_t *g_act; static int g_nact, g_next_act;

static uint8_t g_keys[256];                       /* DirectInput keyboard state */
static int32_t g_dm_dx, g_dm_dy; static uint32_t g_dm_buttons;   /* DirectInput mouse (dimouse) */
static char g_file_answer[MAX_PATH]; static int g_file_pending;  /* next file dialog (file) */
typedef struct { uint32_t m, w, l; } qmsg_t;
static qmsg_t g_charq[64]; static uint32_t g_char_head, g_nchar;  /* messages posted by the script */
static HWND g_hwnd;
static LONG g_cur_x = 1000, g_cur_y = 740;        /* virtual cursor (screen coordinates) */

static int parse_reg(const char *tok, regs_t *r)
{
    static const char *names[] = {"edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax", "eflags"};
    const char *eq = strchr(tok, '='); if (!eq) return 0;
    for (int i = 0; i < 9; i++)
        if ((size_t)(eq - tok) == strlen(names[i]) && !strncmp(tok, names[i], eq - tok)) {
            ((uint32_t *)r)[i] = strtoul(eq + 1, NULL, 0); return 1;
        }
    return 0;
}
static void fatal(const char *why, int line)
{
    logf_("FATAL: %s (script line %d)\n", why, line);
    spike_abort();
    if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
    TerminateProcess(GetCurrentProcess(), 3);
}
static void load_script(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { logf_("script: cannot open %s\n", path); fatal("script unreadable", 0); }
    char line[1024]; int ln = 0;
    /* actions live at a fixed address, not in the DLL's heap: a long script would otherwise grow
     * that heap before the game starts and move where Wine places the game's memory */
    g_act = VirtualAlloc((void *)0x3D000000, 0x01000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_act) fatal("action arena not allocatable at 0x3D000000", 0);
    int cap = 0x01000000 / sizeof *g_act;
    while (fgets(line, sizeof line, f)) {
        ln++;
        char *c = strchr(line, '#'); if (c) *c = 0;
        char *tok[32]; int nt = 0;
        for (char *t = strtok(line, " \t\r\n"); t && nt < 32; t = strtok(NULL, " \t\r\n")) tok[nt++] = t;
        if (!nt) continue;
        if (!strcmp(tok[0], "seed") && nt >= 2) {
            /* virtual clock at process start; the scenario RNG seed is timeGetTime() ^ srand0 */
            g_vt = strtoul(tok[1], NULL, 0);
            logf_("script:%d: seed: virtual clock starts at %u\n", ln, g_vt);
            continue;
        }
        if (!strcmp(tok[0], "quantum") && nt >= 2) {
            /* virtual ms per time query (overrides RCTHOOK_QUANTUM); recorded in TR_HEADER */
            g_quantum = strtoul(tok[1], NULL, 0);
            if (!g_quantum) fatal("quantum must be at least 1", ln);
            logf_("script:%d: quantum %u\n", ln, g_quantum);
            continue;
        }
        if (nt < 3) fatal("action too short", ln);
        if (strcmp(tok[0], "tick") && strcmp(tok[0], "frame")) fatal("time must be 'tick N' or 'frame [+]N'", ln);
        if (g_nact == cap) fatal("script has too many actions", ln);
        action_t *a = &g_act[g_nact]; memset(a, 0, sizeof *a); a->line = ln;
        a->when_kind = !strcmp(tok[0], "tick") ? W_TICK : W_FRAME;
        a->rel = tok[1][0] == '+';               /* frame +N: N frames after the last load */
        a->when = strtoul(tok[1] + a->rel, NULL, 0);
        const char *v = tok[2];
        if (!strcmp(v, "quit")) a->action = A_QUIT;
        else if (!strcmp(v, "dump")) a->action = A_DUMP;
        else if (!strcmp(v, "shot")) a->action = A_SHOT;
        else if (!strcmp(v, "fb")) a->action = A_FB;
        else if (!strcmp(v, "load") && nt >= 4) { a->action = A_LOAD; a->arg = strtoul(tok[3], NULL, 0); }
        else if (!strcmp(v, "cmd") && nt >= 4) {
            a->action = A_CMD; a->arg = strtoul(tok[3], NULL, 0);
            for (int i = 4; i < nt; i++) parse_reg(tok[i], &a->r);
        } else if (!strcmp(v, "call") && nt >= 4) {
            a->action = A_CALL; a->arg = strtoul(tok[3], NULL, 0);
            for (int i = 4; i < nt; i++) parse_reg(tok[i], &a->r);
        } else if (!strcmp(v, "key") && nt >= 5) {
            a->action = A_KEY; a->arg = strtoul(tok[3], NULL, 0); a->arg2 = strtoul(tok[4], NULL, 0);
        } else if (!strcmp(v, "cursor") && nt >= 5) {
            a->action = A_CURSOR; a->arg = strtoul(tok[3], NULL, 0); a->arg2 = strtoul(tok[4], NULL, 0);
        } else if (!strcmp(v, "mouse") && nt >= 6) {
            /* mouse <x> <y> <event>: event 1 left down, 2 right down, 3 left up, 4 right up */
            a->action = A_MOUSE; a->arg = strtoul(tok[3], NULL, 0); a->arg2 = strtoul(tok[4], NULL, 0);
            a->r.eax = strtoul(tok[5], NULL, 0);
        } else if (!strcmp(v, "file") && nt >= 4) {
            a->action = A_FILE; snprintf(a->text, sizeof a->text, "%s", tok[3]);
        } else if (!strcmp(v, "char") && nt >= 4) {
            a->action = A_CHAR;
            a->arg = strlen(tok[3]) == 1 ? (uint8_t)tok[3][0] : strtoul(tok[3], NULL, 0);
        } else if (!strcmp(v, "move") && nt >= 5) {
            a->action = A_MOVE; a->arg = strtoul(tok[3], NULL, 0); a->arg2 = strtoul(tok[4], NULL, 0);
        } else if (!strcmp(v, "dimouse") && nt >= 6) {
            a->action = A_DIMOUSE; a->arg = (uint32_t)strtol(tok[3], NULL, 0); a->arg2 = (uint32_t)strtol(tok[4], NULL, 0);
            a->r.eax = strtoul(tok[5], NULL, 0);
        } else if (!strcmp(v, "poke") && nt >= 5) {
            a->action = A_POKE; a->arg = strtoul(tok[3], NULL, 0); a->arg2 = strtoul(tok[4], NULL, 0);
        } else fatal("unknown action or missing arguments", ln);
        g_nact++;
    }
    fclose(f);
    logf_("script: %d actions from %s\n", g_nact, path);
}

static void do_quit(void)
{
    g_quitting = 1;
    spike_quit();
    record_state(TR_FINAL);
    trec(TR_END, g_frame, g_tick, g_rng_draws);
    tflush();
    logf_("quit at frame %u tick %u, rng draws %u, vt %u\n", g_frame, g_tick, g_rng_draws, g_vt);
    if (g_trace != INVALID_HANDLE_VALUE) CloseHandle(g_trace);
    if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
    TerminateProcess(GetCurrentProcess(), 0);
}


/* The game's own 8-bit screen buffer (drawing context at 0x99FB7C: bits, x, y, w, h, pitch),
 * written as a PGM of palette indices. */
#define A_SCREEN_DPI 0x99FB7Cu
static void fb_dump(void)
{
    const uint8_t *bits = *(uint8_t **)A_SCREEN_DPI;
    uint16_t w = *(uint16_t *)(A_SCREEN_DPI + 8), h = *(uint16_t *)(A_SCREEN_DPI + 10);
    uint16_t pitch = *(uint16_t *)(A_SCREEN_DPI + 12);
    logf_("fb: bits %p x %d y %d w %u h %u pitch %u zoom %u\n", bits, *(int16_t *)(A_SCREEN_DPI + 4),
          *(int16_t *)(A_SCREEN_DPI + 6), w, h, pitch, *(uint16_t *)(A_SCREEN_DPI + 14));
    if (!bits || !w || !h) return;
    char name[64]; snprintf(name, sizeof name, "fb_t%u_f%u.pgm", g_tick, g_frame);
    HANDLE f = open_out(name); DWORD wr; char hdr[64];
    int n = snprintf(hdr, sizeof hdr, "P5\n%u %u\n255\n", w, h);
    WriteFile(f, hdr, n, &wr, NULL);
    for (uint32_t y = 0; y < h; y++) WriteFile(f, bits + y * (uint32_t)(w + pitch), w, &wr, NULL);
    CloseHandle(f);
}

/* Debug aid, not part of any projection: the game window as a 24-bit BMP. */
static void screenshot(void)
{
    if (!g_hwnd) return;
    RECT rc; GetClientRect(g_hwnd, &rc);
    int w = rc.right, h = rc.bottom;
    HDC wdc = GetDC(g_hwnd), mdc = CreateCompatibleDC(wdc);
    BITMAPINFO bi; memset(&bi, 0, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24;
    void *bits; HBITMAP bm = CreateDIBSection(mdc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    HGDIOBJ old = SelectObject(mdc, bm);
    BitBlt(mdc, 0, 0, w, h, wdc, 0, 0, SRCCOPY);
    GdiFlush();
    uint32_t stride = (w * 3 + 3) & ~3u, size = stride * h;
    BITMAPFILEHEADER fh; memset(&fh, 0, sizeof fh);
    fh.bfType = 0x4D42; fh.bfOffBits = sizeof fh + sizeof bi.bmiHeader; fh.bfSize = fh.bfOffBits + size;
    char name[64]; snprintf(name, sizeof name, "shot_f%u.bmp", g_frame);
    HANDLE f = open_out(name); DWORD wr;
    WriteFile(f, &fh, sizeof fh, &wr, NULL); WriteFile(f, &bi.bmiHeader, sizeof bi.bmiHeader, &wr, NULL);
    WriteFile(f, bits, size, &wr, NULL); CloseHandle(f);
    SelectObject(mdc, old); DeleteObject(bm); DeleteDC(mdc); ReleaseDC(g_hwnd, wdc);
}

static void run_actions(int kind)
{
    while (g_next_act < g_nact) {
        action_t *a = &g_act[g_next_act];
        uint32_t now = a->when_kind == W_TICK ? g_tick : g_frame - (a->rel ? g_load_frame : 0);
        if (a->when_kind != kind || now < a->when) return;
        /* the scenario-select window only exists once the intro has finished */
        if (a->action == A_LOAD && *(uint8_t *)A_TITLE) return;
        g_next_act++;
        switch (a->action) {
        case A_QUIT: do_quit(); break;
        case A_DUMP: dump_state("script"); break;
        case A_SHOT: screenshot(); break;
        case A_FB: fb_dump(); break;
        case A_KEY: g_keys[a->arg & 255] = a->arg2 ? 0x80 : 0;
            trec(TR_INPUT, g_tick, 1, a->arg | a->arg2 << 16); break;
        case A_MOUSE: {
            /* the game's mouse event queue, as filled by its window procedure (0x403454) */
            uint32_t head = *(uint32_t *)0x5E91E4, next = (head + 1) & 0x3F;
            if (next == *(uint32_t *)0x5E91E8) { logf_("mouse queue full\n"); break; }
            uint32_t *e = (uint32_t *)(0x5F1CC0 + head * 12);
            e[0] = a->arg; e[1] = a->arg2; e[2] = a->r.eax;
            *(uint32_t *)0x5E91E4 = next;
            g_cur_x = a->arg; g_cur_y = a->arg2;
            trec(TR_INPUT, g_tick, 4, a->arg | a->arg2 << 16 | a->r.eax << 28);
            break;
        }
        case A_FILE:     /* the answer of the next file dialog */
            snprintf(g_file_answer, sizeof g_file_answer, "%s", a->text); g_file_pending = 1;
            trec(TR_INPUT, g_tick, 5, a->line);
            logf_("line %d: next file dialog answers %s\n", a->line, a->text);
            break;
        case A_CHAR:     /* WM_CHAR through the message queue, as a key press would deliver it */
        case A_MOVE: {   /* WM_MOUSEMOVE (client coordinates, no buttons): the game's hover position */
            qmsg_t q = a->action == A_CHAR ? (qmsg_t){WM_CHAR, a->arg, 1}
                                           : (qmsg_t){WM_MOUSEMOVE, 0, (a->arg & 0xFFFF) | (a->arg2 & 0xFFFF) << 16};
            if (!g_hwnd || g_nchar >= 64) { logf_("line %d: message %#x not delivered (no window or queue full)\n", a->line, q.m); break; }
            g_charq[(g_char_head + g_nchar++) & 63] = q;
            PostMessageA(g_hwnd, q.m, q.w, q.l);
            if (a->action == A_CHAR) trec(TR_INPUT, g_tick, 6, a->arg);
            else { trec(TR_INPUT, g_tick, 8, q.l); g_cur_x = a->arg; g_cur_y = a->arg2; }
            break;
        }
        case A_DIMOUSE:  /* DirectInput mouse: deltas add up until the game reads them; buttons persist */
            g_dm_dx += (int32_t)a->arg; g_dm_dy += (int32_t)a->arg2; g_dm_buttons = a->r.eax & 0xF;
            trec(TR_INPUT, g_tick, 7, (a->arg & 0xFFF) | (a->arg2 & 0xFFF) << 12 | g_dm_buttons << 24);
            break;
        case A_CURSOR: g_cur_x = a->arg; g_cur_y = a->arg2;
            trec(TR_INPUT, g_tick, 2, a->arg | a->arg2 << 16); break;
        case A_POKE: *(uint8_t *)a->arg ^= (uint8_t)a->arg2;   /* fault injection for gate self-tests */
            trec(TR_INPUT, g_tick, 3, a->arg); logf_("poke [%#x]^=%#x at tick %u\n", a->arg, a->arg2, g_tick); break;
        case A_LOAD: {
            /* What the scenario-select window does (0x4304A7): ax = scenario number, call the
             * new-game routine from inside the frame. On success it resets esp to the frame's
             * saved esp and returns to the main loop, so this call does not return here. */
            regs_t r; memset(&r, 0, sizeof r); r.eax = a->arg; r.eflags = 0x202;
            trec(TR_LOAD, g_tick, a->arg, g_frame);
            logf_("load scenario %u at frame %u tick %u\n", a->arg, g_frame, g_tick);
            g_loading = 1;
            spike_guest_call(A_NEW_GAME, 0);
            call_asm(A_NEW_GAME, &r);
            g_loading = 0;
            trec(TR_NOTE, g_tick, 2, a->arg);
            logf_("load scenario %u FAILED (returned, eflags %#x)\n", a->arg, r.eflags);
            break;
        }
        case A_CMD: case A_CALL: {
            regs_t r = a->r;
            uint32_t target = A_DO_COMMAND;
            if (a->action == A_CMD) r.esi = a->arg; else target = a->arg;
            trec(TR_INJECT, g_tick, a->action == A_CMD ? a->arg : target, a->line);
            /* flags at entry are defined (CF PF AF ZF SF DF OF from the script, default 0; IF set) */
            r.eflags = (r.eflags & 0xCD5u) | 0x202u;
            trec(TR_INJ_IN, r.eax, r.ebx, r.ecx); trec(TR_INJ_IN2, r.edx, r.esi, r.edi);
            trec(TR_INJ_IN3, r.ebp, r.eflags & 0xCD5u, 0);
            spike_guest_call(target, 0);
            call_asm(target, &r);
            trec(TR_REGS_OUT, r.eax, r.ebx, r.ecx); trec(TR_REGS_OUT2, r.edx, r.esi, r.edi);
            trec(TR_REGS_OUT3, r.ebp, r.eflags, 0);
            logf_("line %d %s %#x at frame %u tick %u -> ebx=%#x\n", a->line,
                  a->action == A_CMD ? "cmd" : "call", a->action == A_CMD ? a->arg : target,
                  g_frame, g_tick, r.ebx);
            if (a->action == A_CMD && r.ebx == 0x80000000u)   /* the game's error message (string id) */
                logf_("line %d cmd %#x failed: error string id [0x991EFC] = %#x\n", a->line, a->arg,
                      *(uint16_t *)0x991EFC);
            break;
        }
        }
    }
}

/* ---------------------------------------------------------------- game hooks */
static void __cdecl h_rng(regs_t *r)
{
    uint32_t caller = *(uint32_t *)(ORIG_ESP(r) + 4) - 5;  /* [esp]=saved ebx, [esp+4]=return */
    g_rng_draws++;
    trec(TR_RNG, g_tick, caller, r->eax);
}
static void __cdecl h_tick(regs_t *r)
{
    g_tick++;
    spike_tick((uint32_t *)r, g_tick, A_TICK, g_tick_disp);
    trec(TR_TICK, g_tick, *(uint32_t *)A_SRAND0, *(uint32_t *)A_SRAND1);
    record_state(TR_STATE);
    run_actions(W_TICK);
    spike_tick_end((uint32_t *)r, g_tick_disp);
}
static void __cdecl h_frame(regs_t *r)
{
    (void)r;
    if (g_loading) {   /* previous frame's scenario load completed by longjmp */
        g_loading = 0;
        trec(TR_NOTE, g_tick, 3, *(uint16_t *)0x8DBED2);
        logf_("scenario %u loaded, frame %u (title ticks before load: %u); tick counter reset\n",
              *(uint16_t *)0x8DBED2, g_frame, g_tick);
        g_tick = 0;   /* script ticks count from the scenario start */
        g_load_frame = g_frame + 1;
    }
    g_frame++;
    spike_frame(g_frame, g_tick);
    trec(TR_FRAME, g_frame, g_vt, g_tick);
}
static void __cdecl h_frame_body(regs_t *r)
{
    (void)r;
    static uint16_t last_mode = 0xffff;
    if (*(uint16_t *)0x99A500 != last_mode) {
        logf_("frame %u tick %u: [0x99A500] %#x -> %#x, scenario %u\n", g_frame, g_tick, last_mode,
              *(uint16_t *)0x99A500, *(uint16_t *)0x8DBED2);
        last_mode = *(uint16_t *)0x99A500;
    }
    run_actions(W_FRAME);
}
static void __cdecl h_command(regs_t *r)
{
    uint32_t caller = *(uint32_t *)ORIG_ESP(r) - 5;
    if (caller < 0x401000 || caller >= 0x9BD000) caller = 0xFFFFFFFF;   /* injected by the script */
    trec(TR_COMMAND, g_tick, r->esi | (r->ebx & 0xff) << 8 | *(uint8_t *)0x5F4A6A << 16, caller);
    trec(TR_REGS_IN, r->eax, r->ebx, r->ecx); trec(TR_REGS_IN2, r->edx, r->esi, r->edi);
    trec(TR_REGS_IN3, r->ebp, r->eflags & 0xCD5u, 0);   /* handlers receive ebp too */
}

/* ---------------------------------------------------------------- OS pins */
static DWORD WINAPI p_timeGetTime(void) { if (g_realtime) return timeGetTime(); DWORD t = g_vt; g_vt += g_quantum; return t; }
static DWORD WINAPI p_GetTickCount(void) { if (g_realtime) return GetTickCount(); DWORD t = g_vt; g_vt += g_quantum; return t; }
static void WINAPI p_Sleep(DWORD ms) { if (g_realtime) { Sleep(ms); return; } g_vt += ms; logf_("Sleep(%lu) frame %u\n", ms, g_frame); }
static void WINAPI p_GetSystemTime(LPSYSTEMTIME st)
{
    if (g_realtime) { GetSystemTime(st); return; }
    FILETIME ft; SYSTEMTIME base = {2000, 1, 4, 13, 12, 0, 0, 0};
    SystemTimeToFileTime(&base, &ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (uint64_t)(g_vt - VT_BASE) * 10000;
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart;
    FileTimeToSystemTime(&ft, st);
}
static BOOL WINAPI p_GetCursorPos(LPPOINT p)
{
    if (g_passthrough) return GetCursorPos(p);
    p->x = g_cur_x; p->y = g_cur_y; return TRUE;
}
static BOOL WINAPI p_SetCursorPos(int x, int y)
{
    if (g_passthrough) return SetCursorPos(x, y);
    g_cur_x = x; g_cur_y = y; return TRUE;
}
/* environment: the process environment differs between runs (run directory, RCTHOOK_* settings,
 * the gate's padding); the game sees this fixed block instead. The hook reads the real one. */
#define ENV_BLOCK "COMSPEC=C:\\windows\\system32\\cmd.exe\0PATH=C:\\windows\\system32;C:\\windows\0" \
                  "SystemRoot=C:\\windows\0TEMP=C:\\windows\\temp\0TMP=C:\\windows\\temp\0windir=C:\\windows\0"
static char g_envA[] = ENV_BLOCK;            /* the literal's own NUL terminates the block */
static WCHAR g_envW[] = L"" ENV_BLOCK;
static LPCH WINAPI p_GetEnvironmentStrings(void) { return g_realtime ? GetEnvironmentStrings() : g_envA; }
static LPWCH WINAPI p_GetEnvironmentStringsW(void) { return g_realtime ? GetEnvironmentStringsW() : g_envW; }
static BOOL WINAPI p_FreeEnvironmentStringsA(LPCH p) { return p == g_envA ? TRUE : FreeEnvironmentStringsA(p); }
static BOOL WINAPI p_FreeEnvironmentStringsW(LPWCH p) { return p == g_envW ? TRUE : FreeEnvironmentStringsW(p); }
static BOOL WINAPI p_GetComputerNameA(LPSTR b, LPDWORD n) { strcpy(b, "ORACLE"); *n = 6; return TRUE; }
static BOOL WINAPI p_GetUserNameA(LPSTR b, LPDWORD n) { strcpy(b, "oracle"); *n = 7; return TRUE; }
static void WINAPI p_GlobalMemoryStatus(LPMEMORYSTATUS m)
{
    memset(m, 0, sizeof *m); m->dwLength = sizeof *m; m->dwMemoryLoad = 10;
    m->dwTotalPhys = 256u << 20; m->dwAvailPhys = 200u << 20;
    m->dwTotalPageFile = 512u << 20; m->dwAvailPageFile = 400u << 20;
    m->dwTotalVirtual = 2047u << 20; m->dwAvailVirtual = 1800u << 20;
}
static BOOL WINAPI p_GetDiskFreeSpaceA(LPCSTR root, LPDWORD spc, LPDWORD bps, LPDWORD freec, LPDWORD totc)
{
    (void)root; *spc = 8; *bps = 512; *freec = 0x40000; *totc = 0x100000; return TRUE;
}

/* timers */
static UINT_PTR g_timer_id; static UINT g_timer_period; static DWORD g_timer_due; static HWND g_timer_hwnd;
static UINT_PTR WINAPI p_SetTimer(HWND h, UINT_PTR id, UINT ms, TIMERPROC fn)
{
    logf_("SetTimer(%p,%u,%u,%p) frame %u\n", h, (unsigned)id, ms, fn, g_frame);
    if (g_realtime) return SetTimer(h, id, ms, fn);
    g_timer_hwnd = h; g_timer_id = id; g_timer_period = ms; g_timer_due = g_vt + ms;
    return id;
}
static BOOL WINAPI p_KillTimer(HWND h, UINT_PTR id)
{
    logf_("KillTimer(%p,%u) frame %u\n", h, (unsigned)id, g_frame);
    if (g_realtime) return KillTimer(h, id);
    if (id == g_timer_id) g_timer_period = 0;
    return TRUE;
}
static MMRESULT WINAPI p_timeSetEvent(UINT delay, UINT res, LPTIMECALLBACK cb, DWORD_PTR user, UINT flags)
{
    logf_("timeSetEvent(%u,%u,%p,%lx,%u) frame %u: not started\n", delay, res, cb, (unsigned long)user, flags, g_frame);
    trec(TR_NOTE, g_tick, 1, (uint32_t)cb);
    return 0x7777;
}
static MMRESULT WINAPI p_timeKillEvent(UINT id) { (void)id; return 0; }

static BOOL (WINAPI *r_PeekMessageA)(LPMSG, HWND, UINT, UINT, UINT);
static BOOL WINAPI p_PeekMessageA(LPMSG m, HWND h, UINT lo, UINT hi, UINT rm)
{
    BOOL got = r_PeekMessageA(m, h, lo, hi, rm);
    /* Wine stamps messages with the real tick count and the real cursor: give the virtual ones */
    if (got && !g_realtime) { m->time = g_vt; if (!g_passthrough) { m->pt.x = g_cur_x; m->pt.y = g_cur_y; } }
    if (!got && !g_realtime && g_timer_period && (int32_t)(g_vt - g_timer_due) >= 0) {
        memset(m, 0, sizeof *m);
        m->hwnd = g_timer_hwnd; m->message = WM_TIMER; m->wParam = g_timer_id; m->time = g_vt;
        if (rm & PM_REMOVE) g_timer_due = g_vt + g_timer_period;
        trec(TR_MSG, g_tick, WM_TIMER, (uint32_t)g_timer_id);
        return TRUE;
    }
    return got;
}

/* window procedure filter: drop all user input, log everything that reaches the game */
static WNDPROC g_wndproc;
static int is_input_msg(UINT m)
{
    return (m >= WM_MOUSEFIRST && m <= 0x020E) || (m >= WM_KEYFIRST && m <= WM_KEYLAST) ||
           (m >= WM_NCMOUSEMOVE && m <= 0x00AD) || m == WM_MOUSEHOVER || m == WM_MOUSELEAVE ||
           m == WM_NCMOUSEHOVER || m == WM_NCMOUSELEAVE || m == WM_SETCURSOR || m == WM_CAPTURECHANGED ||
           m == WM_INPUT;
}
static LRESULT CALLBACK filt_wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (!g_hwnd) g_hwnd = h;
    if (g_passthrough) {
        if (m == WM_LBUTTONDOWN) g_pt_buttons |= 1;
        if (m == WM_LBUTTONUP) g_pt_buttons &= ~1;
        if (m == WM_RBUTTONDOWN) g_pt_buttons |= 2;
        if (m == WM_RBUTTONUP) g_pt_buttons &= ~2;
    }
    if (g_nchar && g_charq[g_char_head & 63].m == m && g_charq[g_char_head & 63].w == (uint32_t)w &&
        g_charq[g_char_head & 63].l == (uint32_t)l) {
        g_char_head++; g_nchar--;           /* posted by a script "char"/"move" action: deliver it */
    } else if (is_input_msg(m) && !g_passthrough) {
        trec(TR_MSG_DROP, g_tick, m, 0);
        if (g_apitrace_on) apitrace_wndproc_drop(m, w, l);
        return DefWindowProcA(h, m, w, l);
    }
    if (m != WM_TIMER) trec(TR_MSG, g_tick, m, (uint32_t)w);
    logf_("msg %#x w=%#lx l=%#lx frame %u\n", m, (unsigned long)w, (unsigned long)l, g_frame);
    if (g_apitrace_on) apitrace_wndproc_enter((uint32_t)g_wndproc, (uint32_t)h, m, w, l);
    spike_guest_call((uint32_t)g_wndproc, 1);
    LRESULT res = CallWindowProcA(g_wndproc, h, m, w, l);
    if (g_apitrace_on) apitrace_wndproc_leave((uint32_t)res);
    return res;
}
static ATOM WINAPI p_RegisterClassA(const WNDCLASSA *wc)
{
    WNDCLASSA c = *wc;
    logf_("RegisterClassA(%s) wndproc %p\n", HIWORD(wc->lpszClassName) ? wc->lpszClassName : "#", wc->lpfnWndProc);
    if (!g_wndproc) { g_wndproc = c.lpfnWndProc; c.lpfnWndProc = filt_wndproc; }
    return RegisterClassA(&c);
}

/* sorted directory enumeration */
typedef struct { WIN32_FIND_DATAA *e; int n, i; } findset_t;
#define FIND_BASE 0x46490000u      /* search handles: FIND_BASE + 4*slot, lowest free slot */
#define MAX_FIND 16
#define FIND_CAP 512
static findset_t *g_find[MAX_FIND], g_findsets[MAX_FIND];
static WIN32_FIND_DATAA *g_findpool;       /* MAX_FIND * FIND_CAP entries at 0x3C000000 */
static int cmp_find(const void *a, const void *b)
{
    return strcmp(((const WIN32_FIND_DATAA *)a)->cFileName, ((const WIN32_FIND_DATAA *)b)->cFileName);
}
/* 8.3 aliases on the CD drive. The copy protection at 0x42F1D3 looks up D:\Saved Games and
 * requires '~' at index 5 of cAlternateFileName (else every new game quits to the title, via
 * the flag at 0x5F853C). Wine's hashed alias ("SAVE~YWG") has it at index 4. We report the
 * Windows-style alias (first five valid characters, "~1") that the genuine disc yields. */
static void cd_alias(WIN32_FIND_DATAA *d)
{
    if (!d->cAlternateFileName[0]) return;      /* name is already 8.3 */
    char a[14]; int k = 0;
    for (const char *p = d->cFileName; *p && k < 5; p++) {
        char c = *p;
        if (c == ' ' || c == '.') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        a[k++] = c;
    }
    a[k++] = '~'; a[k++] = '1'; a[k] = 0;
    logf_("cd alias: %s: %s -> %s\n", d->cFileName, d->cAlternateFileName, a);
    strcpy(d->cAlternateFileName, a);
}

/* Store a result the way FindFirstFileA/FindNextFileA do: the fields and the two names up to and
 * including their NUL. The rest of the caller's name buffers keeps whatever the caller had there
 * (the game reads its own stale bytes back into DATASEG at 0x5F9313). Copying the whole struct
 * would leak this DLL's uninitialised stack bytes, which vary with the environment's size. */
static void put_find(LPWIN32_FIND_DATAA out, const WIN32_FIND_DATAA *e)
{
    out->dwFileAttributes = e->dwFileAttributes;
    out->ftCreationTime = e->ftCreationTime; out->ftLastAccessTime = e->ftLastAccessTime;
    out->ftLastWriteTime = e->ftLastWriteTime;
    out->nFileSizeHigh = e->nFileSizeHigh; out->nFileSizeLow = e->nFileSizeLow;
    out->dwReserved0 = 0; out->dwReserved1 = 0;
    strcpy(out->cFileName, e->cFileName);
    strcpy(out->cAlternateFileName, e->cAlternateFileName);
}

static HANDLE WINAPI p_FindFirstFileA(LPCSTR pat, LPWIN32_FIND_DATAA out)
{
    WIN32_FIND_DATAA d; HANDLE h = FindFirstFileA(pat, &d);
    logf_("FindFirstFileA(%s) frame %u -> %s [%s]\n", pat, g_frame,
          h == INVALID_HANDLE_VALUE ? "(none)" : d.cFileName, h == INVALID_HANDLE_VALUE ? "" : d.cAlternateFileName);
    if (h == INVALID_HANDLE_VALUE) return h;
    /* result sets live in a fixed pool, not the DLL's heap (heap growth would move Wine's layout) */
    int k = 0;
    while (k < MAX_FIND && g_find[k]) k++;
    if (k == MAX_FIND || !g_findpool) {
        FindClose(h); logf_("FindFirstFileA: too many open searches\n"); SetLastError(ERROR_NO_MORE_FILES);
        return INVALID_HANDLE_VALUE;
    }
    findset_t *s = &g_findsets[k]; s->n = 0; s->i = 0; s->e = g_findpool + k * FIND_CAP;
    do {
        if (s->n < FIND_CAP) s->e[s->n++] = d;
        else { logf_("FindFirstFileA(%s): more than %d entries, rest dropped\n", pat, FIND_CAP); break; }
    } while (FindNextFileA(h, &d));
    FindClose(h);
    qsort(s->e, s->n, sizeof *s->e, cmp_find);
    for (int i = 0; i < s->n; i++) {   /* timestamps differ between installs; pin them */
        FILETIME ft = {0x5c2d8000, 0x01bf5d9b};  /* 2000-01-13 */
        s->e[i].ftCreationTime = s->e[i].ftLastAccessTime = s->e[i].ftLastWriteTime = ft;
    }
    if ((pat[0] == 'D' || pat[0] == 'd') && pat[1] == ':')
        for (int i = 0; i < s->n; i++) cd_alias(&s->e[i]);
    put_find(out, &s->e[0]); s->i = 1;
    /* the game keeps the handle in its state (0x5F9427): numbered handles, not an address */
    g_find[k] = s;
    return (HANDLE)(FIND_BASE + 4u * k);
}
static findset_t *find_of(HANDLE h)
{
    uint32_t k = ((uint32_t)h - FIND_BASE) / 4;
    return ((uint32_t)h - FIND_BASE) % 4 == 0 && k < MAX_FIND ? g_find[k] : NULL;
}
static BOOL WINAPI p_FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA out)
{
    findset_t *s = find_of(h);
    if (!s) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (s->i >= s->n) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
    put_find(out, &s->e[s->i++]); return TRUE;
}
static BOOL WINAPI p_FindClose(HANDLE h)
{
    findset_t *s = find_of(h);
    if (!s) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    g_find[((uint32_t)h - FIND_BASE) / 4] = NULL;
    return TRUE;
}

/* heuristic backtrace for discovery logs: stack words that are return addresses into the game */
static void log_backtrace(void)
{
    uint32_t *sp = (uint32_t *)__builtin_frame_address(0);
    int found = 0;
    logf_("  stack:");
    for (int i = 0; i < 400 && found < 12; i++) {
        uint32_t v = sp[i];
        if (v >= 0x401005 && v < 0x5E7000) {
            const uint8_t *c = (const uint8_t *)v;
            if (c[-5] == 0xE8 || (c[-6] == 0xFF && c[-5] == 0x15)) { logf_(" %#x", v); found++; }
        }
    }
    logf_("\n");
}

/* Modal dialogs and message boxes would block the run until its timeout. None appears in normal
 * play from a script, so any one is logged with a backtrace and ends the run (exit code 4).
 * (The modeless dialog the game creates at startup, CreateDialogParamA #101, is normal.) */
static void dialog_fatal(const char *what, const char *text)
{
    logf_("FATAL: %s: %s (frame %u tick %u)\n", what, text ? text : "", g_frame, g_tick);
    log_backtrace();
    spike_abort();
    tflush();
    if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
    TerminateProcess(GetCurrentProcess(), 4);
}
static int WINAPI p_MessageBoxA(HWND h, LPCSTR text, LPCSTR cap, UINT t)
{
    (void)h; (void)t; char b[512]; snprintf(b, sizeof b, "[%s] %s", cap ? cap : "", text ? text : "");
    dialog_fatal("MessageBoxA", b); return 0;
}
static INT_PTR WINAPI p_DialogBoxParamA(HINSTANCE i, LPCSTR tmpl, HWND h, DLGPROC p, LPARAM l)
{
    (void)i; (void)h; (void)p; (void)l; char b[64];
    snprintf(b, sizeof b, "template %s%u", HIWORD(tmpl) ? "" : "#", HIWORD(tmpl) ? 0 : LOWORD(tmpl));
    dialog_fatal("DialogBoxParamA", HIWORD(tmpl) ? tmpl : b); return 0;
}
/* Common file dialogs are modal: never open one. A script "file <name>" action answers the next
 * one with <game directory>\Saved Games\<name>; without one the dialog is cancelled. */
static BOOL file_dialog(LPOPENFILENAMEA o, const char *what)
{
    logf_("%s: title %s initial dir %s (frame %u tick %u)\n", what, o && o->lpstrTitle ? o->lpstrTitle : "-",
          o && o->lpstrInitialDir ? o->lpstrInitialDir : "-", g_frame, g_tick);
    if (!g_file_pending || !o || !o->lpstrFile) {
        logf_("%s: no script answer: cancelled\n", what); trec(TR_NOTE, g_tick, 4, 0); return FALSE;
    }
    g_file_pending = 0;
    char dir[MAX_PATH], path[MAX_PATH];
    GetModuleFileNameA(NULL, dir, sizeof dir);
    char *bs = strrchr(dir, '\\'); if (bs) *bs = 0;
    int n = snprintf(path, sizeof path, "%s\\Saved Games\\%s", dir, g_file_answer);
    if (n < 0 || (DWORD)n + 1 > o->nMaxFile) { logf_("%s: answer too long\n", what); trec(TR_NOTE, g_tick, 4, 0); return FALSE; }
    strcpy(o->lpstrFile, path);
    o->nFileOffset = (WORD)(n - strlen(g_file_answer));
    const char *dot = strrchr(g_file_answer, '.');
    o->nFileExtension = dot ? (WORD)(o->nFileOffset + (dot - g_file_answer) + 1) : 0;
    if (o->lpstrFileTitle && o->nMaxFileTitle > strlen(g_file_answer)) strcpy(o->lpstrFileTitle, g_file_answer);
    logf_("%s: answered %s\n", what, path);
    trec(TR_NOTE, g_tick, 4, 1);
    return TRUE;
}
static BOOL WINAPI p_GetOpenFileNameA(LPOPENFILENAMEA o) { return file_dialog(o, "GetOpenFileNameA"); }
static BOOL WINAPI p_GetSaveFileNameA(LPOPENFILENAMEA o) { return file_dialog(o, "GetSaveFileNameA"); }

static HANDLE WINAPI p_CreateFileA(LPCSTR n, DWORD acc, DWORD sh, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD fl, HANDLE t)
{
    HANDLE h = CreateFileA(n, acc, sh, sa, cd, fl, t);
    uint32_t ret = (uint32_t)__builtin_return_address(0);
    ret = apitrace_game_ret(ret);      /* returning through the register pin's trampoline */
    logf_("CreateFileA(%s, %#lx, disp %lu) from %#x frame %u -> %p\n", n, acc, cd, ret, g_frame, h);
    if (g_frame > 1) log_backtrace();
    trec(TR_FILE, g_tick, ret, h != INVALID_HANDLE_VALUE);
    return h;
}

/* DirectSound: no device */
static HRESULT WINAPI p_DirectSoundCreate(void *guid, void **ds, void *outer)
{
    (void)guid; (void)outer; logf_("DirectSoundCreate -> DSERR_NODRIVER\n");
    if (ds) *ds = NULL;
    return (HRESULT)0x88780078;
}
static HRESULT WINAPI p_DirectSoundEnumerateA(void *cb, void *ctx) { (void)cb; (void)ctx; return 0; }

/* DirectInput: in-process fake, state from the script */
typedef struct { void **vtbl; int kind; } fakedev_t;      /* kind 0 keyboard, 1 mouse */
static HRESULT WINAPI d_QI(void *t, REFIID r, void **o) { (void)r; *o = t; return 0; }
static ULONG WINAPI d_Ref(void *t) { (void)t; return 1; }
static HRESULT WINAPI d_ok1(void *t) { (void)t; return 0; }
static HRESULT WINAPI d_ok2(void *t, DWORD a) { (void)t; (void)a; return 0; }
static HRESULT WINAPI d_ok3(void *t, DWORD a, DWORD b) { (void)t; (void)a; (void)b; return 0; }
static HRESULT WINAPI d_ok4(void *t, DWORD a, DWORD b, DWORD c) { (void)t; (void)a; (void)b; (void)c; return 0; }
static HRESULT WINAPI d_ok5(void *t, DWORD a, DWORD b, DWORD c, DWORD d) { (void)t; (void)a; (void)b; (void)c; (void)d; return 0; }
static HRESULT WINAPI d_GetDeviceState(fakedev_t *t, DWORD n, void *buf)
{
    memset(buf, 0, n);
    if (t->kind == 0) memcpy(buf, g_keys, n < 256 ? n : 256);
    if (t->kind == 1 && g_passthrough) return (HRESULT)0x8007000C;  /* discovery: use window messages */
    if (t->kind == 1 && n >= 16) {      /* DIMOUSESTATE: lX, lY, lZ, rgbButtons[4] */
        int32_t *m = buf; m[0] = g_dm_dx; m[1] = g_dm_dy; g_dm_dx = g_dm_dy = 0;
        for (int i = 0; i < 4; i++) ((uint8_t *)buf)[12 + i] = (g_dm_buttons >> i & 1) ? 0x80 : 0;
    }
    return 0;
}
static HRESULT WINAPI d_GetDeviceData(void *t, DWORD sz, void *buf, DWORD *n, DWORD fl)
{
    (void)t; (void)sz; (void)buf; (void)fl; *n = 0; return 0;
}
static void *g_dev_vtbl[] = {
    d_QI, d_Ref, d_Ref, d_ok2 /*GetCapabilities*/, d_ok4 /*EnumObjects*/, d_ok3 /*GetProperty*/,
    d_ok3 /*SetProperty*/, d_ok1 /*Acquire*/, d_ok1 /*Unacquire*/, d_GetDeviceState, d_GetDeviceData,
    d_ok2 /*SetDataFormat*/, d_ok2 /*SetEventNotification*/, d_ok3 /*SetCooperativeLevel*/,
    d_ok4 /*GetObjectInfo*/, d_ok2 /*GetDeviceInfo*/, d_ok3 /*RunControlPanel*/, d_ok4 /*Initialize*/,
};
static fakedev_t g_kbd = {g_dev_vtbl, 0}, g_mouse = {g_dev_vtbl, 1};
static const GUID GUID_SysMouse_ = {0x6F1D2B60, 0xD5A0, 0x11CF, {0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0, 0}};
static HRESULT WINAPI di_CreateDevice(void *t, REFGUID g, void **dev, void *outer)
{
    (void)t; (void)outer;
    int mouse = !memcmp(g, &GUID_SysMouse_, sizeof(GUID));
    *dev = mouse ? (void *)&g_mouse : (void *)&g_kbd;
    logf_("DirectInput CreateDevice(%s)\n", mouse ? "mouse" : "keyboard");
    return 0;
}
static void *g_di_vtbl[] = {d_QI, d_Ref, d_Ref, di_CreateDevice, d_ok5 /*EnumDevices*/,
                            d_ok2 /*GetDeviceStatus*/, d_ok3 /*RunControlPanel*/, d_ok3 /*Initialize*/};
static struct { void **vtbl; } g_di = {g_di_vtbl};
HRESULT WINAPI p_DirectInputCreateA(HINSTANCE i, DWORD v, void **out, void *outer)
{
    (void)i; (void)outer; logf_("DirectInputCreateA(%#lx) -> fake\n", v);
    *out = &g_di; return 0;
}

/* ---------------------------------------------------------------- init */
#define IAT(slot, fn) patch_iat(slot, (void *)(fn), NULL)
static void install(void)
{
    char v[MAX_PATH];
    if (!GetEnvironmentVariableA("RCTHOOK_OUT", g_out, sizeof g_out)) strcpy(g_out, ".");
    if (GetEnvironmentVariableA("RCTHOOK_REALTIME", v, sizeof v)) g_realtime = atoi(v);
    if (GetEnvironmentVariableA("RCTHOOK_QUANTUM", v, sizeof v)) g_quantum = strtoul(v, NULL, 0);
    if (GetEnvironmentVariableA("RCTHOOK_CHUNKS", v, sizeof v)) g_chunks = atoi(v);
    if (GetEnvironmentVariableA("RCTHOOK_PASSTHROUGH", v, sizeof v)) g_passthrough = atoi(v);
    g_log = open_out("hook.log");
    g_trace = open_out("trace.bin");
    g_tbuf = VirtualAlloc(NULL, TBUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    mask_build();
    g_findpool = VirtualAlloc((void *)0x3C000000, MAX_FIND * FIND_CAP * sizeof(WIN32_FIND_DATAA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_stubs = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    logf_("rcthook: build %016llx out=%s realtime=%d quantum=%u\n", (unsigned long long)ORACLE_BUILD_ID,
          g_out, g_realtime, g_quantum);
    if (GetEnvironmentVariableA("RCTHOOK_SCRIPT", v, sizeof v)) load_script(v);
    trec(TR_HEADER, TRACE_VERSION, g_realtime | g_passthrough << 1, g_quantum);
    trec(TR_BUILD, (uint32_t)ORACLE_BUILD_ID, (uint32_t)(ORACLE_BUILD_ID >> 32), 0);
    trec(TR_NOTE, 0, 0, g_vt);   /* note 0: virtual clock at start (seed) */

    /* time */
    IAT(0x5E7330, p_timeGetTime);
    IAT(0x5E70D8, p_GetTickCount);
    IAT(0x5E7124, p_Sleep);
    IAT(0x5E71F8, p_GetSystemTime);
    IAT(0x5E72C8, p_SetTimer);
    IAT(0x5E72E4, p_KillTimer);
    IAT(0x5E72FC, p_timeSetEvent);
    IAT(0x5E7300, p_timeKillEvent);
    /* input */
    patch_iat(0x5E72DC, (void *)p_PeekMessageA, (void **)&r_PeekMessageA);
    IAT(0x5E72BC, p_RegisterClassA);
    IAT(0x5E7238, p_GetCursorPos);
    IAT(0x5E7294, p_SetCursorPos);
    IAT(0x5E7028, p_DirectInputCreateA);
    /* sound */
    IAT(0x5E703C, p_DirectSoundCreate);
    IAT(0x5E7040, p_DirectSoundEnumerateA);
    /* machine identity / resources */
    IAT(0x5E71F4, p_GetComputerNameA);
    IAT(0x5E7014, p_GetUserNameA);
    IAT(0x5E71F0, p_GlobalMemoryStatus);
    IAT(0x5E719C, p_GetDiskFreeSpaceA);
    IAT(0x5E7180, p_GetEnvironmentStrings);
    IAT(0x5E71FC, p_GetEnvironmentStringsW);
    IAT(0x5E7204, p_FreeEnvironmentStringsA);
    IAT(0x5E7208, p_FreeEnvironmentStringsW);
    /* filesystem */
    IAT(0x5E71AC, p_FindFirstFileA);
    IAT(0x5E71A8, p_FindNextFileA);
    IAT(0x5E71A4, p_FindClose);
    IAT(0x5E71C4, p_CreateFileA);
    /* modal UI: fail fast */
    IAT(0x5E72CC, p_MessageBoxA);
    IAT(0x5E729C, p_DialogBoxParamA);
    IAT(0x5E7350, p_GetOpenFileNameA);
    IAT(0x5E7354, p_GetSaveFileNameA);

    hook_at(A_RNG_STORE, 5, h_rng);
    hook_at(A_TICK, 6, h_tick);
    hook_at(A_FRAME, 7, h_frame);
    hook_at(A_FRAME_BODY, 5, h_frame_body);
    hook_at(A_DO_COMMAND, 7, h_command);
    static const uint32_t hooked[][2] = {
        {A_RNG_STORE, A_RNG_STORE + 5}, {A_TICK, A_TICK + 6}, {A_FRAME, A_FRAME + 7},
        {A_FRAME_BODY, A_FRAME_BODY + 5}, {A_DO_COMMAND, A_DO_COMMAND + 7}};
    spike_set_hook_ranges(hooked, 5);
    spike_install((uint32_t)g_stubs, (uint32_t)g_stubs + 65536);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) install();
    else if (reason == DLL_PROCESS_DETACH && !g_quitting) {
        trec(TR_END, g_frame, g_tick, g_rng_draws); tflush();
        spike_abort();
        logf_("process detach at frame %u tick %u\n", g_frame, g_tick);
    }
    return TRUE;
}
