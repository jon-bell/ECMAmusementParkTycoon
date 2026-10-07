/* API trace (RCTHOOK_SPIKE=apitrace): every call rct.exe makes to the OS, as the game sees it.
 *
 * Records, one per line, in out/<run>/apitrace.txt (format: oracle/README.md, "API trace"):
 *   C  a call through rct.exe's IAT, through a GetProcAddress result, or to a COM method, made
 *      from game code (return address inside rct.exe): arguments as passed, pointed-to inputs;
 *   R  its return: the value the game receives (after the oracle's pins) and the out-params the
 *      callee wrote, read after the call;
 *   B  an entry into game code from the OS (window procedure, dialog procedure, enumeration
 *      callbacks), nested inside the C record of the API call during which it happens;
 *   E  that callback's return.
 * Argument rendering is driven by oracle/apisig.txt, embedded at build time (apitrace_asm.S).
 *
 * Non-perturbation: thunks touch no game register, flag or stack byte that the untraced call
 * would not (apitrace_asm.S); all C code runs on a private stack; the arena is allocated at a
 * fixed high address, away from where Wine places the game's memory. The measurement of this
 * (RNG, raw and masked state identical to untraced runs) is in oracle/README.md. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spike.h"

#define GAME_LO 0x401000u
#define GAME_HI 0x9BD000u
#define ENTRY_POINT 0x412E80u

extern const char apisig_txt[];
extern uint32_t at_game_esp, at_priv_top, at_target, at_cur_id;
extern void at_pre_entry(void), at_post_entry(void);
extern void __cdecl at_call_priv(void (__cdecl *fn)(void *), void *arg);

int g_apitrace_on;

/* ------------------------------------------------------------------ arena (fixed address) */
/* Fixed addresses in a range Wine leaves free in every corpus run (0x10000000-0x3FF00000), so the
 * instrument does not move memory the game allocates later. The trace is kept in memory and
 * written at quit: opening a file earlier would shift the handle numbers the game receives. */
#define OUT_BASE    0x10000000u
#define OUT_SIZE    0x10000000u          /* 256 MiB; flushed early (opening the file) only if full */
#define ARENA_BASE  0x20000000u
#define ARENA_SIZE  0x02000000u
static uint8_t *s_arena, *s_out, *s_thunks, *s_misc;
static uint32_t s_out_len, s_misc_used;
static HANDLE s_file = INVALID_HANDLE_VALUE;
static uint32_t s_main_tid;
static uint32_t s_frame, s_tick;
static uint32_t s_other_thread, s_records, s_errors;

static void *misc_alloc(uint32_t n)
{
    n = (n + 15) & ~15u;
    if (s_misc_used + n > 0x00C00000u) return NULL;
    void *p = s_misc + s_misc_used; s_misc_used += n; return p;
}

#define LINE_MAX 0x10000
static void out_flush(void)
{
    DWORD w;
    if (s_file == INVALID_HANDLE_VALUE) {
        s_file = spike_open("apitrace.txt");
        if (s_out_len == OUT_SIZE || s_out_len + LINE_MAX > OUT_SIZE)
            spike_log("apitrace: output buffer full, file opened during the run (handle numbers may shift)\n");
    }
    if (s_out_len && s_file != INVALID_HANDLE_VALUE) WriteFile(s_file, s_out, s_out_len, &w, NULL);
    s_out_len = 0;
}

/* ------------------------------------------------------------------ line buffer */
static char s_line[0x10000]; static uint32_t s_ll;
static void lput(const char *s) { while (*s && s_ll < LINE_MAX - 64) s_line[s_ll++] = *s++; }
static void lch(char c) { if (s_ll < LINE_MAX - 64) s_line[s_ll++] = c; }
static void lhex(uint32_t v)
{
    char b[9]; int n = 0;
    do { b[n++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
    while (n) lch(b[--n]);
}
static void lhex64(uint64_t v) { for (int i = 60; i >= 0; i -= 4) lch("0123456789abcdef"[(v >> i) & 15]); }
static void ldec(uint32_t v) { char b[12]; snprintf(b, sizeof b, "%u", v); lput(b); }
static void lend(void)
{
    if (!g_apitrace_on) { s_ll = 0; return; }     /* thunks without recording (register pin only) */
    s_line[s_ll++] = '\n';
    if (s_out_len + s_ll > OUT_SIZE) out_flush();
    memcpy(s_out + s_out_len, s_line, s_ll); s_out_len += s_ll; s_ll = 0; s_records++;
}
/* an annotation line; only called between records */
static void note(const char *fmt, ...)
{
    if (!g_apitrace_on) return;
    char b[512]; va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (s_ll) return;
    lput("# "); lput(b); lend();
}

/* ------------------------------------------------------------------ memory access */
static uint32_t rq_lo, rq_hi;
static int readable(uint32_t p, uint32_t n)
{
    if (!p || p + n < p) return 0;
    if (p >= rq_lo && p + n <= rq_hi) return 1;
    uint32_t a = p, end = p + (n ? n : 1);
    while (a < end) {
        MEMORY_BASIC_INFORMATION mi;
        if (VirtualQuery((void *)a, &mi, sizeof mi) != sizeof mi) return 0;
        if (mi.State != MEM_COMMIT || (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) || !mi.Protect) return 0;
        uint32_t lo = (uint32_t)mi.BaseAddress, hi = lo + mi.RegionSize;
        if (a == p) { rq_lo = lo; rq_hi = hi; }
        a = hi;
        if (!hi) break;
    }
    return 1;
}
static uint32_t rd32(uint32_t p) { return readable(p, 4) ? *(uint32_t *)p : 0; }
static uint64_t fnv(const uint8_t *p, uint32_t n)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (uint32_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ull; }
    return h;
}

/* ------------------------------------------------------------------ signature table */
enum { B_X, B_H, B_P, B_S, B_WS, B_G, B_CB, B_STRUCT, B_IFACE, B_LPAL, B_BMI, B_MSGL, B_BUF, B_HEX,
       B_DX, B_DH, B_DP, B_DA, B_V, B_EWS, B_EAS, B_ALLOC, B_UNK, B_Q };
enum { L_NONE, L_ARG, L_DEREF, L_RET, L_CONST, L_DIB };
typedef struct { uint8_t type; uint32_t v, mul; } len_t;
typedef struct { uint8_t dir; uint8_t base; uint8_t cond; int16_t sub; len_t len; } argk_t;   /* dir: 0 in, 1 out, 2 io */
enum { C_ALWAYS, C_NZ, C_Z, C_NOTM1 };     /* when out content exists: always, ret != 0, ret == 0, ret != -1 */
enum { D_IN, D_OUT, D_IO };
#define MAXARGS 14
typedef struct { const char *name; uint8_t cdecl_, is_cb; uint8_t nargs; argk_t ret; argk_t a[MAXARGS]; } sig_t;
typedef struct { const char *name; uint32_t size; uint8_t nstr, nchr, nunused; uint16_t stroff[8], chroff[8], chrlen[8], unoff[4], unlen[4]; } struc_t;
typedef struct { const char *name; int nmeth; const char *meth[40]; } iface_t;
typedef struct { uint32_t msg; uint8_t io; int16_t kind; } msgk_t;   /* kind: struct idx, -1 string, -2 nccalc */
#define MAXSIG 512
static sig_t s_sig[MAXSIG]; static int s_nsig;
static struc_t s_struc[64]; static int s_nstruc;
static iface_t s_iface[16]; static int s_niface;
static msgk_t s_msgk[32]; static int s_nmsgk;
static const char *s_cbkind[32]; static int s_ncbkind;

static int find_struct(const char *n) { for (int i = 0; i < s_nstruc; i++) if (!strcmp(s_struc[i].name, n)) return i; return -1; }
static int find_iface(const char *n) { for (int i = 0; i < s_niface; i++) if (!strcmp(s_iface[i].name, n)) return i; return -1; }
static int find_sig(const char *n) { for (int i = 0; i < s_nsig; i++) if (!strcmp(s_sig[i].name, n)) return i; return -1; }
static const char *dupname(const char *a, const char *b);
static int cbkind(const char *n)
{
    for (int i = 0; i < s_ncbkind; i++) if (!strcmp(s_cbkind[i], n)) return i;
    if (s_ncbkind < 32) { s_cbkind[s_ncbkind] = n; return s_ncbkind++; }
    return -1;
}

static int parse_len(const char *s, len_t *l)
{
    l->mul = 1;
    if (*s == '*') { l->type = L_DEREF; l->v = strtoul(s + 1, (char **)&s, 10); }
    else if (*s == 'r') { l->type = L_RET; s++; }
    else if (*s == '=') { l->type = L_CONST; l->v = strtoul(s + 1, (char **)&s, 10); }
    else if (*s == 'd') { l->type = L_DIB; l->v = strtoul(s + 1, (char **)&s, 10); }
    else if (*s >= '0' && *s <= '9') { l->type = L_ARG; l->v = strtoul(s, (char **)&s, 10); }
    else return 0;
    if (*s == 'x') l->mul = strtoul(s + 1, NULL, 10);
    return 1;
}
static int parse_kind(const char *t, argk_t *k, int is_ret)
{
    memset(k, 0, sizeof *k);
    char tb[64]; snprintf(tb, sizeof tb, "%s", t); t = tb;
    char *q = strchr(tb, '?');
    if (q && !is_ret) {
        k->cond = !strcmp(q, "?") ? C_NZ : !strcmp(q, "?0") ? C_Z : !strcmp(q, "?-1") ? C_NOTM1 : 0xFF;
        if (k->cond == 0xFF) return 0;
        *q = 0;
    }
    if (!is_ret) {
        if (t[0] == 'i' && t[1] == 'o') { k->dir = D_IO; t += 2; }
        else if (t[0] == 'o') { k->dir = D_OUT; t++; }
    }
    const char *at = strchr(t, '@');
    if (at && !parse_len(at + 1, &k->len)) return 0;
    size_t n = at ? (size_t)(at - t) : strlen(t);
#define IS(s) (n == strlen(s) && !strncmp(t, s, n))
    if (IS("x")) k->base = B_X; else if (IS("h")) k->base = B_H; else if (IS("p")) k->base = B_P;
    else if (IS("s")) k->base = B_S; else if (IS("ws")) k->base = B_WS; else if (IS("g")) k->base = B_G;
    else if (IS("lpal")) k->base = B_LPAL; else if (IS("bmi")) k->base = B_BMI; else if (IS("msgl")) k->base = B_MSGL;
    else if (IS("b")) k->base = B_BUF; else if (IS("x") ) k->base = B_X;
    else if (IS("dx")) k->base = B_DX; else if (IS("dh")) k->base = B_DH; else if (IS("dp")) k->base = B_DP;
    else if (IS("da")) k->base = B_DA; else if (IS("v")) k->base = B_V; else if (IS("ews")) k->base = B_EWS;
    else if (IS("eas")) k->base = B_EAS; else if (IS("a")) k->base = B_ALLOC; else if (IS("q")) k->base = B_Q;
    else if (!strncmp(t, "cb:", 3)) { k->base = B_CB; k->sub = cbkind(dupname(t + 3, NULL)); }
    else if (!strncmp(t, "S:", 2)) { k->base = B_STRUCT; k->sub = find_struct(t + 2); if (k->sub < 0) return 0; }
    else if (!strncmp(t, "I:", 2)) { k->base = B_IFACE; k->sub = find_iface(t + 2); }
    else return 0;
#undef IS
    if (at && k->base == B_X) k->base = B_HEX;      /* x@L: bytes rendered as hex */
    return 1;
}
static uint32_t field_size(const char *f)
{
    if (f[0] == 'c' || f[0] == 'b' || f[0] == 'u') return strtoul(f + 1, NULL, 10);
    return strtoul(f + 1, NULL, 10);   /* x1 x2 x4 h4 p4 s4 */
}

/* tokenise a copy of apisig.txt in place; pass 0 reads struct/iface/msg, pass 1 fn/cb */
static int load_sigs_pass(int pass)
{
    size_t n = strlen(apisig_txt);
    char *txt = misc_alloc(n + 1); if (!txt) return 0;
    memcpy(txt, apisig_txt, n + 1);
    char *line = txt; int ln = 0, bad = 0;
    while (line && *line) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        ln++;
        char *hash = strchr(line, '#');
        /* '#' starts a comment only at line start or after whitespace (names contain '#') */
        if (hash && (hash == line || hash[-1] == ' ' || hash[-1] == '\t')) *hash = 0;
        char *tok[48]; int nt = 0;
        for (char *t = strtok(line, " \t\r"); t && nt < 48; t = strtok(NULL, " \t\r")) tok[nt++] = t;
        if (nt && pass == 0) {
            if (!strcmp(tok[0], "struct") && nt >= 2 && s_nstruc < 64) {
                struc_t *s = &s_struc[s_nstruc++]; memset(s, 0, sizeof *s); s->name = tok[1];
                for (int i = 2; i < nt; i++) {
                    uint32_t sz = field_size(tok[i]);
                    if (tok[i][0] == 's' && s->nstr < 8) s->stroff[s->nstr++] = (uint16_t)s->size;
                    if (tok[i][0] == 'u' && s->nunused < 4) { s->unoff[s->nunused] = (uint16_t)s->size; s->unlen[s->nunused++] = (uint16_t)sz; }
                    if (tok[i][0] == 'c' && s->nchr < 8) { s->chroff[s->nchr] = (uint16_t)s->size; s->chrlen[s->nchr++] = (uint16_t)sz; }
                    s->size += sz;
                }
            } else if (!strcmp(tok[0], "iface") && nt >= 2 && s_niface < 16) {
                iface_t *f = &s_iface[s_niface++]; f->name = tok[1]; f->nmeth = 0;
                for (int i = 2; i < nt && f->nmeth < 40; i++) f->meth[f->nmeth++] = tok[i];
            } else if (!strcmp(tok[0], "msg") && nt >= 4 && s_nmsgk < 32) {
                msgk_t *m = &s_msgk[s_nmsgk++]; m->msg = strtoul(tok[1], NULL, 0); m->io = !strcmp(tok[2], "io");
                m->kind = !strcmp(tok[3], "s") ? -1 : !strcmp(tok[3], "NCCALC") ? -2 : find_struct(tok[3]);
            }
        } else if (nt) {
            if ((!strcmp(tok[0], "fn") && nt >= 4) || (!strcmp(tok[0], "cb") && nt >= 3)) {
                int cb = tok[0][0] == 'c';
                if (s_nsig >= MAXSIG) { bad++; goto next; }
                sig_t *s = &s_sig[s_nsig]; memset(s, 0, sizeof *s);
                s->name = tok[1]; s->is_cb = cb;
                int i = 2;
                if (!cb) { s->cdecl_ = !strcmp(tok[2], "cdecl"); i = 3; }
                if (!parse_kind(tok[i], &s->ret, 1)) { spike_log("apitrace: apisig.txt:%d: bad return kind %s\n", ln, tok[i]); bad++; goto next; }
                for (i++; i < nt && s->nargs < MAXARGS; i++)
                    if (!parse_kind(tok[i], &s->a[s->nargs++], 0)) { spike_log("apitrace: apisig.txt:%d: bad kind %s\n", ln, tok[i]); bad++; goto next; }
                if (cb) cbkind(s->name);
                if (find_sig(s->name) >= 0) { spike_log("apitrace: apisig.txt:%d: duplicate %s\n", ln, s->name); bad++; goto next; }
                s_nsig++;
            }
        }
    next:
        line = nl ? nl + 1 : NULL;
    }
    return bad;
}
static int load_sigs(void)
{
    int bad = load_sigs_pass(0) + load_sigs_pass(1);
    for (int i = 0; i < s_nsig; i++) {         /* every interface named in a signature must exist */
        const sig_t *s = &s_sig[i];
        for (int j = 0; j < s->nargs; j++)
            if (s->a[j].base == B_IFACE && s->a[j].sub < 0 && strstr(s->name, "QueryInterface") == NULL) {
                spike_log("apitrace: %s: unknown interface in argument %d\n", s->name, j + 1); bad++;
            }
    }
    spike_log("apitrace: %d signatures, %d structs, %d interfaces, %d message kinds, %d errors\n",
              s_nsig, s_nstruc, s_niface, s_nmsgk, bad);
    return bad == 0;
}

/* ------------------------------------------------------------------ rendering */
static int lit_ok(int c) { return c > 0x20 && c < 0x7f && c != '"' && c != '\\' && c != '{' && c != '}' && c != ','; }
/* ANSI string at p: exactly n bytes, or up to the first NUL if n is (uint32_t)-1 or stop_nul
 * (a buffer of n bytes); at most 1024 bytes are shown, '~' after the quote marks truncation */
static void r_strn(uint32_t p, uint32_t n, int stop_nul)
{
    if (!p) { lch('0'); return; }
    if (p < 0x10000) { lch('#'); lhex(p); return; }
    lhex(p); lch('=');
    int nul = n == 0xFFFFFFFFu || stop_nul; if (n == 0xFFFFFFFFu) n = 1024;
    uint32_t cap = n > 1024 ? 1024 : n;
    lch('"');
    uint32_t i = 0;
    for (; i < cap; i++) {
        if (((p + i) & 0xFFF) == 0 || i == 0) if (!readable(p + i, 1)) { lput("\"!"); return; }
        uint8_t c = *(uint8_t *)(p + i);
        if (nul && !c) break;
        if (lit_ok(c)) lch((char)c); else { lput("\\x"); lch("0123456789abcdef"[c >> 4]); lch("0123456789abcdef"[c & 15]); }
    }
    lch('"');
    if (i == cap && n > cap) lch('~');
}
static void r_str(uint32_t p, uint32_t n) { r_strn(p, n, 0); }
static void r_wstrn(uint32_t p, uint32_t n, int stop_nul)
{
    if (!p) { lch('0'); return; }
    lhex(p); lput("=L\"");
    int nul = n == 0xFFFFFFFFu || stop_nul; if (n == 0xFFFFFFFFu) n = 1024;
    uint32_t cap = n > 1024 ? 1024 : n;
    uint32_t i = 0;
    for (; i < cap; i++) {
        uint32_t a = p + 2 * i;
        if ((a & 0xFFF) == 0 || (a & 0xFFF) == 0xFFF || i == 0) if (!readable(a, 2)) { lput("\"!"); return; }
        uint16_t c = *(uint16_t *)a;
        if (nul && !c) break;
        if (c < 0x80 && lit_ok(c)) lch((char)c);
        else { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); lput(b); }
    }
    lch('"');
    if (i == cap && n > cap) lch('~');
}
static void r_hexbytes(uint32_t p, uint32_t n)
{
    lch('{');
    if (readable(p, n)) for (uint32_t i = 0; i < n; i++) { uint8_t c = *(uint8_t *)(p + i); lch("0123456789abcdef"[c >> 4]); lch("0123456789abcdef"[c & 15]); }
    else lch('!');
    lch('}');
}
static void r_buf(uint32_t p, uint32_t n)
{
    if (!p) { lch('0'); return; }
    lhex(p); lch('=');
    if (n > 0x4000000u) { lch('?'); return; }
    if (!readable(p, n)) { lch('!'); return; }
    ldec(n); lch(':'); lhex64(fnv((const uint8_t *)p, n));
}
static void r_struct(uint32_t p, int si)
{
    if (!p) { lch('0'); return; }
    if (si < 0) { lhex(p); return; }
    const struc_t *s = &s_struc[si];
    lhex(p); lch('=');
    if (!readable(p, s->size)) { lput("{!}"); return; }
    /* char[N] fields: bytes after the first NUL are not part of the string; shown as ".." */
    lch('{');
    for (uint32_t i = 0; i < s->size; i++) {
        int dead = 0;
        for (int f = 0; f < s->nchr; f++)
            if (i > s->chroff[f] && i < (uint32_t)s->chroff[f] + s->chrlen[f] &&
                memchr((void *)(p + s->chroff[f]), 0, i - s->chroff[f])) dead = 1;
        for (int f = 0; f < s->nunused; f++) if (i >= s->unoff[f] && i < (uint32_t)s->unoff[f] + s->unlen[f]) dead = 1;
        uint8_t c = *(uint8_t *)(p + i);
        if (dead) lput(".."); else { lch("0123456789abcdef"[c >> 4]); lch("0123456789abcdef"[c & 15]); }
    }
    lch('}');
    for (int i = 0; i < s->nstr; i++) { lch(','); r_str(*(uint32_t *)(p + s->stroff[i]), 0xFFFFFFFFu); }
}
static void r_guid(uint32_t p)
{
    if (!p) { lch('0'); return; }
    lhex(p); lch('=');
    if (!readable(p, 16)) { lch('!'); return; }
    const GUID *g = (const GUID *)p; char b[48];
    snprintf(b, sizeof b, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", (unsigned long)g->Data1, g->Data2, g->Data3,
             g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    lput(b);
}
/* BITMAPINFO: header (40 bytes) as hex, then the colour table as len:hash */
static uint32_t bmi_colors_len(uint32_t p, uint32_t usage)
{
    if (!readable(p, 40)) return 0;
    const BITMAPINFOHEADER *h = (const BITMAPINFOHEADER *)p;
    uint32_t n = h->biClrUsed ? h->biClrUsed : (h->biBitCount <= 8 ? 1u << h->biBitCount : 0);
    if (h->biCompression == BI_BITFIELDS) return 12;
    return n * (usage == DIB_PAL_COLORS ? 2 : 4);
}
static uint32_t dib_size(uint32_t p)
{
    if (!readable(p, 40)) return 0;
    const BITMAPINFOHEADER *h = (const BITMAPINFOHEADER *)p;
    int32_t ht = h->biHeight < 0 ? -h->biHeight : h->biHeight;
    return (uint32_t)ht * ((((uint32_t)h->biWidth * h->biBitCount) + 31) / 32 * 4);
}
static void r_bmi(uint32_t p, uint32_t usage)
{
    if (!p) { lch('0'); return; }
    lhex(p); lch('='); r_hexbytes(p, 40);
    uint32_t n = bmi_colors_len(p, usage);
    lch(',');
    if (!readable(p + 40, n)) { lch('!'); return; }
    ldec(n); lch(':'); lhex64(fnv((const uint8_t *)(p + 40), n));
}
static void r_lpal(uint32_t p)
{
    if (!p) { lch('0'); return; }
    lhex(p); lch('=');
    if (!readable(p, 4)) { lch('!'); return; }
    r_hexbytes(p, 4 + 4u * *(uint16_t *)(p + 2));
}

typedef struct { const uint32_t *args; uint32_t ret; } ctx_t;
static uint32_t eval_len(const len_t *l, const ctx_t *c, int *ok)
{
    uint32_t v = 0; *ok = 1;
    switch (l->type) {
    case L_ARG: v = l->v >= 1 && l->v <= MAXARGS ? c->args[l->v - 1] : 0; break;
    case L_DEREF: { uint32_t p = l->v >= 1 && l->v <= MAXARGS ? c->args[l->v - 1] : 0; if (!p || !readable(p, 4)) { *ok = 0; return 0; } v = *(uint32_t *)p; break; }
    case L_RET: v = c->ret; break;
    case L_CONST: v = l->v; break;
    case L_DIB: v = dib_size(l->v >= 1 && l->v <= MAXARGS ? c->args[l->v - 1] : 0); break;
    default: *ok = 0; return 0;
    }
    if (v == 0xFFFFFFFFu) return v;
    return v * l->mul;
}
static void r_msgl(uint32_t msg, uint32_t wp, uint32_t lp, int after)
{
    for (int i = 0; i < s_nmsgk; i++) {
        if (s_msgk[i].msg != msg) continue;
        if (after && !s_msgk[i].io) break;
        if (s_msgk[i].kind == -1) { r_str(lp, 0xFFFFFFFFu); return; }
        if (s_msgk[i].kind == -2) { r_struct(lp, find_struct(wp ? "NCCALCSIZE_PARAMS" : "RECT")); return; }
        r_struct(lp, s_msgk[i].kind); return;
    }
    lhex(lp);
}

/* one argument; phase 0 = call (C/B), 1 = return (R/E) */
static void r_arg(const argk_t *k, int i, const ctx_t *c, int phase)
{
    uint32_t v = c->args[i];
    if (phase == 0 && k->dir == D_OUT) { lhex(v); return; }     /* out-only: the pointer */
    if (phase == 1 && v && ((k->cond == C_NZ && !c->ret) || (k->cond == C_Z && c->ret) ||
                            (k->cond == C_NOTM1 && c->ret == 0xFFFFFFFFu))) { lhex(v); lput("=-"); return; }
    int ok; uint32_t n;
    switch (k->base) {
    case B_X: case B_H: case B_P: case B_CB: lhex(v); break;
    case B_S: n = k->len.type ? eval_len(&k->len, c, &ok) : 0xFFFFFFFFu; r_strn(v, n, k->dir != D_IN); break;
    case B_WS: n = k->len.type ? eval_len(&k->len, c, &ok) : 0xFFFFFFFFu; r_wstrn(v, n, k->dir != D_IN); break;
    case B_G: r_guid(v); break;
    case B_STRUCT: r_struct(v, k->sub); break;
    case B_LPAL: r_lpal(v); break;
    case B_BMI: r_bmi(v, k->len.v >= 1 ? c->args[k->len.v - 1] : 0); break;
    case B_MSGL: r_msgl(c->args[1], c->args[2], v, phase); break;
    case B_BUF: n = eval_len(&k->len, c, &ok); if (!ok || n == 0xFFFFFFFFu) { if (v) { lhex(v); lput("=?"); } else lch('0'); } else r_buf(v, n); break;
    case B_HEX: n = eval_len(&k->len, c, &ok); if (!v) lch('0'); else if (!ok || n > 4096) { lhex(v); lput("=?"); } else { lhex(v); lch('='); r_hexbytes(v, n); } break;
    case B_DX: case B_DH: case B_DP: case B_IFACE:
        if (!v) { lch('0'); break; }
        lhex(v); lch('='); if (readable(v, 4)) lhex(*(uint32_t *)v); else lch('!'); break;
    case B_DA:
        if (!v) { lch('0'); break; }
        lhex(v); lch('='); if (readable(v, 4)) lhex(*(uint32_t *)v); else lch('!');
        n = eval_len(&k->len, c, &ok); lch(':'); ldec(n); break;
    default: lhex(v); break;
    }
}
static void r_ret(const argk_t *k, const ctx_t *c)
{
    int ok; uint32_t v = c->ret;
    switch (k->base) {
    case B_V: lch('-'); break;
    case B_S: r_str(v, 0xFFFFFFFFu); break;
    case B_ALLOC: lhex(v); lch(':'); ldec(eval_len(&k->len, c, &ok)); break;
    case B_EAS: case B_EWS: {
        if (!v) { lch('0'); break; }
        uint32_t w = k->base == B_EWS ? 2 : 1, n = 0;
        while (n < 0x100000 && readable(v + n, 2 * w)) {
            if (w == 2 ? !*(uint16_t *)(v + n) && !*(uint16_t *)(v + n + 2) : !*(uint8_t *)(v + n) && !*(uint8_t *)(v + n + 1)) { n += 2 * w; break; }
            n += w;
        }
        r_buf(v, n); break;
    }
    default: lhex(v); break;
    }
}

/* ------------------------------------------------------------------ targets and thunks */
typedef struct { int sig; void *orig; const char *name; uint32_t calls, slot; uint8_t warned, retvoid, retq; } target_t;
#define MAXTGT 4096
static target_t s_tgt[MAXTGT]; static int s_ntgt;
static uint8_t *thunk_for(int id) { return s_thunks + 16 * id; }
static void *new_target(const char *name, void *orig)
{
    if (s_ntgt >= MAXTGT) return orig;
    int id = s_ntgt++;
    target_t *t = &s_tgt[id]; t->name = name; t->orig = orig; t->sig = find_sig(name);
    if (t->sig < 0) spike_log("apitrace: no signature for %s\n", name);
    t->retvoid = t->sig >= 0 && s_sig[t->sig].ret.base == B_V;
    t->retq = t->sig >= 0 && s_sig[t->sig].ret.base == B_Q;
    uint8_t *p = thunk_for(id);
    p[0] = 0xC7; p[1] = 0x05; *(uint32_t *)(p + 2) = (uint32_t)&at_cur_id; *(uint32_t *)(p + 6) = id;
    p[10] = 0xE9; *(int32_t *)(p + 11) = (int32_t)((uint32_t)at_pre_entry - ((uint32_t)p + 15));
    return p;
}
static const char *dupname(const char *a, const char *b)
{
    size_t n = strlen(a) + (b ? strlen(b) + 2 : 0) + 1;
    char *s = misc_alloc(n); if (!s) return "?";
    if (b) snprintf(s, n, "%s::%s", a, b); else snprintf(s, n, "%s", a);
    return s;
}

/* COM: patch a vtable (shared by all objects of the class) once */
static void *s_vt_done[64]; static int s_nvt;
static void patch_vtable(uint32_t obj, int iface)
{
    if (iface < 0 || !readable(obj, 4)) return;
    void **vt = *(void ***)obj;
    for (int i = 0; i < s_nvt; i++) if (s_vt_done[i] == vt) return;
    if (s_nvt >= 64) return;
    s_vt_done[s_nvt++] = vt;
    const iface_t *f = &s_iface[iface];
    DWORD old; VirtualProtect(vt, 4 * f->nmeth, PAGE_READWRITE, &old);
    for (int i = 0; i < f->nmeth; i++) vt[i] = new_target(dupname(f->name, f->meth[i]), vt[i]);
    VirtualProtect(vt, 4 * f->nmeth, old, &old);
    spike_log("apitrace: patched %s vtable %p (%d methods)\n", f->name, vt, f->nmeth);
}

static struct { uint32_t ptr; int iface; } s_obj[64]; static int s_nobj;   /* COM objects handed to the game */

/* osmap.txt: the OS-chosen values the game holds, for comparing register captures: every
 * function value it sees (IAT slot contents, GetProcAddress results, COM methods) and every COM
 * object pointer it was given. Format (oracle/README.md "Register capture"):
 *   fn <value> <slot or 0> <name>      obj <pointer> <interface> */
void apitrace_osmap(void)
{
    HANDLE f = spike_open("osmap.txt"); DWORD w; char ln[200];
    int n = snprintf(ln, sizeof ln, "# osmap 1\n"); WriteFile(f, ln, n, &w, NULL);
    for (int i = 0; i < s_ntgt; i++) {
        n = snprintf(ln, sizeof ln, "fn %x %x %s\n", (uint32_t)thunk_for(i), s_tgt[i].slot, s_tgt[i].name);
        WriteFile(f, ln, n, &w, NULL);
    }
    for (int i = 0; i < s_nobj; i++) {
        n = snprintf(ln, sizeof ln, "obj %x %s\n", s_obj[i].ptr, s_obj[i].iface >= 0 ? s_iface[s_obj[i].iface].name : "?");
        WriteFile(f, ln, n, &w, NULL);
    }
    CloseHandle(f);
}

/* ------------------------------------------------------------------ shadow stack */
typedef struct {
    int tgt;                 /* target id, or -1 - cb sig for a callback */
    int sig;
    uint32_t ret, esp;
    uint32_t args[MAXARGS];
    int8_t subst_idx; uint32_t subst_val;
} shadow_t;
#define MAXDEPTH 256
static shadow_t s_sh[MAXDEPTH]; static int s_depth;

/* ------------------------------------------------------------------ callbacks into game code */
static void cb_enter(int sig, uint32_t target, uint32_t esp, const uint32_t *args, int n)
{
    if (s_depth >= MAXDEPTH) return;
    shadow_t *e = &s_sh[s_depth];
    memset(e, 0, sizeof *e); e->tgt = -1; e->sig = sig; e->esp = esp; e->ret = target; e->subst_idx = -1;
    for (int i = 0; i < n && i < MAXARGS; i++) e->args[i] = args[i];
    const sig_t *s = sig >= 0 ? &s_sig[sig] : NULL;
    lch('B'); lch(' '); lhex(s_frame); lch(' '); lhex(s_tick); lch(' '); lhex(s_depth); lch(' ');
    lput(s ? s->name : "?"); lch(' '); lhex(target); lch(' '); lhex(esp);
    ctx_t c = {e->args, 0};
    if (s) for (int i = 0; i < s->nargs; i++) { lch(' '); r_arg(&s->a[i], i, &c, 0); }
    lend();
    s_depth++;
}
static void cb_leave(uint32_t ret)
{
    if (s_depth <= 0) return;
    s_depth--;
    shadow_t *e = &s_sh[s_depth];
    const sig_t *s = e->sig >= 0 ? &s_sig[e->sig] : NULL;
    lch('E'); lch(' '); lhex(s_depth); lch(' '); lput(s ? s->name : "?"); lch(' ');
    ctx_t c = {e->args, ret};
    if (s) r_ret(&s->ret, &c); else lhex(ret);
    if (s) for (int i = 0; i < s->nargs; i++)
        if (s->a[i].dir != D_IN || (s->a[i].base == B_MSGL)) {
            if (s->a[i].base == B_MSGL) {
                int io = 0;
                for (int j = 0; j < s_nmsgk; j++) if (s_msgk[j].msg == e->args[1] && s_msgk[j].io) io = 1;
                if (!io) continue;
            }
            lch(' '); r_arg(&s->a[i], i, &c, 1);
        }
    lend();
}
typedef struct { int sig; uint32_t target, esp, ret; uint32_t a[MAXARGS]; int n; } cbreq_t;
static void __cdecl cb_enter_priv(void *p) { cbreq_t *r = p; cb_enter(r->sig, r->target, r->esp, r->a, r->n); }
static void __cdecl cb_leave_priv(void *p) { cbreq_t *r = p; cb_leave(r->ret); }
static int s_sig_wndproc = -1, s_sig_dlgproc = -1, s_sig_enummodes = -1, s_sig_enumsurf = -1, s_sig_ddenum = -1, s_sig_dsenum = -1;

static int main_thread(void) { return GetCurrentThreadId() == s_main_tid; }

/* called by rcthook.c's window procedure filter around the game's window procedure */
void apitrace_wndproc_enter(uint32_t target, uint32_t h, uint32_t m, uint32_t w, uint32_t l)
{
    if (!g_apitrace_on || !main_thread()) return;
    cbreq_t r = {s_sig_wndproc, target, (uint32_t)__builtin_frame_address(0), 0, {h, m, w, l}, 4};
    at_call_priv(cb_enter_priv, &r);
}
void apitrace_wndproc_leave(uint32_t ret)
{
    if (!g_apitrace_on || !main_thread()) return;
    cbreq_t r; r.ret = ret;
    at_call_priv(cb_leave_priv, &r);
}
typedef struct { uint32_t m, w, l; } dropreq_t;
static void __cdecl drop_priv(void *p)
{
    dropreq_t *d = p;
    lput("# drop "); lhex(s_frame); lch(' '); lhex(s_tick); lch(' '); lhex(s_depth); lput(" msg="); lhex(d->m);
    lput(" w="); lhex(d->w); lput(" l="); lhex(d->l); lend();
}
void apitrace_wndproc_drop(uint32_t m, uint32_t w, uint32_t l)
{
    if (!g_apitrace_on || !main_thread()) return;
    dropreq_t d = {m, w, l}; at_call_priv(drop_priv, &d);
}

/* trampolines substituted for the game's callback pointers */
#define MAXCB 16
static struct { uint32_t hwnd, proc; } s_dlg[MAXCB]; static int s_ndlg; static uint32_t s_dlg_pending;
static uint32_t s_cb_orig[8]; static int s_ncb;     /* enumeration callbacks in progress (nested) */
static INT_PTR CALLBACK tr_dlgproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    uint32_t proc = s_dlg_pending;
    for (int i = 0; i < s_ndlg; i++) if (s_dlg[i].hwnd == (uint32_t)h) proc = s_dlg[i].proc;
    if (!proc) return FALSE;
    cbreq_t r = {s_sig_dlgproc, proc, (uint32_t)__builtin_frame_address(0), 0, {(uint32_t)h, m, w, l}, 4};
    int on = g_apitrace_on && main_thread();
    if (on) at_call_priv(cb_enter_priv, &r);
    INT_PTR ret = ((DLGPROC)proc)(h, m, w, l);
    r.ret = ret;
    if (on) at_call_priv(cb_leave_priv, &r);
    return ret;
}
static HRESULT WINAPI tr_enummodes(void *desc, void *ctx)
{
    uint32_t proc = s_ncb ? s_cb_orig[s_ncb - 1] : 0;
    cbreq_t r = {s_sig_enummodes, proc, (uint32_t)__builtin_frame_address(0), 0, {(uint32_t)desc, (uint32_t)ctx}, 2};
    at_call_priv(cb_enter_priv, &r);
    HRESULT ret = ((HRESULT (WINAPI *)(void *, void *))proc)(desc, ctx);
    r.ret = ret; at_call_priv(cb_leave_priv, &r);
    return ret;
}
static HRESULT WINAPI tr_enumsurf(void *surf, void *desc, void *ctx)
{
    uint32_t proc = s_ncb ? s_cb_orig[s_ncb - 1] : 0;
    cbreq_t r = {s_sig_enumsurf, proc, (uint32_t)__builtin_frame_address(0), 0, {(uint32_t)surf, (uint32_t)desc, (uint32_t)ctx}, 3};
    at_call_priv(cb_enter_priv, &r);
    HRESULT ret = ((HRESULT (WINAPI *)(void *, void *, void *))proc)(surf, desc, ctx);
    r.ret = ret; at_call_priv(cb_leave_priv, &r);
    return ret;
}
static BOOL WINAPI tr_strenum(int sig, void *guid, void *desc, void *name, void *ctx)
{
    uint32_t proc = s_ncb ? s_cb_orig[s_ncb - 1] : 0;
    cbreq_t r = {sig, proc, (uint32_t)__builtin_frame_address(0), 0, {(uint32_t)guid, (uint32_t)desc, (uint32_t)name, (uint32_t)ctx}, 4};
    at_call_priv(cb_enter_priv, &r);
    BOOL ret = ((BOOL (WINAPI *)(void *, void *, void *, void *))proc)(guid, desc, name, ctx);
    r.ret = ret; at_call_priv(cb_leave_priv, &r);
    return ret;
}
static BOOL WINAPI tr_ddenum(void *g, void *d, void *n, void *c) { return tr_strenum(s_sig_ddenum, g, d, n, c); }
static BOOL WINAPI tr_dsenum(void *g, void *d, void *n, void *c) { return tr_strenum(s_sig_dsenum, g, d, n, c); }
static uint32_t trampoline_for(int cbk)
{
    const char *k = cbk >= 0 ? s_cbkind[cbk] : "";
    if (!strcmp(k, "dlgproc")) return (uint32_t)tr_dlgproc;
    if (!strcmp(k, "enummodes")) return (uint32_t)tr_enummodes;
    if (!strcmp(k, "enumsurf")) return (uint32_t)tr_enumsurf;
    if (!strcmp(k, "ddenum")) return (uint32_t)tr_ddenum;
    if (!strcmp(k, "dsenum")) return (uint32_t)tr_dsenum;
    return 0;
}

/* ------------------------------------------------------------------ perturbation experiments */
/* RCTHOOK_PERTURB="<name>[#K]:<what>^<mask>[;...]" changes what the game receives, to measure whether
 * an OS answer reaches game state (compare the run's trace.bin with a clean run). <what> is "ret"
 * (the return value) or "outN@OFF" (the dword at offset OFF of the memory argument N points to,
 * after the call). #K: only the K-th call (1-based), else every call. Measurement only. */
typedef struct { char name[64]; uint32_t nth, mask, off; int arg; uint32_t applied; } perturb_t;
static perturb_t s_pt[16]; static int s_npt;
static void perturb_parse(void)
{
    char v[512];
    if (!GetEnvironmentVariableA("RCTHOOK_PERTURB", v, sizeof v)) return;
    for (char *t = strtok(v, ";"); t && s_npt < 16; t = strtok(NULL, ";")) {
        perturb_t *p = &s_pt[s_npt]; memset(p, 0, sizeof *p);
        char *colon = strchr(t, ':'), *x = strchr(t, '^');
        if (!colon || !x) { spike_log("apitrace: bad RCTHOOK_PERTURB item %s\n", t); continue; }
        *colon = 0; *x = 0;
        char *hash = strchr(t, '#'); if (hash && hash != t) { *hash = 0; p->nth = strtoul(hash + 1, NULL, 0); }
        snprintf(p->name, sizeof p->name, "%s", t);
        if (!strcmp(colon + 1, "ret")) p->arg = 0;
        else if (!strncmp(colon + 1, "out", 3)) { char *e; p->arg = strtoul(colon + 4, &e, 0); p->off = *e == '@' ? strtoul(e + 1, NULL, 0) : 0; }
        else { spike_log("apitrace: bad RCTHOOK_PERTURB target %s\n", colon + 1); continue; }
        p->mask = strtoul(x + 1, NULL, 0);
        spike_log("apitrace: PERTURB %s call %u %s%d@%u ^ %#x\n", p->name, p->nth, p->arg ? "out" : "ret", p->arg, p->off, p->mask);
        s_npt++;
    }
}
static void perturb_apply(const target_t *t, const uint32_t *args, uint32_t *eax)
{
    for (int i = 0; i < s_npt; i++) {
        perturb_t *p = &s_pt[i];
        if (strcmp(p->name, t->name) || (p->nth && p->nth != t->calls)) continue;
        if (!p->arg) *eax ^= p->mask;
        else if (p->arg <= MAXARGS && readable(args[p->arg - 1] + p->off, 4)) *(uint32_t *)(args[p->arg - 1] + p->off) ^= p->mask;
        else continue;
        if (p->applied++ < 20) note("perturbed %s call %u", t->name, t->calls);
    }
}

/* ------------------------------------------------------------------ pre / post */
static uint32_t s_gpa_tgt = 0xFFFFFFFF;

uint32_t __cdecl at_pre(uint32_t id, uint32_t esp, uint32_t *regs)
{
    (void)regs;
    target_t *t = &s_tgt[id];
    uint32_t ret = *(uint32_t *)esp;
    if (ret < GAME_LO || ret >= GAME_HI) return (uint32_t)t->orig;   /* not called by the game */
    if (!main_thread()) { s_other_thread++; return (uint32_t)t->orig; }
    if (s_depth >= MAXDEPTH) { s_errors++; return (uint32_t)t->orig; }
    rq_lo = rq_hi = 0;
    while (s_depth > 0 && s_sh[s_depth - 1].esp <= esp) {     /* frames abandoned without returning */
        s_depth--; note("abandoned %s at depth %d", s_sh[s_depth].tgt >= 0 ? s_tgt[s_sh[s_depth].tgt].name : "callback", s_depth);
    }
    t->calls++;
    const sig_t *s = t->sig >= 0 ? &s_sig[t->sig] : NULL;
    shadow_t *e = &s_sh[s_depth];
    e->tgt = id; e->sig = t->sig; e->ret = ret; e->esp = esp; e->subst_idx = -1;
    for (int i = 0; i < MAXARGS; i++) e->args[i] = *(uint32_t *)(esp + 4 + 4 * i);   /* the caller's stack */
    if (!g_apitrace_on) goto armed;
    lput("C "); lhex(s_frame); lch(' '); lhex(s_tick); lch(' '); lhex(s_depth); lch(' '); lhex(ret); lch(' ');
    lhex(esp); lch(' '); lput(t->name);
    ctx_t c = {e->args, 0};
    if (s) for (int i = 0; i < s->nargs; i++) { lch(' '); r_arg(&s->a[i], i, &c, 0); }
    else lput(" ?");
    lend();
    /* callback arguments: substitute a recording trampoline (restored after the call) */
    if (s) for (int i = 0; i < s->nargs; i++) {
        if (s->a[i].base != B_CB || !e->args[i]) continue;
        uint32_t tr = trampoline_for(s->a[i].sub);
        if (!tr) { note("callback %s of %s not traced", s_cbkind[s->a[i].sub], t->name); continue; }
        if (tr == (uint32_t)tr_dlgproc) s_dlg_pending = e->args[i];
        else if (s_ncb < 8) s_cb_orig[s_ncb++] = e->args[i];
        e->subst_idx = (int8_t)i; e->subst_val = e->args[i];
        *(uint32_t *)(esp + 4 + 4 * i) = tr;
        break;
    }
armed:
    s_depth++;
    *(uint32_t *)esp = (uint32_t)at_post_entry;
    return (uint32_t)t->orig;
}

uint32_t __cdecl at_post(uint32_t esp, uint32_t *regs)
{
    rq_lo = rq_hi = 0;
    /* the innermost API frame (callbacks never return through here) */
    int d = s_depth - 1;
    while (d >= 0 && (s_sh[d].tgt < 0 || s_sh[d].esp >= esp)) d--;
    if (d < 0) { s_errors++; spike_log("apitrace: FATAL: return with no open call (esp %#x)\n", esp); TerminateProcess(GetCurrentProcess(), 5); }
    if (d != s_depth - 1) note("unwound %d frames at return", s_depth - 1 - d);
    s_depth = d;
    shadow_t *e = &s_sh[d];
    target_t *t = &s_tgt[e->tgt];
    const sig_t *s = e->sig >= 0 ? &s_sig[e->sig] : NULL;
    uint32_t popped = (esp - e->esp - 4) / 4;
    if (g_apitrace_on && s && !t->warned && popped != (s->cdecl_ ? 0u : s->nargs)) {
        t->warned = 1; s_errors++;
        note("warn %s: signature has %d args, callee popped %u", t->name, s->nargs, popped);
        spike_log("apitrace: %s: signature has %d args, callee popped %u\n", t->name, s->nargs, popped);
    }
    uint32_t eax = regs[7];
    if (s_npt) { perturb_apply(t, e->args, &eax); regs[7] = eax; }
    /* procedures resolved by the game get a traced thunk */
    if (e->tgt == (int)s_gpa_tgt && eax) {
        uint32_t nm = e->args[1];
        char tmp[80];
        if (nm >= 0x10000 && readable(nm, 1)) snprintf(tmp, sizeof tmp, "%s", (const char *)nm);
        else snprintf(tmp, sizeof tmp, "#%u", nm & 0xFFFF);
        int k = 0;
        while (k < s_ntgt && !(s_tgt[k].orig == (void *)eax && !strcmp(s_tgt[k].name, tmp))) k++;
        eax = regs[7] = k < s_ntgt ? (uint32_t)thunk_for(k) : (uint32_t)new_target(dupname(tmp, NULL), (void *)eax);
    }
    if (e->subst_idx >= 0) {
        *(uint32_t *)(e->esp + 4 + 4 * e->subst_idx) = e->subst_val;
        if (e->subst_val == s_dlg_pending && s && !strcmp(s_cbkind[s->a[e->subst_idx].sub], "dlgproc")) {
            if (eax && s_ndlg < MAXCB) { s_dlg[s_ndlg].hwnd = eax; s_dlg[s_ndlg].proc = e->subst_val; s_ndlg++; }
        } else if (s_ncb) s_ncb--;
    }
    if (!g_apitrace_on) goto done;
    lput("R "); lhex(d); lch(' '); lput(t->name); lch(' ');
    ctx_t c = {e->args, eax};
    if (s) {
        r_ret(&s->ret, &c);
        for (int i = 0; i < s->nargs; i++)
            if (s->a[i].dir != D_IN) { lch(' '); r_arg(&s->a[i], i, &c, 1); }
    } else { lhex(eax); lput(" nargs="); ldec(popped); }
    lend();
done:
    if (s) for (int i = 0; i < s->nargs; i++)          /* interfaces handed to the game */
        if (s->a[i].base == B_IFACE && e->args[i] && readable(e->args[i], 4) && !eax) {
            uint32_t obj = *(uint32_t *)e->args[i];
            patch_vtable(obj, s->a[i].sub);
            if (s_nobj < 64) { s_obj[s_nobj].ptr = obj; s_obj[s_nobj].iface = s->a[i].sub; s_nobj++; }
        }
    /* PIN: registers the callee leaves undefined are given fixed values, so the game never sees
     * what Wine's or this DLL's code left there: ecx = edx = 0 (edx kept for edx:eax returns),
     * eax = 0 for functions returning nothing, eflags = 0x202 (TF kept for the stepping instrument) */
    regs[6] = 0;
    if (!t->retq) regs[5] = 0;
    if (t->retvoid) regs[7] = 0;
    regs[8] = 0x202 | (regs[8] & 0x100);
    *(uint32_t *)e->esp = e->ret;      /* the stale return-address slot, as an untraced call leaves it */
    return e->ret;
}

/* ------------------------------------------------------------------ process entry */
static uint8_t s_entry_orig; static int s_entry_armed;
static LONG CALLBACK entry_veh(EXCEPTION_POINTERS *x)
{
    CONTEXT *c = x->ContextRecord;
    if (!s_entry_armed || x->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT ||
        (c->Eip != ENTRY_POINT && c->Eip != ENTRY_POINT + 1)) return EXCEPTION_CONTINUE_SEARCH;
    DWORD old; VirtualProtect((void *)ENTRY_POINT, 1, PAGE_EXECUTE_READWRITE, &old);
    *(uint8_t *)ENTRY_POINT = s_entry_orig;
    VirtualProtect((void *)ENTRY_POINT, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)ENTRY_POINT, 1);
    s_entry_armed = 0; c->Eip = ENTRY_POINT;
    uint32_t sp = c->Esp;
    lput("B 0 0 0 entry "); lhex(ENTRY_POINT); lch(' '); lhex(sp);
    uint32_t r[] = {c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->EFlags & ~0x100u,
                    rd32(sp), rd32(sp + 4), rd32(sp + 8), rd32(sp + 12)};
    for (int i = 0; i < 12; i++) { lch(' '); lhex(r[i]); }
    lend();
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ------------------------------------------------------------------ install */
void apitrace_time(uint32_t frame, uint32_t tick) { s_frame = frame; s_tick = tick; }
/* the game's return address of the innermost traced call, for pins that log their caller */
uint32_t apitrace_game_ret(uint32_t ret)
{
    if (ret != (uint32_t)at_post_entry) return ret;
    for (int d = s_depth - 1; d >= 0; d--) if (s_sh[d].tgt >= 0) return s_sh[d].ret;
    return ret;
}
void apitrace_quit(void)
{
    if (!g_apitrace_on) return;
    static int done; if (done) return; done = 1;
    lput("# end records="); ldec(s_records); lput(" errors="); ldec(s_errors); lput(" other_thread_calls="); ldec(s_other_thread);
    lput(" open="); ldec(s_depth); lend();
    out_flush();
    CloseHandle(s_file);
    spike_log("apitrace: %u records, %u errors, %u calls from other threads, %d targets\n",
              s_records, s_errors, s_other_thread, s_ntgt);
    for (int i = 0; i < s_npt; i++) spike_log("apitrace: PERTURB %s applied %u times\n", s_pt[i].name, s_pt[i].applied);
    /* per-target call counts, for cross-checking against apicount */
    HANDLE f = spike_open("apitrace_counts.txt"); DWORD w; char ln[160];
    for (int i = 0; i < s_ntgt; i++) {
        int n = snprintf(ln, sizeof ln, "%10u %s%s\n", s_tgt[i].calls, s_tgt[i].name, s_tgt[i].sig < 0 ? " (no signature)" : "");
        WriteFile(f, ln, n, &w, NULL);
    }
    CloseHandle(f);
}

/* trace = 0: thunks for the register pin only (every run); 1: also record (apitrace) */
int apitrace_install(int trace)
{
    s_main_tid = GetCurrentThreadId();
    s_arena = VirtualAlloc((void *)ARENA_BASE, ARENA_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (trace) s_out = VirtualAlloc((void *)OUT_BASE, OUT_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!s_arena || (trace && !s_out)) {
        spike_log("apitrace: arena not available at %#x/%#x; refusing (a moved arena could shift game memory)\n", ARENA_BASE, OUT_BASE);
        return 0;
    }
    s_thunks = s_arena; s_misc = s_thunks + 0x100000;
    at_priv_top = (uint32_t)(s_misc + 0x00C00000u + 0x00400000u - 64);   /* 4 MiB private stack */
    if (!load_sigs()) { spike_log("apitrace: FATAL: apisig.txt has errors\n"); return 0; }
    g_apitrace_on = trace;
    if (trace) perturb_parse();
    s_sig_wndproc = find_sig("wndproc"); s_sig_dlgproc = find_sig("dlgproc"); s_sig_enummodes = find_sig("enummodes");
    s_sig_enumsurf = find_sig("enumsurf"); s_sig_ddenum = find_sig("ddenum"); s_sig_dsenum = find_sig("dsenum");
    lput("# apitrace 1"); lend();

    uint8_t *base = (uint8_t *)0x400000;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR *imp = (void *)(base + dd.VirtualAddress); imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        IMAGE_THUNK_DATA *names = (void *)(base + imp->OriginalFirstThunk);
        void **slots = (void **)(base + imp->FirstThunk);
        for (int i = 0; names[i].u1.AddressOfData; i++) {
            const char *nm;
            if (names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                char b[64]; snprintf(b, sizeof b, "%s#%lu", dll, (unsigned long)(names[i].u1.Ordinal & 0xFFFF));
                nm = dupname(b, NULL);
            } else nm = ((IMAGE_IMPORT_BY_NAME *)(base + names[i].u1.AddressOfData))->Name;
            DWORD old; VirtualProtect(&slots[i], 4, PAGE_READWRITE, &old);
            if (!strcmp(nm, "GetProcAddress")) s_gpa_tgt = s_ntgt;
            slots[i] = new_target(nm, slots[i]);     /* after the pins: the game sees the pinned value */
            s_tgt[s_ntgt - 1].slot = (uint32_t)&slots[i];
            VirtualProtect(&slots[i], 4, old, &old);
        }
    }
    if (!trace) { spike_log("regpin: %d import slots wrapped\n", s_ntgt); return 1; }
    /* process entry: registers and stack as the OS hands them to the game */
    AddVectoredExceptionHandler(1, entry_veh);
    DWORD old; VirtualProtect((void *)ENTRY_POINT, 1, PAGE_EXECUTE_READWRITE, &old);
    s_entry_orig = *(uint8_t *)ENTRY_POINT; *(uint8_t *)ENTRY_POINT = 0xCC; s_entry_armed = 1;
    VirtualProtect((void *)ENTRY_POINT, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)ENTRY_POINT, 1);
    spike_log("apitrace: %d import slots traced, arena %p\n", s_ntgt, s_arena);
    return 1;
}

/* the fake DirectInput objects live in rcthook.c; their vtables are patched when the game gets them */
