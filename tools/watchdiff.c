/* watchdiff A.bin B.bin: compare two watch logs (oracle RCTHOOK_SPIKE=watch=FILE, uint32 LE triples
 * tick, address, value) of the same script. The logs must have the same (tick, address) sequence;
 * prints "addr ormask first_tick base_value shift_value" for every address whose values differ
 * (ormask = OR of base^shift over all its entries), or "MISALIGNED <index>" and exit 2.
 * Built and used by tools/maskaudit.py. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct { uint32_t addr, mask, tick, va, vb; } hit_t;
static int cmp(const void *a, const void *b) { uint32_t x = ((const hit_t *)a)->addr, y = ((const hit_t *)b)->addr; return (x > y) - (x < y); }
int main(int argc, char **argv)
{
    if (argc < 3) return 1;
    FILE *fa = fopen(argv[1], "rb"), *fb = fopen(argv[2], "rb");
    if (!fa || !fb) return 1;
    static uint32_t ba[3 << 16], bb[3 << 16];
    size_t cap = 1 << 16, n = 0; hit_t *h = malloc(cap * sizeof *h);
    uint32_t *idx = calloc(1u << 23, 4);       /* (addr - 0x5F0000) / 2 -> hit index + 1 */
    uint64_t k = 0;
    for (;;) {
        size_t na = fread(ba, 12, 1 << 16, fa), nb = fread(bb, 12, 1 << 16, fb);
        if (na != nb) { printf("MISALIGNED length at %llu\n", (unsigned long long)(k + (na < nb ? na : nb))); return 2; }
        if (!na) break;
        for (size_t i = 0; i < na; i++, k++) {
            uint32_t *a = ba + 3 * i, *b = bb + 3 * i;
            if (a[0] != b[0] || a[1] != b[1]) { printf("MISALIGNED %llu tick %u/%u addr %08x/%08x\n", (unsigned long long)k, a[0], b[0], a[1], b[1]); return 2; }
            if (a[2] == b[2]) continue;
            uint32_t s = (a[1] - 0x5F0000u) >> 1;
            if (s >= (1u << 23)) continue;
            if (!idx[s]) {
                if (n == cap) { cap *= 2; h = realloc(h, cap * sizeof *h); }
                h[n] = (hit_t){a[1], 0, a[0], a[2], b[2]}; idx[s] = ++n;
            }
            h[idx[s] - 1].mask |= a[2] ^ b[2];
        }
    }
    qsort(h, n, sizeof *h, cmp);
    for (size_t i = 0; i < n; i++) printf("%08x %08x %u %08x %08x\n", h[i].addr, h[i].mask, h[i].tick, h[i].va, h[i].vb);
    return 0;
}
