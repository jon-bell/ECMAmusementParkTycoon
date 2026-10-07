/* State bytes that hold values the OS chose rather than the game: addresses of memory Wine
 * allocated or mapped (heap, VirtualAlloc, the screen DIB, the CSG1.DAT view) and handles. The
 * masked state hash (TR_MSTATE) reads these bytes as 0; every other state byte counts.
 *
 * Single source of truth for the oracle (rcthook.c) and the JS host. Format, one entry per line:
 *   MASK_DWORD(addr)                  the 4 bytes at addr (any alignment)
 *   MASK_STRIDE(base, stride, count)  MASK_DWORD(base + i*stride) for i in [0, count)
 * Numbers are C hex literals; a comment follows the entry on the same line. Hashing: the state is
 * hashed as 32-bit little-endian words from 0x5F4000 and from 0x9A2000 (record_state); a masked
 * byte contributes 0 to its word.
 *
 * Evidence: docs/stage1-scope.md M5 (heapshift dumps, ptrscan) and oracle/README.md. */
MASK_STRIDE(0x8DC0B4, 16, 38365)   /* sprite table (from CSG1I.DAT): pointer into the CSG1.DAT view */
MASK_DWORD(0x5F88A4)               /* file handle of the last scenario file opened */
MASK_STRIDE(0x9A1550, 4, 22)       /* cursor handles (HCURSOR, LoadCursorA at 0x404BD9) */
MASK_DWORD(0x5F96C0)               /* drawing context: bits (pointer into the screen DIB) */
MASK_DWORD(0x5F96D0)               /* drawing context: bits (passed at 0x4315A0, 0x4317A8) */
MASK_DWORD(0x99FB7C)               /* screen drawing context: bits (passed at 0x43869F and 10 more sites) */
MASK_DWORD(0x99FB8C)               /* drawing context: bits (passed at 0x5E15FB) */
MASK_DWORD(0x99FE08)               /* drawing context: bits (passed at 0x5E5100) */
MASK_DWORD(0x9A012C)               /* drawing context: bits (filled at 0x5E6AB6, passed at 0x5E6BC2) */
MASK_DWORD(0x628C44)               /* 64 KiB buffer from malloc (0x404656, stored at 0x437FFB; map window) */
MASK_DWORD(0x9A2008)               /* CSG1.DAT view base */
MASK_DWORD(0x9A200C)               /* transient OS address (tick 1) */
MASK_DWORD(0x9A2010)               /* CSG1.DAT view */
