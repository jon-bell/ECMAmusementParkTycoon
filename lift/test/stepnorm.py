#!/usr/bin/env python3
"""Normalise OS function addresses in a register capture before `tools/stepdiff.py diff`.

  python3 lift/test/stepnorm.py IN OUT

The lift's IAT holds host addresses (0xFFF00000 + 16*i); Wine's holds real DLL addresses
(0x7B000000-0x7FFFFFFF in the oracle's process). Game code copies them into registers and memory
(`mov ebp, [__imp_X]` ... `call ebp`), so captures differ there by construction. This rewrites
every register value and written value in those ranges to 0xEEEEEEEE in R and W records.
A stopgap: the proper fix is for the oracle capture to record its IAT so stepdiff can map
slot by slot (requested from ORACLE INSTRUMENTS).
"""
import struct
import sys

WINE = (0x7B000000, 0x80000000)
HOST = (0xFFF00000, 0xFFFFFFF0)
CANON = 0xEEEEEEEE


def norm(v):
    if WINE[0] <= v < WINE[1] or HOST[0] <= v < HOST[1]:
        return CANON
    return v


def main():
    d = bytearray(open(sys.argv[1], 'rb').read())
    p = 16
    n = 0
    while p < len(d):
        k = struct.unpack_from('<I', d, p)[0] & 0xFF
        if k == 0x52:
            for j in range(2, 10):        # eax..edi (eip and eflags untouched)
                v = struct.unpack_from('<I', d, p + 4 * j)[0]
                if norm(v) != v:
                    struct.pack_into('<I', d, p + 4 * j, CANON)
                    n += 1
            p += 44
        elif k == 0x57:
            v = struct.unpack_from('<I', d, p + 8)[0]
            if (struct.unpack_from('<I', d, p)[0] >> 8) == 4 and norm(v) != v:
                struct.pack_into('<I', d, p + 8, CANON)
                n += 1
            p += 12
        elif k == 0x54:
            p += 8
        elif k == 0x4F:
            p += 12
        else:
            raise SystemExit(f'unknown record {k:#x} at {p}')
    open(sys.argv[2], 'wb').write(d)
    print(f'{n} values normalised')


if __name__ == '__main__':
    main()
