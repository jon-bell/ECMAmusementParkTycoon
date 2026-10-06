#!/usr/bin/env python3
"""Byte-level diff of two state dumps (dump action: DATASEG then DataSeg).

  dumpdiff.py <a.bin> <b.bin> [max_ranges]
Prints differing ranges as virtual addresses with both values (as little-endian dwords when the
range fits in one)."""
import sys

STATE_LO, STATE_HI, STATE2_LO = 0x5F4000, 0x9A161C, 0x9A2000
N1 = STATE_HI - STATE_LO


def va(off):
    return STATE_LO + off if off < N1 else STATE2_LO + off - N1


def ranges(a, b, gap=3):
    out, i, n = [], 0, min(len(a), len(b))
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and (a[j] != b[j] or any(a[k] != b[k] for k in range(j + 1, min(n, j + 1 + gap)))):
                j += 1
            out.append((i, j))
            i = j
        i += 1
    return out


def main():
    a, b = open(sys.argv[1], 'rb').read(), open(sys.argv[2], 'rb').read()
    lim = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    rs = ranges(a, b)
    print(f'{sum(e - s for s, e in rs)} differing bytes in {len(rs)} ranges')
    for s, e in rs[:lim]:
        s4 = s & ~3
        print(f'  {va(s):#x} len {e - s:4d}  a={a[s4:s4 + 8].hex()} b={b[s4:s4 + 8].hex()}')


if __name__ == '__main__':
    main()
