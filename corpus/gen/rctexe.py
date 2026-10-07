"""Read-only access to tables in the user's rct.exe (loaded at generation time, never committed).

Only the PE section headers are parsed: no third-party modules, so generators run with plain
python3. Addresses are virtual addresses (image base 0x400000, no relocation).
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_EXE = os.path.join(ROOT, 'game', 'cd', 'English', 'rct.exe')
MD5 = '59e88bbcf3a6db7ea81c648a4afba935'


class Exe:
    def __init__(self, path=DEFAULT_EXE):
        self.data = open(path, 'rb').read()
        import hashlib
        if hashlib.md5(self.data).hexdigest() != MD5:
            raise SystemExit(f'{path}: not the pinned rct.exe (md5 {MD5})')
        pe = struct.unpack_from('<I', self.data, 0x3C)[0]
        nsec = struct.unpack_from('<H', self.data, pe + 6)[0]
        optsz = struct.unpack_from('<H', self.data, pe + 20)[0]
        self.base = struct.unpack_from('<I', self.data, pe + 24 + 28)[0]
        self.sections = []
        off = pe + 24 + optsz
        for i in range(nsec):
            name, vsize, va, rawsz, rawptr = struct.unpack_from('<8sIIII', self.data, off + 40 * i)
            self.sections.append((self.base + va, vsize, rawptr, rawsz))

    def read(self, va, n):
        for lo, vsize, rawptr, rawsz in self.sections:
            if lo <= va and va + n <= lo + max(vsize, rawsz):
                o = va - lo
                b = self.data[rawptr + o: rawptr + min(o + n, rawsz)]
                return b + bytes(n - len(b))   # uninitialised tail reads as zero
        raise ValueError(f'{va:#x}: not in the image')

    def u8(self, va):
        return self.read(va, 1)[0]

    def u16(self, va):
        return struct.unpack('<H', self.read(va, 2))[0]

    def s16(self, va):
        return struct.unpack('<h', self.read(va, 2))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]
