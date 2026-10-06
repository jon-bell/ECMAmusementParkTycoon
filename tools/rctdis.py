import pefile, capstone, struct
pe=pefile.PE('game/cd/English/rct.exe')
IB=0x400000
img=pe.get_memory_mapped_image()
def rd(va,n): return img[va-IB:va-IB+n]
def u32(va): return struct.unpack('<I',rd(va,4))[0]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def dis(va,n=40,stop_ret=False):
    out=[]
    for i in md.disasm(rd(va,n*15),va):
        out.append(f"{i.address:08x}: {i.bytes.hex():20s} {i.mnemonic} {i.op_str}")
        if len(out)>=n or (stop_ret and i.mnemonic in('ret','jmp')): break
    return "\n".join(out)
def find(b,lo=0x401000,hi=0x9c0000):
    r=[];s=img[lo-IB:hi-IB];i=s.find(b)
    while i>=0: r.append(lo+i); i=s.find(b,i+1)
    return r
def callers(t, lo=0x401000, hi=0x9bd000):
    r=[]; s=img[lo-IB:hi-IB]; i=s.find(b'\xe8')
    while i>=0:
        rel=struct.unpack('<i',s[i+1:i+5])[0]
        if (lo+i+5+rel)&0xffffffff==t: r.append(lo+i)
        i=s.find(b'\xe8',i+1)
    return r
def jumpers(t, lo=0x401000, hi=0x9bd000):
    r=[]; s=img[lo-IB:hi-IB]; i=s.find(b'\xe9')
    while i>=0:
        rel=struct.unpack('<i',s[i+1:i+5])[0]
        if (lo+i+5+rel)&0xffffffff==t: r.append(lo+i)
        i=s.find(b'\xe9',i+1)
    return r
def disr(va,maxn=200):
    out=[]
    for i in md.disasm(rd(va,maxn*15),va):
        out.append(f"{i.address:08x}: {i.mnemonic} {i.op_str}")
        if len(out)>=maxn or i.mnemonic=='ret': break
    return "\n".join(out)
