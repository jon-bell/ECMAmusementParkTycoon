'use strict';
// Guest address space for memory the OS hands out: VirtualAlloc regions, Win32 heaps
// (HeapCreate/HeapAlloc/HeapFree, the process heap, GlobalAlloc), and fixed placements (the DIB
// section and the CSG1.DAT mapping, at the addresses Wine chose: docs/stage1-design.md).
//
// Addresses are deterministic. They need not equal Wine's: the scope study (M5) shows that no
// heap or VirtualAlloc address reaches the compared (masked) state; only the DIB and mapping
// pointers do, and those are placed where Wine put them. Fresh memory reads as zero, as fresh
// pages do under Wine.
const G = require('./guestmem');

const PAGE = 0x1000, GRAN = 0x10000;
const MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_DECOMMIT = 0x4000, MEM_RELEASE = 0x8000;
const HEAP_ZERO_MEMORY = 0x8;

const alignUp = (v, a) => Math.ceil(v / a) * a;

class AddressSpace {
  /** @param {Array<[number,number]>} ranges free guest ranges [lo, hi) available for allocation */
  constructor(ranges) {
    this.free = ranges.map(([lo, hi]) => ({ lo, hi }));
    this.regions = new Map();   // base -> {base, size, committed: Set<page index>, kind}
  }
  /** Reserve `size` bytes at a GRAN-aligned address (or exactly at `at`). */
  reserve(size, at, kind = 'virtual') {
    size = alignUp(size, GRAN);
    let base = -1;
    for (const f of this.free) {
      const lo = at !== undefined ? at : alignUp(f.lo, GRAN);
      if (lo >= f.lo && lo + size <= f.hi) { base = lo; break; }
      if (at !== undefined) continue;
    }
    if (base < 0) return 0;
    this._take(base, size);
    this.regions.set(base, { base, size, committed: new Set(), kind });
    return base;
  }
  _take(lo, size) {
    const hi = lo + size;
    const out = [];
    for (const f of this.free) {
      if (hi <= f.lo || lo >= f.hi) { out.push(f); continue; }
      if (f.lo < lo) out.push({ lo: f.lo, hi: lo });
      if (hi < f.hi) out.push({ lo: hi, hi: f.hi });
    }
    this.free = out.sort((a, b) => a.lo - b.lo);
  }
  regionOf(addr) {
    for (const r of this.regions.values()) if (addr >= r.base && addr < r.base + r.size) return r;
    return null;
  }
  commit(addr, size) {
    const r = this.regionOf(addr);
    if (!r || addr + size > r.base + r.size) return false;
    const lo = Math.floor(addr / PAGE) * PAGE, hi = alignUp(addr + size, PAGE);
    for (let p = lo; p < hi; p += PAGE) {
      if (!r.committed.has(p)) { r.committed.add(p); G.fill(p, PAGE, 0); }
    }
    G.map(lo, hi - lo);
    return true;
  }
  decommit(addr, size) {
    const r = this.regionOf(addr);
    if (!r) return false;
    const lo = Math.floor(addr / PAGE) * PAGE, hi = alignUp(addr + size, PAGE);
    for (let p = lo; p < hi; p += PAGE) r.committed.delete(p);
    G.M.unmapPages(lo, hi - lo);
    return true;
  }
  release(base) {
    const r = this.regions.get(base);
    if (!r) return false;
    G.M.unmapPages(r.base, r.size);
    this.regions.delete(base);
    this.free.push({ lo: r.base, hi: r.base + r.size });
    this.free.sort((a, b) => a.lo - b.lo);
    // coalesce
    const out = [];
    for (const f of this.free) {
      const last = out[out.length - 1];
      if (last && last.hi === f.lo) last.hi = f.hi; else out.push({ ...f });
    }
    this.free = out;
    return true;
  }
}

/** A Win32 heap: first-fit over committed chunks, 8-byte aligned blocks with an 8-byte gap. */
class Heap {
  /**
   * @param o {at, first}: place the heap at guest address `at` (Wine's address for it), with
   *   its first block header at offset `first` (Wine's heap header size): then blocks land at
   *   the addresses Wine gives (consecutive 8-byte-headed blocks, first fit).
   */
  constructor(space, handle, initialSize, o = {}) {
    this.space = space;
    this.handle = handle;
    this.chunks = [];           // {lo, hi}
    this.freeList = [];         // {lo, hi} free spans, sorted
    this.blocks = new Map();    // user address -> size
    this._grow(o.size || Math.max(initialSize || 0, 0x100000), o.at, o.first || 0);
  }
  _grow(min, at, first = 0) {
    const size = at ? alignUp(min, GRAN) : alignUp(min + 0x1000, GRAN);
    const base = this.space.reserve(size, at, 'heap');
    if (!base) throw new Error(`heap: out of guest address space (${size} bytes${at ? ' at 0x' + at.toString(16) : ''})`);
    this.space.commit(base, size);
    this.chunks.push({ lo: base, hi: base + size });
    this._addFree(base + first, base + size);
  }
  _addFree(lo, hi) {
    this.freeList.push({ lo, hi });
    this.freeList.sort((a, b) => a.lo - b.lo);
    const out = [];
    for (const f of this.freeList) {
      const last = out[out.length - 1];
      if (last && last.hi === f.lo) last.hi = f.hi; else out.push({ ...f });
    }
    this.freeList = out;
  }
  alloc(size, flags = 0) {
    const need = alignUp(Math.max(size, 1), 8) + 8;     // 8-byte header gap, as Wine's heap
    let f = this.freeList.find((s) => s.hi - s.lo >= need);
    if (!f) { this._grow(need); f = this.freeList.find((s) => s.hi - s.lo >= need); }
    const lo = f.lo;
    f.lo += need;
    if (f.lo === f.hi) this.freeList.splice(this.freeList.indexOf(f), 1);
    const user = lo + 8;
    this.blocks.set(user, need);
    // fresh memory is zero; reused memory keeps old bytes unless HEAP_ZERO_MEMORY
    if (flags & HEAP_ZERO_MEMORY) G.fill(user, size, 0);
    return user;
  }
  free(user) {
    const need = this.blocks.get(user);
    if (need === undefined) return false;
    this.blocks.delete(user);
    this._addFree(user - 8, user - 8 + need);
    return true;
  }
  size(user) { const n = this.blocks.get(user); return n === undefined ? -1 : n - 8; }
}

module.exports = { AddressSpace, Heap, MEM_COMMIT, MEM_RESERVE, MEM_DECOMMIT, MEM_RELEASE, HEAP_ZERO_MEMORY, PAGE, GRAN };
