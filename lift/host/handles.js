'use strict';
// Kernel handle table. Wine hands out the lowest free handle value (multiples of 4) from a
// per-process table; some values are taken by handles Wine itself opens (wine-answers.js HANDLES
// documents which, so the values the game receives equal Wine's).
class HandleTable {
  /** @param w {below, taken[], retakeAfterClose[]} (wine-answers.js HANDLES) */
  constructor(w, reserved = []) {
    this.base = 4;
    this.map = new Map();
    for (let h = 4; h < w.below; h += 4) this.map.set(h, { type: 'wine' });
    for (const h of w.taken || []) this.map.set(h, { type: 'wine' });
    this.retake = new Set(w.retakeAfterClose || []);
    for (const [h, obj] of reserved) this.map.set(h, obj);
  }
  alloc(obj) {
    let h = this.base;
    while (this.map.has(h)) h += 4;
    this.map.set(h, obj);
    obj.handle = h;
    return h;
  }
  get(h) { return this.map.get(h >>> 0); }
  free(h) {
    h >>>= 0;
    if (!this.map.delete(h)) return false;
    if (this.retake.has(h)) { this.retake.delete(h); this.map.set(h, { type: 'wine' }); }
    return true;
  }
}
module.exports = { HandleTable };
