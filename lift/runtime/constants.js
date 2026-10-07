'use strict';
// Fixed addresses and sizes of the lift's execution model (docs/stage1-design.md).

module.exports = Object.freeze({
  MEM_SIZE: 0x05400000,            // guest memory covers [0, MEM_SIZE)
  PAGE_SHIFT: 12,                  // protection granularity (4 KiB pages)

  IMAGE_BASE: 0x00400000,          // rct.exe has no relocations; it loads here
  IMAGE_LO: 0x00400000,            // block table covers [IMAGE_LO, IMAGE_HI)
  IMAGE_HI: 0x009C4000,            // ImageBase + SizeOfImage (headers .. .rsrc)

  STACK_LO: 0x00230000,            // main thread stack (reserved and committed: RW)
  STACK_HI: 0x00330000,
  STACK_INIT: 0x0032FF00,          // initial esp before the entry point's return address is pushed

  TEB_BASE: 0x00380000,            // fs: base; one RW page (see README: TEB)

  HOST_BASE: 0xFFF00000,           // host function i lives at HOST_BASE + 16*i
  HOST_RETURN: 0xFFFFFFF0,         // return address pushed by callGuest
  HOST_RETURN_LOAD: 0xFFFFFFE0,    // return address pushed by the script `load` action
  HOST_EXIT: 0xFFFFFFD0,           // return address of the entry point (process exit)
  HOST_SLOTS: 0xFFFD,              // host slots available below HOST_EXIT

  // PE sections of rct.exe v1.08.183 (checked by the loader against the file it loads)
  SECTIONS: Object.freeze({
    '.text': [0x00401000, 0x0041B1A6],
    CODESEG: [0x0041C000, 0x005E6C5D],
    '.rdata': [0x005E7000, 0x005E8F46],
    '.data': [0x005E9000, 0x005F3F74],
    DATASEG: [0x005F4000, 0x009A161C],
    DataSeg: [0x009A2000, 0x009B2301],
    CodeSeg: [0x009B3000, 0x009BC562],
    '.rsrc': [0x009BD000, 0x009C3870],
  }),
  CODE_SECTIONS: Object.freeze(['.text', 'CODESEG', 'CodeSeg']),
  ENTRY: 0x00412E80,
});
