/* Trace record format shared by rcthook.dll and tools/trace.py.
 * Every record is four little-endian uint32: kind, a, b, c. */
#ifndef RCT_TRACE_H
#define RCT_TRACE_H
#define TRACE_VERSION 1
enum {
    TR_HEADER   = 0x01, /* version, realtime flag, time quantum                          */
    TR_FRAME    = 0x02, /* frame number, virtual clock, ticks so far                     */
    TR_TICK     = 0x03, /* tick number, srand0, srand1 (at tick start)                   */
    TR_RNG      = 0x04, /* tick, call site, drawn value                                  */
    TR_CHUNK    = 0x05, /* chunk index, hash lo, hash hi (64 KiB chunks of the state)    */
    TR_STATE    = 0x06, /* tick, state hash lo, hi  (DATASEG + DataSeg, at tick start)   */
    TR_COMMAND  = 0x07, /* tick, cmd | flags<<8 | depth<<16, call site (game's own calls) */
    TR_REGS_IN  = 0x08, /* eax, ebx, ecx */
    TR_REGS_IN2 = 0x09, /* edx, esi, edi */
    TR_INJECT   = 0x0A, /* tick, command id or routine address, script line              */
    TR_REGS_OUT = 0x0B, /* eax, ebx, ecx */
    TR_REGS_OUT2= 0x0C, /* edx, esi, edi */
    TR_REGS_OUT3= 0x0D, /* ebp, eflags, 0 */
    TR_INPUT    = 0x0E, /* tick, channel (1 key, 2 cursor, 3 poke, 4 mouse), value      */
    TR_LOAD     = 0x0F, /* tick, ok, frame */
    TR_MSG      = 0x10, /* tick, window message, wparam (delivered to the game)          */
    TR_MSG_DROP = 0x11, /* tick, window message (user input dropped by the pin)          */
    TR_FILE     = 0x12, /* tick, call site, success                                      */
    TR_NOTE     = 0x13, /* tick, note id, value */
    TR_FINAL    = 0x14, /* tick, state hash lo, hi at quit                               */
    TR_END      = 0x15, /* frames, ticks, rng draws */
    TR_INJ_IN   = 0x16, /* eax, ebx, ecx  of an injected call */
    TR_INJ_IN2  = 0x17, /* edx, esi, edi  of an injected call */
};
#endif
