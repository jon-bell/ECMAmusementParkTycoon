/* Measurement modes (spike.c). Inactive unless RCTHOOK_SPIKE is set. */
#ifndef RCT_SPIKE_H
#define RCT_SPIKE_H
#include <windows.h>
#include <stdint.h>
void spike_set_hook_ranges(const uint32_t (*r)[2], int n);
void spike_install(uint32_t stub_lo, uint32_t stub_hi);
void spike_frame(uint32_t frame, uint32_t tick);
void spike_tick(uint32_t *regs, uint32_t tick, uint32_t tick_addr, uint32_t tick_disp);
void spike_tick_end(uint32_t *regs, uint32_t tick_disp);
void spike_quit(void);
void spike_abort(void);
void spike_add_hook(uint32_t orig, uint32_t len, uint32_t disp, uint32_t reloc_stub, uint32_t reloc_orig);
void spike_guest_call(uint32_t target, int callback);
/* apitrace.c */
extern int g_apitrace_on;
int apitrace_install(int trace);
void apitrace_time(uint32_t frame, uint32_t tick);
void apitrace_quit(void);
void apitrace_osmap(void);
uint32_t apitrace_game_ret(uint32_t ret);
void apitrace_wndproc_enter(uint32_t target, uint32_t h, uint32_t m, uint32_t w, uint32_t l);
void apitrace_wndproc_leave(uint32_t ret);
void apitrace_wndproc_drop(uint32_t m, uint32_t w, uint32_t l);
/* provided by rcthook.c */
void spike_log(const char *fmt, ...);
HANDLE spike_open(const char *name);
#endif
