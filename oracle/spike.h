/* Measurement modes (spike.c). Inactive unless RCTHOOK_SPIKE is set. */
#ifndef RCT_SPIKE_H
#define RCT_SPIKE_H
#include <windows.h>
#include <stdint.h>
void spike_set_hook_ranges(const uint32_t (*r)[2], int n);
void spike_install(uint32_t stub_lo, uint32_t stub_hi);
void spike_frame(uint32_t frame, uint32_t tick);
void spike_tick(uint32_t *eflags, uint32_t tick);
void spike_quit(void);
/* provided by rcthook.c */
void spike_log(const char *fmt, ...);
HANDLE spike_open(const char *name);
#endif
