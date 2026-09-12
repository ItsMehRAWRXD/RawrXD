/* deep2_progress_watch.h — stall diagnosis only; never mints PASS */
#ifndef DEEP2_PROGRESS_WATCH_H
#define DEEP2_PROGRESS_WATCH_H
#include <stdint.h>
typedef struct {
    uint64_t last_token_serial, last_op_serial, last_change_tick;
    uint64_t stall_ticks;
    const char *stall_owner;
} D2ProgWatch;
void d2_pw_init(D2ProgWatch *w);
void d2_pw_tick(D2ProgWatch *w, uint64_t now, uint64_t tok_serial, uint64_t op_serial,
                const char *owner);
int d2_pw_stalled(const D2ProgWatch *w, uint64_t max_idle_ticks);
#endif
