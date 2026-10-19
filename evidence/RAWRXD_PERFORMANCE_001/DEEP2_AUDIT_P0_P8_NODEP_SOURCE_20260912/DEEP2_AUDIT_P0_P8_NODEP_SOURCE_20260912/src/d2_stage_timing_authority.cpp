#include "deep2_audit_nodep.h"
#include <string.h>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

extern "C" uint64_t d2_clock_ticks(void) {
#if defined(_WIN32)
    LARGE_INTEGER v; QueryPerformanceCounter(&v); return (uint64_t)v.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}
extern "C" uint64_t d2_clock_hz(void) {
#if defined(_WIN32)
    LARGE_INTEGER v; QueryPerformanceFrequency(&v); return (uint64_t)v.QuadPart;
#else
    return 1000000000ull;
#endif
}
extern "C" int d2_stage_clock_init(D2StageClock* c) {
    if (!c) return 0; memset(c, 0, sizeof(*c)); c->tick_hz = d2_clock_hz(); return c->tick_hz ? 1 : 0;
}
extern "C" int d2_stage_begin(D2StageClock* c, D2StageId id) {
    if (!c || id >= D2_STAGE_COUNT || !c->tick_hz || (c->active_mask & (1u << id))) return 0;
    c->begin_ticks[id] = d2_clock_ticks(); c->active_mask |= (1u << id); return 1;
}
extern "C" int d2_stage_end(D2StageClock* c, D2StageId id) {
    if (!c || id >= D2_STAGE_COUNT || !(c->active_mask & (1u << id))) return 0;
    const uint64_t now=d2_clock_ticks(); if (now < c->begin_ticks[id]) return 0;
    c->elapsed_ticks[id] += now - c->begin_ticks[id]; c->active_mask &= ~(1u << id); c->sample_count++; return 1;
}
extern "C" int d2_stage_ns(const D2StageClock* c, D2StageId id, uint64_t* out_ns) {
    if (!c || !out_ns || id >= D2_STAGE_COUNT || !c->tick_hz) return 0;
    const uint64_t q=c->elapsed_ticks[id] / c->tick_hz, r=c->elapsed_ticks[id] % c->tick_hz;
    *out_ns=q*1000000000ull + (r*1000000000ull)/c->tick_hz; return 1;
}
extern "C" int d2_stage_timing_authoritative(const D2StageClock* c, uint32_t same_cert_path,
                                              uint32_t synthetic_timing, uint32_t all_required_stages_seen) {
    if (!c || !same_cert_path || synthetic_timing || !all_required_stages_seen || c->active_mask) return 0;
    return c->sample_count >= D2_STAGE_COUNT ? 1 : 0;
}
