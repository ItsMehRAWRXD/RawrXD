#pragma once
/* DEEP2_PERSISTENT_DECODE_001 — same-process continuity counters. PROMOTE=0. */
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct PersistentContinuity {
    uint64_t device_create_events = 0;
    uint64_t model_load_events = 0;
    uint64_t command_rebuild_events = 0;
    uint64_t sealed_logits_reuse_events = 0;
    uint64_t dualstick_reset_events = 0;
    uint64_t n_gt0_tokens = 0;
    uint64_t n_gt0_pass = 0;
    uint64_t kv_len_last = 0;
    uint64_t kv_regressions = 0;
};

inline void PersistentEmitToken(
    FILE* f, uint64_t token, uint64_t kv_len, unsigned devices,
    int model_loaded, int gpu_resident, int ssvk_bound, int bind_ok,
    int sealed_reuse, uint64_t device_creates, uint64_t model_loads,
    uint64_t cmd_rebuilds, uint64_t dualstick_resets) noexcept
{
    if (!f) return;
    std::fprintf(f,
        "PERSISTENT_DECODE_TOKEN t=%llu kv=%llu devices=%u model=%d "
        "gpu_res=%d ssvk=%d bind=%d sealed=%d "
        "dev_create=%llu model_load=%llu cmd_rebuild=%llu ds_reset=%llu\n",
        (unsigned long long)token, (unsigned long long)kv_len, devices,
        model_loaded, gpu_resident, ssvk_bound, bind_ok, sealed_reuse,
        (unsigned long long)device_creates, (unsigned long long)model_loads,
        (unsigned long long)cmd_rebuilds, (unsigned long long)dualstick_resets);
}

} // namespace Deep2
