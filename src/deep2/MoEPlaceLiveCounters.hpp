/* MoE place live reachability counters — always monotonic; stderr on TRACE. */
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct MoEPlaceLiveCounters {
    uint64_t moe_tokens;
    uint64_t moe_ffn_enter;
    uint64_t moe_ffn_early_return;
    uint64_t moe_router_calls;
    uint64_t moe_place_enter;
    uint64_t moe_place_calls;
    uint64_t experts_selected;
    uint64_t experts_executed;
    uint64_t expert_cache_hits;
    uint64_t expert_cache_misses;
    uint64_t expert_hit_bytes;
    uint64_t expert_miss_bytes;
    uint64_t expert_stick_retains;
    uint64_t expert_stick_assigns;
    uint64_t expert_acquire_ok;
    uint64_t expert_acquire_fail;
    uint64_t expert_markhot;
    uint64_t moe_thrash_tokens;
    uint64_t ffn_dispatch_moe;
    uint64_t ffn_dispatch_dense;
    uint64_t ffn_dispatch_ssm;
    /* Decode-phase subset (position>0); totals may include prefill. */
    uint64_t decode_moe_layer_calls;
    uint64_t decode_moe_place_calls;
    uint64_t decode_experts_selected;
    uint64_t decode_experts_executed;
    uint64_t shared_expert_calls;
    uint64_t expert_slice_layout_mismatch;
    /* DualStick stick-VRAM expert path (K2_EXPERT_GPU_EXEC_BIND). */
    uint64_t expert_gpu_acquire;
    uint64_t expert_gpu_exec;
    uint64_t host_gemv_expert; /* routed experts that fell back to GetGEMV */
    /* DUALSTICK_REUSE_MICROFIX_001 */
    uint64_t expert_bundle_lookups;
    uint64_t expert_bundle_hits;
    uint64_t expert_bundle_misses;
    uint64_t expert_acquire_hits;   /* skip reacquire when pin-resident */
    uint64_t expert_acquire_misses;
    uint64_t host_bytes_for_hit;    /* must stay 0 on cache-hit path */
    uint64_t host_bytes_for_miss;
    uint64_t secondary_lookup;      /* Place already carried stick/handle */
    uint64_t compulsory_miss_bytes;
    uint64_t reload_miss_bytes;
    uint64_t hit_bytes;
    uint64_t gpu0_experts;
    uint64_t gpu1_experts;
    uint64_t gpu0_work_ns;
    uint64_t gpu1_work_ns;
    uint64_t gpu_join_wait_ns;
    uint64_t h2d_bytes;
    uint64_t d2h_bytes;
    uint64_t gpu_submits;
    uint64_t gpu_waits;
    uint64_t moe_layers_gpu;
    uint64_t seen_bundle_keys; /* unique (layer,expert) first-touch count */
};

MoEPlaceLiveCounters& MoEPlaceLive();
void MoEPlaceLiveReset();
void MoEPlaceLiveEmit(FILE* f);

} // namespace Deep2
