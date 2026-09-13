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
};

MoEPlaceLiveCounters& MoEPlaceLive();
void MoEPlaceLiveReset();
void MoEPlaceLiveEmit(FILE* f);

} // namespace Deep2
