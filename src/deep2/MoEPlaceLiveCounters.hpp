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
    uint64_t stick_overlap_ns; /* intersection of stick worker intervals */
    uint64_t device_down_partials; /* legacy alias increments */
    uint64_t gemv_input_reuse; /* Gate→Up GemvReuseInputNext hits */
    uint64_t device_down_vectors;
    uint64_t device_partial_accums;
    uint64_t d2h_partial_vectors;
    uint64_t host_expert_down_vectors;
    uint64_t max_concurrent_stick_workers;
    uint64_t worker_failures;
    uint64_t layer_joins;
    uint64_t product_backend_attested; /* 1 only after live DualStick device path */
    /* DUALSTICK_KERNEL_IMBALANCE_001 Phase B authority metrics */
    uint64_t gpu0_idle_at_join_ns;
    uint64_t gpu1_idle_at_join_ns;
    uint64_t stick_skew_ns;
    uint64_t stick_skew_pct_sum_x100; /* sum of 0.01% units */
    uint64_t stick_skew_samples;
    uint64_t stick_migrations;
    uint64_t work_steals;
    uint64_t residency_lost_to_rebalance_bytes;
    uint64_t pred_err_sum_ns;
    uint64_t pred_actual_sum_ns;
    /* V6 DIAG: decompose predict error kernel vs xfer vs queue */
    uint64_t pred_err_kernel_ns;
    uint64_t pred_err_xfer_ns;
    uint64_t pred_err_queue_ns;
    /* V6 miss-bytes split — do NOT use EXPERT_MISS_BYTES_PER_TOKEN as auth */
    uint64_t stream_generated_tokens;
    /* V7 observe-only matrix diagnostics (NONAUTH for ACCEPT) */
    uint64_t v7_cost_cells;
    uint64_t v7_cost_samples;
    uint64_t v7_observe_only;
    uint64_t v7_blend_w_x100;
    uint64_t v7_shadow_err_ns;
    uint64_t v7_shadow_act_ns;
    /* V7_MATRIX_COVERAGE_ATTRIBUTION_001 */
    uint64_t v7_kernel_cells;
    uint64_t v7_xfer_cells;
    uint64_t v7_attr_cells;
    uint64_t v7_hot_cells;
    uint64_t v7_hot_cells_ge4;
    uint64_t v7_min_hot_samples;
    uint64_t v7_cell_cov_x100;
    uint64_t v7_hot_cov_x100;
    uint64_t v7_residual_sum_ns;
    uint64_t v7_residual_n;
    uint64_t v7_attrib_only;
    uint64_t v7_compute_xfer_split;
    /* DEEP2_MOE_PIN_EVICTION_COHERENCY_001 */
    uint64_t moe_pin_evictions;
    uint64_t mla_caused_moe_evictions;
    uint64_t general_caused_moe_evictions;
    uint64_t dualstick_stale_pin_metadata;
    uint64_t pinsready_false_positive;
    uint64_t pinsready_repair;
    uint64_t dualstick_slot_invalidated;
    uint64_t moe_pin_touches;
    uint64_t moe_bundle_touches;
    uint64_t cache_budget_set;
    uint64_t cache_budget_shrink;
    uint64_t cache_budget_shrink_blocked;
    /* DEEP2_SEGMENTED_RESIDENCY_QUOTAS_001 */
    uint64_t moe_reserved_bytes;
    uint64_t moe_resident_bytes;
    uint64_t mla_quota_bytes;
    uint64_t general_quota_bytes;
    uint64_t mla_resident_bytes;
    uint64_t general_resident_bytes;
    uint64_t moe_physical_reload_bytes;
    /* DEEP2_MOE_RELOAD_ATTRIBUTION_001 */
    uint64_t moe_evicted_keys;
    uint64_t moe_evicted_bundles;
    uint64_t moe_evicted_then_reused_keys;
    uint64_t moe_evicted_then_reused_bundles;
    uint64_t moe_reload_after_eviction_bytes;
    uint64_t moe_compulsory_load_bytes;
};

MoEPlaceLiveCounters& MoEPlaceLive();
void MoEPlaceLiveReset();
void MoEPlaceLiveEmit(FILE* f);

} // namespace Deep2
