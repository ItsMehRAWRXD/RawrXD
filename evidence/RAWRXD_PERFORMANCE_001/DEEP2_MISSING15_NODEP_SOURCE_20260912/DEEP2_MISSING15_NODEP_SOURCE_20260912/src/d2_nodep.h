#pragma once
#include <cstddef>
#include <cstdint>

extern "C" {

enum D2FitClass : uint32_t {
    D2_FIT_INVALID = 0,
    D2_FIT_VRAM_HOT = 1,
    D2_FIT_MIXED_RAM = 2,
    D2_FIT_COLD_BACKED = 3
};

enum D2KvCodec : uint32_t {
    D2_KV_Q8 = 8,
    D2_KV_Q4 = 4,
    D2_KV_Q2 = 2,
    D2_KV_EVICT = 0
};

enum D2RangeOwner : uint32_t {
    D2_OWNER_NONE = 0,
    D2_OWNER_GPU0 = 1,
    D2_OWNER_GPU1 = 2,
    D2_OWNER_HOST = 3,
    D2_OWNER_COLD = 4
};

struct D2Range {
    uint64_t offset;
    uint64_t bytes;
};

struct D2FabricSlice {
    uint32_t gpu_index;
    uint32_t row_begin;
    uint32_t row_count;
    uint64_t local_weight_bytes;
    D2Range range;
};

struct D2FabricPlan {
    D2FabricSlice lane[2];
    uint32_t total_rows;
    uint32_t valid;
};

struct D2LaneReceipt {
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t local_weight_bytes;
    uint64_t real_forwards;
    uint32_t device_lost;
    uint32_t synthetic_device_io;
};

struct D2ReduceReceipt {
    uint64_t reduce_ns;
    uint64_t inter_gpu_bytes;
    uint32_t compact_merge_real;
};

struct D2FabricMetrics {
    uint64_t overlap_ns;
    uint64_t critical_path_ns;
    uint64_t aggregate_effective_bps;
    uint64_t gpu0_real_forwards;
    uint64_t gpu1_real_forwards;
    uint64_t gpu0_local_bytes;
    uint64_t gpu1_local_bytes;
    uint64_t inter_gpu_bytes;
    uint32_t overlap_ratio_measured;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration_bytes_nonzero;
    uint32_t device_lost;
    uint32_t synthetic_device_io;
    uint32_t compact_merge_real;
};

struct D2FabricTicket { uint64_t opaque[4]; };

typedef int (*D2FabricEnqueueFn)(void* ctx, const D2FabricSlice* slice, uint64_t token_id, D2FabricTicket* out_ticket);
typedef int (*D2FabricCollectFn)(void* ctx, const D2FabricTicket* ticket, D2LaneReceipt* out_receipt);
typedef int (*D2FabricReduceFn)(void* ctx, const D2FabricTicket* a, const D2FabricTicket* b, D2ReduceReceipt* out_receipt);

struct D2SsVkBinding {
    void* ctx;
    D2FabricEnqueueFn enqueue;
    D2FabricCollectFn collect;
    D2FabricReduceFn reduce;
};

struct D2ResidencyItem {
    uint64_t id;
    uint64_t bytes;
    uint64_t reuse_ppm;
    uint64_t criticality_ppm;
    uint32_t pinned;
    uint32_t selected;
};

struct D2ResidencyBudget {
    uint64_t vram_bytes;
    uint64_t ram_bytes;
    uint64_t cold_bytes;
};

struct D2KvEntry {
    uint64_t token_index;
    uint32_t importance_ppm;
    uint32_t age_tokens;
    D2KvCodec codec;
};

struct D2AuthorityInput {
    uint32_t product_linked;
    uint32_t runtime_bind_real;
    uint32_t aggregate_bw_authority_requested;
    uint64_t critical_path_nvme_reads_per_token;
    D2FabricMetrics fabric;
};

int d2_plan_rows_bw(uint32_t total_rows, uint64_t bw0, uint64_t bw1, uint64_t bytes_per_row, D2FabricPlan* out);
int d2_validate_local_plan(const D2FabricPlan* plan);
int d2_bind_ssvk(const D2SsVkBinding* binding);
int d2_get_ssvk(D2SsVkBinding* out);
int d2_submit_same_token(const D2FabricPlan* plan, uint64_t token_id, D2FabricMetrics* out);
int d2_measure_overlap(const D2LaneReceipt* a, const D2LaneReceipt* b, const D2ReduceReceipt* r, D2FabricMetrics* out);
int d2_compact_reduce(const D2FabricTicket* a, const D2FabricTicket* b, D2ReduceReceipt* out);
int d2_packed_q2k_contract(uint64_t packed_bytes, uint64_t scratch_bytes, uint64_t materialized_weight_bytes);
int d2_packed_q4k_contract(uint64_t packed_bytes, uint64_t scratch_bytes, uint64_t materialized_weight_bytes);
int d2_residency_solve(D2ResidencyItem* items, size_t count, uint64_t vram_budget, uint64_t* selected_bytes);
D2FitClass d2_fit_classify(uint64_t model_bytes, const D2ResidencyBudget* budget);
int d2_expert_predict(const uint32_t* previous, size_t prev_count, uint32_t expert_count, uint32_t topk, uint32_t* out_ids, size_t out_count);
int d2_adaptive_kv_plan(D2KvEntry* entries, size_t count, uint64_t target_q8_equiv_tokens);
int d2_nvme_critical_path_guard(uint64_t reads_per_token);
int d2_authority_gate(const D2AuthorityInput* in);

}
