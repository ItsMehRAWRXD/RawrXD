#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum D2FabricOpKind : uint32_t {
    D2FAB_OP_ROW_SHARD = 1,
    D2FAB_OP_COL_PARTIAL = 2,
    D2FAB_OP_MOE_EXPERT = 3,
    D2FAB_OP_LM_HEAD = 4
};

struct D2FabricSlice {
    uint64_t tensor_id;
    uint64_t source_offset_bytes;
    uint64_t source_bytes;
    uint32_t row_begin;
    uint32_t row_count;
    uint32_t op_kind;
    uint32_t owner_gpu;
};

struct D2FabricTokenPlan {
    D2FabricSlice gpu[2];
    uint64_t activation_bytes_each;
    uint64_t reduce_bytes;
    uint32_t requires_sum_reduce;
    uint32_t reserved;
};

struct D2FabricCounters {
    uint64_t local_weight_bytes[2];
    uint64_t active_ns[2];
    uint64_t start_ns[2];
    uint64_t end_ns[2];
    uint64_t broadcast_bytes;
    uint64_t reduce_bytes;
    uint64_t weight_migration_bytes;
    uint32_t both_lanes_worked;
    uint32_t serial_gpu_chain;
};

typedef int (*D2FabricSubmitFn)(
    void* user,
    uint32_t gpu_index,
    const D2FabricSlice* slice,
    const void* activation,
    uint64_t activation_bytes,
    void* output,
    uint64_t output_bytes);

typedef int (*D2FabricReduceFn)(
    void* user,
    const void* out0,
    const void* out1,
    void* merged,
    uint64_t bytes,
    uint32_t sum_reduce);

struct D2FabricBackend {
    void* user;
    D2FabricSubmitFn submit;
    D2FabricReduceFn reduce;
};

struct D2FabricConfig {
    uint64_t bw0_bytes_per_sec;
    uint64_t bw1_bytes_per_sec;
    uint64_t max_reduce_bytes;
    uint64_t max_broadcast_bytes;
};

struct D2Fabric;

D2Fabric* d2fabric_create(const D2FabricConfig* cfg, const D2FabricBackend* backend);
void d2fabric_destroy(D2Fabric* f);

/* Bandwidth-weighted output-row partition. source_bytes is the full tensor byte span. */
int d2fabric_plan_rows(
    D2Fabric* f,
    uint64_t tensor_id,
    uint64_t source_offset_bytes,
    uint64_t source_bytes,
    uint32_t total_rows,
    uint32_t op_kind,
    uint64_t activation_bytes_each,
    uint64_t reduce_bytes,
    uint32_t requires_sum_reduce,
    D2FabricTokenPlan* out_plan);

/* Executes both device slices concurrently and then performs the compact merge/reduction. */
int d2fabric_execute(
    D2Fabric* f,
    const D2FabricTokenPlan* plan,
    const void* activation,
    void* out0,
    void* out1,
    void* merged,
    uint64_t output_bytes,
    D2FabricCounters* out_counters);

/* Measured aggregate based only on overlapping active intervals. */
uint64_t d2fabric_aggregate_effective_bps(const D2FabricCounters* c);

/* 1,000,000 == 100% of configured/nominal aggregate reference. */
uint64_t d2fabric_utilization_ppm(uint64_t effective_bps, uint64_t nominal_aggregate_bps);

#ifdef __cplusplus
}
#endif
