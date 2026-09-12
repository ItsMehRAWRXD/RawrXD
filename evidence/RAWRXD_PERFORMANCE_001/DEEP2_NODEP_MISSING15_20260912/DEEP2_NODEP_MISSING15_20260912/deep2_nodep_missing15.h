#ifndef DEEP2_NODEP_MISSING15_H
#define DEEP2_NODEP_MISSING15_H

/* Source-only diagnostics/control helpers.
   No heap, no CRT calls, no Vulkan headers, no third-party dependencies.
   The host runtime owns all GPU/Vulkan operations and passes observations/callbacks. */

#ifdef _MSC_VER
typedef unsigned __int64 d2_u64;
typedef unsigned int     d2_u32;
typedef int              d2_i32;
#else
#include <stdint.h>
typedef uint64_t d2_u64;
typedef uint32_t d2_u32;
typedef int32_t  d2_i32;
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2_OK = 0,
    D2_E_BAD_ARG = 1,
    D2_E_DEVICE_LOST = 2,
    D2_E_RESOURCE_GROWTH = 3,
    D2_E_BUDGET = 4,
    D2_E_RANGE = 5,
    D2_E_SYNC = 6,
    D2_E_AUTHORITY = 7,
    D2_E_NOT_READY = 8
};

typedef enum D2Stage {
    D2_STAGE_BEFORE_FORWARD = 0,
    D2_STAGE_AFTER_BLOCK_0,
    D2_STAGE_AFTER_BLOCK_15,
    D2_STAGE_AFTER_BLOCK_30,
    D2_STAGE_AFTER_BLOCK_45,
    D2_STAGE_AFTER_BLOCK_60,
    D2_STAGE_AFTER_FINAL_NORM,
    D2_STAGE_AFTER_LM_HEAD,
    D2_STAGE_AFTER_QUEUE_IDLE,
    D2_STAGE_COUNT
} D2Stage;

typedef struct D2ResourceSnapshot {
    d2_u64 gpu_total_budget;
    d2_u64 weight_resident_bytes;
    d2_u64 kv_resident_bytes;
    d2_u64 persistent_bytes;
    d2_u64 scratch_current_bytes;
    d2_u64 scratch_peak_bytes;
    d2_u64 transient_current_bytes;
    d2_u64 transient_peak_bytes;
    d2_u64 allocation_count;
    d2_u64 descriptor_pool_usage;
    d2_u64 command_buffer_count;
    d2_u32 stage;
    d2_u32 device_lost;
} D2ResourceSnapshot;

typedef struct D2PlateauState {
    D2ResourceSnapshot base;
    D2ResourceSnapshot last;
    d2_u64 max_transient_delta;
    d2_u64 max_alloc_count_delta;
    d2_u64 max_cmd_count_delta;
    d2_u64 allowed_transient_delta;
    d2_u64 allowed_alloc_count_delta;
    d2_u64 allowed_cmd_count_delta;
    d2_u32 samples;
    d2_u32 failed;
} D2PlateauState;

typedef d2_i32 (*D2SubmitFn)(void *ctx);
typedef d2_i32 (*D2WaitFn)(void *ctx);

typedef struct D2SurvivalOps {
    void *ctx;
    D2WaitFn wait_queue_idle;
    D2SubmitFn submit_noop;
    D2SubmitFn submit_embd;
} D2SurvivalOps;

typedef struct D2SurvivalResult {
    d2_i32 wait_rc;
    d2_i32 noop_rc;
    d2_i32 embd_rc;
    d2_u32 post_forward_device_alive;
    d2_u32 post_forward_noop_pass;
    d2_u32 post_forward_embd_pass;
    d2_u32 promote;
} D2SurvivalResult;

typedef struct D2ArenaPlan {
    d2_u64 gpu_budget;
    d2_u64 driver_reserve;
    d2_u64 weights;
    d2_u64 kv;
    d2_u64 persistent;
    d2_u64 scratch;
    d2_u64 activation_a;
    d2_u64 activation_b;
    d2_u64 command_descriptor_reserve;
    d2_u64 total_required;
    d2_u32 full_gpu_resident;
} D2ArenaPlan;

typedef struct D2SyncState {
    d2_u64 submit_serial;
    d2_u64 completed_serial;
    d2_u64 fence_serial;
    d2_u64 semaphore_wait_serial;
    d2_u64 resource_last_use_serial;
    d2_u64 resource_retire_serial;
} D2SyncState;

typedef struct D2Range {
    d2_u64 base;
    d2_u64 size;
    d2_u64 offset;
    d2_u64 length;
} D2Range;

typedef struct D2BisectState {
    d2_u32 low_pass;
    d2_u32 high_fail;
    d2_u32 next_probe;
    d2_u32 done;
} D2BisectState;

typedef struct D2Token2Witness {
    d2_u32 target_tokens;
    d2_u32 forward_calls;
    d2_u32 full_block_forward_calls;
    d2_u32 sealed_logits_reuse_token1;
    d2_u32 embd_calls_after_advance;
    d2_u32 position0;
    d2_u32 position1;
    d2_u32 commit_calls;
    d2_u32 advance_calls;
    d2_u32 generated;
    d2_u32 device_lost;
    d2_u32 auth_autoregressive_commit_granted;
    d2_u32 full_model_tps_authority;
    d2_u32 promote;
} D2Token2Witness;

/* #01 Post-forward device survival gate */
d2_i32 d2_post_forward_survival(const D2SurvivalOps *ops, D2SurvivalResult *out);

/* #02 Snapshot sanity / budget accounting */
d2_i32 d2_resource_snapshot_validate(const D2ResourceSnapshot *s);

/* #03 Resource plateau tracker */
d2_i32 d2_plateau_init(D2PlateauState *st, const D2ResourceSnapshot *base,
                       d2_u64 transient_delta, d2_u64 alloc_delta, d2_u64 cmd_delta);
d2_i32 d2_plateau_update(D2PlateauState *st, const D2ResourceSnapshot *s);
d2_i32 d2_plateau_pass(const D2PlateauState *st);

/* #04 Fixed arena/full-residency planner */
d2_i32 d2_arena_plan_finalize(D2ArenaPlan *p);

/* #05 Ping/pong activation alias validation */
d2_i32 d2_pingpong_validate(d2_u64 a_base, d2_u64 a_size, d2_u64 b_base, d2_u64 b_size);

/* #06 Descriptor pool boundedness */
d2_i32 d2_descriptor_bound_check(d2_u64 used, d2_u64 capacity);

/* #07 Command-buffer ring boundedness */
d2_i32 d2_command_ring_validate(d2_u64 in_flight, d2_u64 ring_capacity);

/* #08 Bounded submission chunk planner */
d2_u32 d2_submission_chunk_count(d2_u32 blocks, d2_u32 max_blocks_per_submit);

/* #09 Fence/semaphore/resource retirement validator */
d2_i32 d2_sync_validate(const D2SyncState *s);

/* #10 Shader/range OOB guard */
d2_i32 d2_range_validate(const D2Range *r);

/* #11 Late-stage memory barrier validator */
d2_i32 d2_barrier_validate(d2_u64 producer_serial, d2_u64 barrier_serial, d2_u64 consumer_serial);

/* #12 Queue-family ownership validator */
d2_i32 d2_queue_ownership_validate(d2_u32 src_family, d2_u32 dst_family,
                                   d2_u32 current_owner, d2_u32 concurrent_sharing);

/* #13 64-bit allocation/offset overflow guard */
d2_i32 d2_u64_add_checked(d2_u64 a, d2_u64 b, d2_u64 *out);

/* #14 Failure localization bisection helper */
d2_i32 d2_bisect_init(D2BisectState *b, d2_u32 known_pass, d2_u32 known_fail);
d2_i32 d2_bisect_record(D2BisectState *b, d2_u32 probe, d2_u32 survived);

/* #15 TARGET=2 authority checker */
d2_i32 d2_target2_authority_check(const D2Token2Witness *w);

#ifdef __cplusplus
}
#endif
#endif
