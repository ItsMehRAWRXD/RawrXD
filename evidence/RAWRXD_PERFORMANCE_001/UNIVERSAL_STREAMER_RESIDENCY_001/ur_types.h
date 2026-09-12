/* ur_types.h — neutral residency vocabulary */
#ifndef UR_TYPES_H
#define UR_TYPES_H
#include <stdint.h>
#include <stddef.h>

typedef uint64_t UrRegionId;
typedef uint64_t UrModelId;
typedef uint64_t UrModelGeneration;
typedef uint64_t UrSessionId;
typedef uint32_t UrProviderId;
typedef uint64_t UrTicket;
typedef uint64_t UrOwner;
typedef uint64_t UrGeneration;

#define UR_LANE_META   1
#define UR_LANE_SHARED 2
#define UR_LANE_ROUTER 3
#define UR_LANE_EXPERT 4
#define UR_LANE_KV     5
#define UR_LANE_GPU_WS 6

#define UR_E_BUDGET    (-14)
#define UR_E_ROUTER    (-15)

typedef enum {
    UR_OK = 0,
    UR_E_ARG = -1,
    UR_E_IO = -2,
    UR_E_BOUND = -3,
    UR_E_AUTH = -4,
    UR_E_STATE = -5,
    UR_E_SPEC = -6,
    UR_E_OOM = -7,
    UR_E_SHORT = -8,
    UR_E_DUP = -9,
    UR_E_PIN = -10,
    UR_E_FAIL = -11,
    UR_E_BUSY = -12
} UrStatus;

typedef enum {
    UR_COLD = 0,
    UR_MG_IN_PROGRESS = 1, /* Morning Grouch in flight — claim held */
    UR_WARM = 2,
    UR_HOT = 3,
    UR_FAILED = 4
} UrResidencyState;

/* Closed provenance enum — not caller-trusted freeform */
typedef enum {
    UR_REASON_CURRENT_OP = 1,
    UR_REASON_SPECULATIVE = 2
} UrRequestReason;

typedef struct {
    UrModelId model;
    UrModelGeneration model_gen;
    UrProviderId provider;
    uint32_t shard;
    uint64_t offset;
    uint64_t length;
    uint32_t type_code;
} UrRegionDesc;

typedef struct {
    UrModelId model;
    UrModelGeneration model_gen;
    UrRegionId region;
} UrRegionKey;

typedef struct {
    uint64_t disk_reads;
    uint64_t disk_bytes;
    uint64_t mg_loads;
    uint64_t mg_bytes;
    uint64_t mg_claim_winners;
    uint64_t duplicate_first_touch;
    uint64_t warm_hits;
    uint64_t hot_hits;
    uint64_t demote_hot_warm;
    uint64_t evict_to_cold;
    uint64_t mg_fail;
    uint64_t reject_spec;
    uint64_t reject_stale;
    uint64_t reject_auth;
    uint64_t join_waits;
    uint64_t join_commits;
    uint64_t alias_hits;
    uint64_t alias_partial_reject;
    uint64_t device_copy_bytes;
    uint64_t device_uploads;
    uint64_t device_invalidations;
    uint64_t gpu_allocs;
    uint64_t gpu_copy_issued;
    uint64_t gpu_copy_completed;
    uint64_t gpu_copy_bytes;
    uint64_t reject_dup_upload;
    uint64_t reject_stale_gpu;
    uint64_t reject_evict_inflight;
    uint64_t reject_expert_before_router;
    uint64_t reject_stale_model;
    uint64_t reject_budget;
    uint64_t plan_batch_ok;
} UrTelemetry;

typedef uint32_t UrDeviceId;
typedef uint64_t UrAllocGeneration;

typedef struct {
    UrModelId model;
    UrModelGeneration model_gen;
    UrRegionId region;
    UrGeneration residency_gen;
    UrDeviceId device;
    UrAllocGeneration alloc_gen;
    UrGeneration source_gen;
    uint64_t bytes;
    void *handle;
} UrHotIdentity;

#endif
