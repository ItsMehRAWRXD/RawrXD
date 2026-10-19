#ifndef DEEP2_RESIDENCY_SOLVER_H
#define DEEP2_RESIDENCY_SOLVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum D2ResidencyTier {
    D2_TIER_NONE = 0,
    D2_TIER_GPU0 = 1,
    D2_TIER_GPU1 = 2,
    D2_TIER_RAM = 3,
    D2_TIER_MMAP = 4
};

enum {
    D2_RES_ALLOW_GPU0 = 1u << 0,
    D2_RES_ALLOW_GPU1 = 1u << 1,
    D2_RES_ALLOW_RAM  = 1u << 2,
    D2_RES_ALLOW_MMAP = 1u << 3,

    D2_RES_PIN_GPU0   = 1u << 4,
    D2_RES_PIN_GPU1   = 1u << 5,
    D2_RES_HOT_EXEC   = 1u << 6,
    D2_RES_COLD_OK    = 1u << 7,
    D2_RES_KV         = 1u << 8,
    D2_RES_SCRATCH    = 1u << 9,
    D2_RES_EXPERT     = 1u << 10
};

typedef struct D2ResidencyNode {
    uint64_t id;
    uint64_t bytes;
    uint64_t hotness;
    uint32_t flags;
    uint32_t preferred_gpu; /* 0, 1, or UINT32_MAX */
} D2ResidencyNode;

typedef struct D2ResidencyCapacity {
    uint64_t gpu0_bytes;
    uint64_t gpu1_bytes;
    uint64_t ram_bytes;
} D2ResidencyCapacity;

typedef struct D2ResidencyPlacement {
    uint64_t id;
    uint64_t bytes;
    uint32_t tier;
    uint32_t exact_range_only;
} D2ResidencyPlacement;

typedef struct D2ResidencyResult {
    uint64_t gpu0_used;
    uint64_t gpu1_used;
    uint64_t ram_used;
    uint64_t mmap_backed;

    uint64_t hot_gpu_bytes;
    uint64_t cold_bytes;

    uint32_t fit;
    uint32_t full_materialization_required;
    uint32_t critical_path_mmap_required;
    uint32_t reserved;
} D2ResidencyResult;

int d2_residency_plan(
    const D2ResidencyNode* nodes,
    size_t count,
    const D2ResidencyCapacity* cap,
    D2ResidencyPlacement* out,
    D2ResidencyResult* result);

#ifdef __cplusplus
}
#endif
#endif
