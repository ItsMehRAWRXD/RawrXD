#ifndef D2_DUAL_GPU_H
#define D2_DUAL_GPU_H
#include "d2_residency.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2PlacementCost {
    uint64_t load_ns[D2_MAX_DEVICES];
    uint64_t exec_ns[D2_MAX_DEVICES];
    uint64_t cross_copy_ns;
} D2PlacementCost;
int d2_dual_gpu_choose(const D2Residency *r,const D2Locality *l,uint32_t expert_id,uint64_t tensor_id,uint64_t bytes,const D2PlacementCost *cost,uint32_t *device);
#ifdef __cplusplus
}
#endif
#endif
