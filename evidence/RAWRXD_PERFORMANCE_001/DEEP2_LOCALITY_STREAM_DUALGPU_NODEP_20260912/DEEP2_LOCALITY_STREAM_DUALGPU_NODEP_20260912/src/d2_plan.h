#ifndef D2_PLAN_H
#define D2_PLAN_H
#include "d2_dual_gpu.h"
#include "d2_stream.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2ExpertTensorSet {
    uint32_t expert_id;
    D2ByteRange ranges[8];
    size_t range_count;
} D2ExpertTensorSet;
typedef struct D2PlanItem {
    D2ByteRange range;
    uint32_t device;
    uint32_t resident_hit;
} D2PlanItem;
typedef struct D2TokenPlan {
    uint64_t token;
    D2PlanItem item[D2_MAX_RANGES];
    size_t count;
    uint64_t bytes_by_device[2];
} D2TokenPlan;
int d2_plan_token(D2Residency *res,D2Locality *loc,uint64_t token,const uint32_t *selected,size_t selected_count,const D2ExpertTensorSet *sets,size_t set_count,const D2PlacementCost *cost,D2TokenPlan *out);
#ifdef __cplusplus
}
#endif
#endif
