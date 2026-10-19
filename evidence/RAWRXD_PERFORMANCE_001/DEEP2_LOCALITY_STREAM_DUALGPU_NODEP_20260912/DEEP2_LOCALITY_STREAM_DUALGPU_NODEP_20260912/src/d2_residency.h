#ifndef D2_RESIDENCY_H
#define D2_RESIDENCY_H
#include "d2_common.h"
#include "d2_locality.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum D2ResidencyState { D2_RES_COLD=0, D2_RES_LOADING=1, D2_RES_HOT=2 } D2ResidencyState;
typedef struct D2Resident {
    uint64_t tensor_id;
    uint64_t bytes;
    uint64_t last_use_token;
    uint32_t expert_id;
    uint32_t device;
    uint32_t state;
    uint32_t pin_count;
} D2Resident;
typedef struct D2DeviceResidency {
    uint64_t budget_bytes;
    uint64_t used_bytes;
    uint64_t bandwidth_bytes_s;
    uint32_t healthy;
    D2Resident item[D2_MAX_RESIDENT];
    size_t count;
} D2DeviceResidency;
typedef struct D2Residency {
    D2DeviceResidency dev[D2_MAX_DEVICES];
    D2ObservedCounters counters;
} D2Residency;
void d2_residency_init(D2Residency *r,uint64_t budget0,uint64_t budget1,uint64_t bw0,uint64_t bw1);
int d2_residency_find(const D2Residency *r,uint32_t device,uint64_t tensor_id,size_t *index);
int d2_residency_reserve(D2Residency *r,D2Locality *loc,uint32_t device,uint64_t tensor_id,uint32_t expert_id,uint64_t bytes,uint64_t token,size_t *slot);
int d2_residency_commit(D2Residency *r,D2Locality *loc,uint32_t device,size_t slot);
int d2_residency_pin(D2Residency *r,uint32_t device,uint64_t tensor_id,int delta,uint64_t token);
int d2_residency_evict_one(D2Residency *r,D2Locality *loc,uint32_t device,uint64_t token);
#ifdef __cplusplus
}
#endif
#endif
