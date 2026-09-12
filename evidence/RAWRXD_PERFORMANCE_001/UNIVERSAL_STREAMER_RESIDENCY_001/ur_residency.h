/* ur_residency.h — residency owns Morning Grouch */
#ifndef UR_RESIDENCY_H
#define UR_RESIDENCY_H
#include "ur_types.h"
#include "ur_index.h"
#include "ur_op_auth.h"
#include "ur_provider.h"
#include "ur_device.h"
#include "ur_sync.h"
#ifdef __cplusplus
extern "C" {
#endif

#define UR_CACHE_CAP 64
#define UR_LEASE_CAP 64

typedef struct {
    UrRegionId id;
    UrRegionDesc desc;
    UrResidencyState state;
    UrGeneration generation;
    uint32_t pin_count;
    uint32_t mg_claimed;
    uint8_t *bytes;
    uint64_t length;
    uint8_t used;
    UrDeviceId device_id;
    UrAllocGeneration dev_alloc_gen;
    UrGeneration hot_source_gen;
    void *dev_handle;
    uint32_t copy_inflight;
} UrCacheSlot;

typedef struct {
    UrRegionId req;
    UrRegionId host;
    uint32_t pins;
    uint8_t used;
} UrPinLease;

typedef struct {
    UrShardIndex index;
    UrOpAuth auth;
    UrProviderVTable provider;
    UrDeviceVTable device;
    UrSync sync;
    UrCacheSlot cache[UR_CACHE_CAP];
    UrPinLease lease[UR_LEASE_CAP];
    UrTelemetry tel;
    UrOwner owner;
    uint64_t host_budget;
} UrRuntime;

void ur_runtime_set_host_budget(UrRuntime *r, uint64_t bytes);
int ur_invalidate_model(UrRuntime *r, UrModelId model);

void ur_runtime_init(UrRuntime *r, UrProviderVTable prov, UrOwner owner);
void ur_runtime_set_device(UrRuntime *r, UrDeviceVTable dev);
void ur_runtime_shutdown(UrRuntime *r);

int ur_require_region(UrRuntime *r, UrTicket ticket, UrRegionId id,
                      UrRequestReason reason, const uint8_t **ptr_out,
                      uint64_t *len_out, UrGeneration *gen_out);
int ur_release_region(UrRuntime *r, UrRegionId id);
int ur_promote_hot(UrRuntime *r, UrRegionId id);
int ur_promote_hot_at(UrRuntime *r, UrRegionId id, UrGeneration expect);
int ur_demote_to_warm(UrRuntime *r, UrRegionId id);
int ur_evict_region(UrRuntime *r, UrRegionId id);
int ur_hot_identity(UrRuntime *r, UrRegionId id, UrHotIdentity *out);
int ur_hot_valid(UrRuntime *r, UrRegionId id, UrAllocGeneration agen);
int ur_hot_reset(UrRuntime *r, UrRegionId id);
int ur_copy_inflight(UrRuntime *r, UrRegionId id);
int ur_region_state(UrRuntime *r, UrRegionId id, UrResidencyState *out);

int usr_resolve(UrRuntime *r, UrRegionId region, UrRegionDesc *out);
int usr_require(UrRuntime *r, UrRegionId region, UrTicket ticket,
                const uint8_t **out_ptr, uint64_t *out_len);
int usr_mark_hot(UrRuntime *r, UrRegionId region);

#ifdef __cplusplus
}
#endif
#endif
