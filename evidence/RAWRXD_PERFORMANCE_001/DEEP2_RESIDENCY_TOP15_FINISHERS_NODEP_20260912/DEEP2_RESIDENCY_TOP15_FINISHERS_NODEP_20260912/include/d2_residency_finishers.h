#ifndef D2_RESIDENCY_FINISHERS_H
#define D2_RESIDENCY_FINISHERS_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum D2ResidencyState {
    D2R_COLD = 0,
    D2R_LOADING = 1,
    D2R_WARM = 2,
    D2R_HOT = 3
} D2ResidencyState;

typedef struct D2ResidencyRegion {
    uint64_t region_id;
    uint64_t generation;
    uint64_t offset;
    uint64_t length;
    uint64_t resident_bytes;
    uint32_t codec;
    uint32_t owner_id;
    uint32_t pin_count;
    uint32_t state;
    uint32_t load_inflight;
} D2ResidencyRegion;

typedef struct D2ResidencyCounters {
    uint64_t first_touch_wins;
    uint64_t joined_loads;
    uint64_t failed_loads;
    uint64_t hot_to_warm;
    uint64_t warm_to_cold;
} D2ResidencyCounters;

typedef struct D2ResidencyParentProof {
    uint32_t bind16_authority;
    uint32_t bind16_pass_tokens;
    uint32_t persistent_decode;
    uint32_t gpu_resident_decode;
    uint32_t dual_gpu_used;
    uint64_t resident_bytes;
    uint64_t weight_upload_delta;
    uint64_t reload_delta;
    uint64_t device_create_delta;
    uint64_t model_load_delta;
    uint64_t pin_evict_delta;
} D2ResidencyParentProof;

void d2r_init(D2ResidencyRegion* r, uint64_t region_id, uint64_t generation,
              uint64_t offset, uint64_t length, uint32_t codec, uint32_t owner_id);
int d2r_begin_first_touch(D2ResidencyRegion* r, D2ResidencyCounters* c,
                          uint64_t generation, uint32_t owner_id);
int d2r_join_first_touch(const D2ResidencyRegion* r, D2ResidencyCounters* c,
                         uint64_t generation);
int d2r_finish_first_touch(D2ResidencyRegion* r, D2ResidencyCounters* c,
                           int success, uint64_t resident_bytes);
int d2r_contains(const D2ResidencyRegion* r, uint64_t generation,
                 uint64_t req_offset, uint64_t req_length, uint32_t codec);
int d2r_pin(D2ResidencyRegion* r);
int d2r_unpin(D2ResidencyRegion* r);
int d2r_demote_hot_to_warm(D2ResidencyRegion* r, D2ResidencyCounters* c);
int d2r_demote_warm_to_cold(D2ResidencyRegion* r, D2ResidencyCounters* c);
int d2r_parent_proof_pass(const D2ResidencyParentProof* p);
uint32_t d2r_top15_pass_mask(const D2ResidencyParentProof* p,
                             int single_owner, int generation_ok,
                             int first_touch_ok, int join_ok, int rollback_ok,
                             int range_ok, int codec_ok, int pin_ok,
                             int demotion_ok);
#ifdef __cplusplus
}
#endif
#endif
