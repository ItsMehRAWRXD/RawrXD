#ifndef D2_LOCALITY_H
#define D2_LOCALITY_H
#include "d2_common.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2ExpertStat {
    uint64_t last_token;
    uint64_t hits;
    uint64_t resident_bytes[D2_MAX_DEVICES];
    uint32_t resident_mask;
    uint32_t selected_now;
} D2ExpertStat;
typedef struct D2Locality {
    D2ExpertStat expert[D2_MAX_EXPERTS];
    uint64_t token;
} D2Locality;
void d2_locality_init(D2Locality *l);
int d2_locality_observe(D2Locality *l, const uint32_t *ids, size_t n, uint64_t token);
uint64_t d2_locality_score(const D2Locality *l, uint32_t expert_id, uint32_t device, uint64_t bytes);
int d2_locality_mark_resident(D2Locality *l, uint32_t expert_id, uint32_t device, uint64_t bytes, int resident);
#ifdef __cplusplus
}
#endif
#endif
