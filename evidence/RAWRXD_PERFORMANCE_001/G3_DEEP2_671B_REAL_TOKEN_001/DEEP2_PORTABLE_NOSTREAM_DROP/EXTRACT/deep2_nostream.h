#ifndef DEEP2_NOSTREAM_H
#define DEEP2_NOSTREAM_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define D2NS_OK 0
#define D2NS_E_ARG -1
#define D2NS_E_RANGE -2
#define D2NS_E_BUDGET -3
#define D2NS_E_LOAD -4
#define D2NS_E_SIZE -5
#define D2NS_E_DUP -6
#define D2NS_E_STRICT_MISS -7
#define D2NS_PHASE_PROMPT 1u
#define D2NS_PHASE_DECODE 2u
#define D2NS_PHASE_FAILED 3u
#define D2NS_F_STRICT_PROMPT 1u
#define D2NS_F_PIN_PROMPT 2u
#define D2NS_MAX_TOPK 16u

typedef int (*d2ns_measure_fn)(void*,uint64_t,uint64_t*);
typedef int (*d2ns_load_fn)(void*,uint64_t,uint64_t,uint64_t*,uint64_t*);
typedef void (*d2ns_release_fn)(void*,uint64_t,uint64_t);
typedef struct { d2ns_measure_fn measure; d2ns_load_fn load; d2ns_release_fn release; void *user; } d2ns_cb;
typedef struct { uint64_t handle,bytes; uint32_t hits,last_token; uint8_t resident,prompt_seen,pinned,reserved; } d2ns_slot;
typedef struct {
 uint32_t moe_layers,experts_per_layer,top_k,flags,phase,prompt_tokens;
 uint64_t budget,resident_bytes,loads,hits,misses,sync_loads,background_submits;
 d2ns_cb cb; d2ns_slot *slots; uint64_t slot_count;
} d2ns_ctx;
typedef struct { uint64_t handles[D2NS_MAX_TOPK]; uint32_t count,loaded_now; } d2ns_route;
size_t d2ns_slots_bytes(uint32_t layers,uint32_t experts);
int d2ns_init(d2ns_ctx*,uint32_t,uint32_t,uint32_t,uint32_t,uint64_t,const d2ns_cb*,void*,size_t);
int d2ns_require_object(d2ns_ctx*,uint64_t,uint32_t,uint64_t*);
int d2ns_require_route(d2ns_ctx*,uint32_t,uint32_t,const uint32_t*,uint32_t,d2ns_route*);
int d2ns_seal_prompt(d2ns_ctx*,uint32_t);
void d2ns_release_object(d2ns_ctx*,uint64_t);
void d2ns_release_all(d2ns_ctx*);
#ifdef __cplusplus
}
#endif
#endif
