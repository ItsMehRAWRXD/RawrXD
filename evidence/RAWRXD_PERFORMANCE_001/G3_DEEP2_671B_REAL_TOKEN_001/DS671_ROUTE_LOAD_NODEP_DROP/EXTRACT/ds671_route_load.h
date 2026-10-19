#ifndef RAWRXD_DS671_ROUTE_LOAD_H
#define RAWRXD_DS671_ROUTE_LOAD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DS671_OK                 0
#define DS671_E_ARG             -1
#define DS671_E_ARENA           -2
#define DS671_E_STATE           -3
#define DS671_E_RANGE           -4
#define DS671_E_BUDGET          -5
#define DS671_E_LOAD            -6
#define DS671_E_SIZE_MISMATCH   -7
#define DS671_E_DECODE_MISS     -8
#define DS671_E_DUPLICATE       -9

#define DS671_MODE_STRICT_PROMPT_ONLY  1u
#define DS671_MODE_GROW_NO_EVICT       2u

#define DS671_PHASE_UNINIT 0u
#define DS671_PHASE_PROMPT 1u
#define DS671_PHASE_DECODE 2u
#define DS671_PHASE_FAILED 3u

typedef int (*ds671_measure_expert_fn)(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t *bytes_out);

typedef int (*ds671_load_expert_fn)(
    void *user, uint32_t moe_layer, uint32_t expert_id,
    uint64_t expected_bytes, uint64_t *handle_out, uint64_t *actual_bytes_out);

typedef void (*ds671_release_expert_fn)(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t handle);

typedef struct ds671_callbacks {
    ds671_measure_expert_fn measure;
    ds671_load_expert_fn load;
    ds671_release_expert_fn release;
    void *user;
} ds671_callbacks;

typedef struct ds671_config {
    uint32_t moe_layers;
    uint32_t experts_per_layer;
    uint32_t top_k;
    uint32_t mode;
    uint64_t routed_expert_budget_bytes;
} ds671_config;

typedef struct ds671_expert_state {
    uint64_t handle;
    uint64_t bytes;
    uint32_t hits;
    uint32_t last_token;
    uint8_t resident;
    uint8_t prompt_seen;
    uint8_t reserved0;
    uint8_t reserved1;
} ds671_expert_state;

typedef struct ds671_ctx {
    ds671_config cfg;
    ds671_callbacks cb;
    ds671_expert_state *states;
    uint64_t state_count;
    uint64_t resident_bytes;
    uint64_t loads;
    uint64_t hits;
    uint64_t misses;
    uint64_t prompt_unique;
    uint64_t decode_unique;
    uint32_t phase;
    uint32_t sealed_prompt_tokens;
} ds671_ctx;

typedef struct ds671_route_result {
    uint64_t handles[16];
    uint32_t count;
    uint32_t loaded_now;
} ds671_route_result;

size_t ds671_arena_bytes(uint32_t moe_layers, uint32_t experts_per_layer);

int ds671_init(
    ds671_ctx *ctx, const ds671_config *cfg, const ds671_callbacks *cb,
    void *arena, size_t arena_bytes);

int ds671_require_route(
    ds671_ctx *ctx, uint32_t token_index, uint32_t moe_layer,
    const uint32_t *expert_ids, uint32_t count, ds671_route_result *out);

int ds671_seal_prompt(ds671_ctx *ctx, uint32_t prompt_tokens);

int ds671_get_handle(
    const ds671_ctx *ctx, uint32_t moe_layer, uint32_t expert_id,
    uint64_t *handle_out);

void ds671_release_all(ds671_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif
