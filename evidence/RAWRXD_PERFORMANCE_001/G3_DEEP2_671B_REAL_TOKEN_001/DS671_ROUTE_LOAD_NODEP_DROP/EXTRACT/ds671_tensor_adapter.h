#ifndef RAWRXD_DS671_TENSOR_ADAPTER_H
#define RAWRXD_DS671_TENSOR_ADAPTER_H
/*
  DS671 measure/load/release adapter over a GGUF tensor index.
  Names match Deep2 MoEWeightsLoader / K2MoEWeights / DeepSeekMoELoader:
    blk.{L}.ffn_gate_exps.weight
    blk.{L}.ffn_up_exps.weight
    blk.{L}.ffn_down_exps.weight
  Expert axis = last GGUF dim. moe_layer + leading_dense = blk layer.
*/
#include "ds671_route_load.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DS671_PROJ_GATE 0u
#define DS671_PROJ_UP   1u
#define DS671_PROJ_DOWN 2u

typedef struct ds671_proj_slot {
    uint32_t blk_layer;
    uint32_t proj;              /* GATE/UP/DOWN */
    uint32_t shard_index;
    uint32_t num_experts;
    uint32_t ggml_type;
    uint64_t file_offset;       /* absolute offset to stacked tensor start */
    uint64_t bytes_per_expert;
} ds671_proj_slot;

typedef struct ds671_tensor_adapter {
    const char *const *shard_paths;
    uint32_t shard_count;
    ds671_proj_slot *slots;
    uint32_t slot_count;
    uint32_t leading_dense;     /* DeepSeek-R1 COMPLETE: 3 */
    uint32_t experts_per_layer; /* 256 */
} ds671_tensor_adapter;

uint32_t ds671_blk_from_moe(const ds671_tensor_adapter *a, uint32_t moe_layer);
int ds671_format_exps_name(char *out, size_t cap, uint32_t blk, uint32_t proj);

uint64_t ds671_ggml_bytes_per_expert(
    uint32_t ggml_type, const uint64_t *dims, uint32_t ndims);

const ds671_proj_slot *ds671_find_proj(
    const ds671_tensor_adapter *a, uint32_t blk, uint32_t proj);

int ds671_adapter_measure(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t *bytes_out);
int ds671_adapter_load(
    void *user, uint32_t moe_layer, uint32_t expert_id,
    uint64_t expected_bytes, uint64_t *handle_out, uint64_t *actual_bytes_out);
void ds671_adapter_release(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t handle);

void ds671_adapter_fill_callbacks(
    ds671_callbacks *cb, ds671_tensor_adapter *adapter);

#ifdef __cplusplus
}
#endif
#endif
