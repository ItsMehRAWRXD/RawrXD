#ifndef RAWRXD_DS671_GGUF_INDEX_H
#define RAWRXD_DS671_GGUF_INDEX_H
#include "ds671_tensor_adapter.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Scan one GGUF shard; append gate/up/down_exps slots into slots[].
   data_offset = aligned data section start (returned). */
int ds671_gguf_scan_shard_exps(
    const char *path, uint32_t shard_index,
    ds671_proj_slot *slots, uint32_t cap, uint32_t *count_io,
    uint64_t *data_offset_out);
#ifdef __cplusplus
}
#endif
#endif
