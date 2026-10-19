#ifndef RAWRXD_R671_DEEP2_BRIDGE_H
#define RAWRXD_R671_DEEP2_BRIDGE_H
#include "r671_stream.h"

/*
  Deep2 tensor metadata already knows a tensor's file offset and byte length.
  Use this bridge at the point where the forward path needs bytes.

  No std::vector materialization is required here.
*/
typedef struct r671_tensor_ref {
    uint64_t file_offset;
    uint64_t byte_length;
} r671_tensor_ref;

static int r671_tensor_acquire(
    r671_ctx* stream,
    const r671_tensor_ref* tensor,
    uint64_t tensor_byte_offset,
    uint64_t byte_count,
    r671_lease* lease)
{
    if (!stream || !tensor || !lease) return 0;
    if (tensor_byte_offset > tensor->byte_length) return 0;
    if (byte_count > tensor->byte_length - tensor_byte_offset) return 0;
    return r671_acquire(stream, tensor->file_offset + tensor_byte_offset, byte_count, lease);
}

#endif
