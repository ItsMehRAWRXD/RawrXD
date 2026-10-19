#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    R671_OK = 0,
    R671_E_INVALID = 1,
    R671_E_OPEN = 2,
    R671_E_SIZE = 3,
    R671_E_MAPPING = 4,
    R671_E_VIEW = 5,
    R671_E_RANGE = 6,
    R671_E_STATE = 7
};

typedef struct R671Context {
    void*    file_handle;
    void*    mapping_handle;
    uint64_t file_bytes;
    uint64_t allocation_gran;
    uint64_t acquire_count;
    uint64_t failed_acquires;
    uint64_t release_count;
    uint64_t live_leases;
    uint64_t mapped_bytes_live;
    uint64_t mapped_bytes_peak;
    uint64_t newly_mapped_bytes;
} R671Context;

typedef struct R671Lease {
    void*    view_base;
    uint64_t view_bytes;
    void*    data_ptr; /* lease operand source; MapViewOfFile-derived */
    uint64_t bytes;
    uint64_t request_offset;
    uint64_t aligned_offset;
    uint64_t delta;
    uint64_t generation_id;
    uint64_t active;
} R671Lease;

typedef struct R671TensorDesc {
    uint64_t file_offset;
    uint64_t byte_length;
    uint64_t element_count;
    uint64_t element_bytes;
    uint32_t tensor_type;
    uint32_t reserved;
} R671TensorDesc;

typedef struct R671PrimitiveResult {
    uint64_t elements_consumed;
    uint64_t nonfinite_count;
    uint64_t checksum_u64;
    uint32_t scalar_f32_bits;
    uint32_t status;
} R671PrimitiveResult;

int r671_open(const char* path_utf8_ascii, R671Context* ctx);
int r671_tensor_acquire(
    R671Context* ctx,
    uint64_t file_offset,
    uint64_t byte_length,
    uint64_t generation_id,
    R671Lease* lease);
int r671_release(R671Context* ctx, R671Lease* lease);
int r671_close(R671Context* ctx);

int Deep2R671TensorPrimitive(
    const R671Lease* lease,
    const R671TensorDesc* desc,
    R671PrimitiveResult* out);

#ifdef __cplusplus
}
#endif
