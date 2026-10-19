#ifndef D2_COMMON_H
#define D2_COMMON_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define D2_OK 0
#define D2_EINVAL -1
#define D2_ENOSPC -2
#define D2_ENOTFOUND -3
#define D2_ESTATE -4
#define D2_EIO -5
#define D2_MAX_DEVICES 2u
#define D2_MAX_EXPERTS 1024u
#define D2_MAX_SELECTED 64u
#define D2_MAX_RANGES 256u
#define D2_MAX_RESIDENT 2048u
#define D2_STREAM_CAP 512u

typedef struct D2ByteRange {
    uint32_t shard;
    uint32_t codec;
    uint64_t offset;
    uint64_t bytes;
    uint64_t tensor_id;
    uint32_t expert_id;
    uint32_t role;
} D2ByteRange;

typedef struct D2ObservedCounters {
    uint64_t exact_range_requests;
    uint64_t exact_range_bytes;
    uint64_t queue_push;
    uint64_t queue_pop;
    uint64_t device_load_ok[D2_MAX_DEVICES];
    uint64_t device_load_fail[D2_MAX_DEVICES];
    uint64_t evictions[D2_MAX_DEVICES];
    uint64_t locality_hits[D2_MAX_DEVICES];
    uint64_t locality_misses[D2_MAX_DEVICES];
    uint64_t cross_device_bytes;
} D2ObservedCounters;
#ifdef __cplusplus
}
#endif
#endif
