#ifndef RAWRXD_R671_STREAM_H
#define RAWRXD_R671_STREAM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define R671_MAX_SLOTS 16u

typedef struct r671_slot {
    void*    view;
    uint64_t file_base;
    uint64_t view_bytes;
    uint64_t last_use;
    uint32_t pins;
    uint32_t valid;
} r671_slot;

typedef struct r671_stats {
    uint64_t acquire_calls;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t evictions;
    uint64_t newly_mapped_bytes;
    uint64_t reused_bytes;
    uint64_t mapped_bytes_current;
    uint64_t mapped_bytes_peak;
    uint64_t failed_acquires;
} r671_stats;

typedef struct r671_ctx {
#ifdef _WIN32
    void* file_handle;
    void* mapping_handle;
#else
    int fd;
#endif
    uint64_t file_bytes;
    uint64_t window_bytes;
    uint64_t granularity;
    uint64_t clock;
    volatile long lock_word;
    uint32_t slot_count;
    uint32_t open_ok;
    r671_slot slots[R671_MAX_SLOTS];
    r671_stats stats;
} r671_ctx;

typedef struct r671_lease {
    const uint8_t* ptr;
    uint64_t bytes;
    uint64_t file_offset;
    uint32_t slot;
    uint32_t valid;
} r671_lease;

/* Open a file-backed byte address space with a fixed number of mapped windows. */
int  r671_open(r671_ctx* ctx, const char* path, uint32_t slot_count, uint64_t window_bytes);

/* Acquire [file_offset, file_offset+bytes). One request must fit one window. */
int  r671_acquire(r671_ctx* ctx, uint64_t file_offset, uint64_t bytes, r671_lease* out);

/* Release a lease; the window stays cached until selected for reuse. */
void r671_release(r671_ctx* ctx, r671_lease* lease);

/* Close every view and backing handle. */
void r671_close(r671_ctx* ctx);

/* Copy counters without exposing internal slot state. */
void r671_get_stats(r671_ctx* ctx, r671_stats* out);

#ifdef __cplusplus
}
#endif
#endif
