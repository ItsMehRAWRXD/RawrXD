#ifndef DEEP2_ENDURANCE_H
#define DEEP2_ENDURANCE_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#define D2_OK 0
#define D2_EINVAL (-1)
#define D2_EBOUNDS (-2)
#define D2_ESTATE (-3)
#define D2_ECAP (-4)
#define D2_EIO (-5)
#define D2_ESTALL (-6)
#define D2_ECORRUPT (-7)

#define D2_CANARY_A UINT64_C(0xD22D22D22D22D22D)
#define D2_CANARY_B UINT64_C(0x2DD22DD22DD22DD2)

typedef struct {
    uint64_t target_tokens;
    uint64_t forward_calls;
    uint64_t full_block_forward_calls;
    uint64_t commit_calls;
    uint64_t advance_calls;
    uint64_t generated_tokens;
    uint64_t sealed_logits_reuse_count;
    uint64_t expected_position;
    int device_lost;
    int token0_full_forward_real;
    int stopped;
    char stop_reason[96];
} D2DecodeInvariant;
int d2_inv_init(D2DecodeInvariant *s, uint64_t target_tokens);
int d2_inv_forward(D2DecodeInvariant *s, uint64_t pos, int full_real, int sealed_reuse);
int d2_inv_commit(D2DecodeInvariant *s, uint64_t pos);
int d2_inv_advance(D2DecodeInvariant *s, uint64_t new_pos);
int d2_inv_device_result(D2DecodeInvariant *s, int device_lost, const char *reason);
int d2_inv_finalize(D2DecodeInvariant *s);

typedef struct {
    uint8_t *base;
    size_t capacity;
    size_t used;
    size_t high_water;
    uint64_t canary_a;
    uint64_t canary_b;
    int frozen;
} D2Arena;
int d2_arena_init(D2Arena *a, void *mem, size_t bytes);
void *d2_arena_alloc(D2Arena *a, size_t bytes, size_t align);
int d2_arena_freeze(D2Arena *a);
int d2_arena_check(const D2Arena *a);
void d2_arena_reset(D2Arena *a);

typedef struct {
    uint32_t layers;
    uint32_t max_positions;
    uint64_t epoch;
    uint64_t *written_bits;
    size_t written_words;
} D2KvGuard;
size_t d2_kv_words_required(uint32_t layers, uint32_t max_positions);
int d2_kv_init(D2KvGuard *k, uint32_t layers, uint32_t max_positions, uint64_t epoch,
               uint64_t *storage_words, size_t storage_word_count);
int d2_kv_mark_write(D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t epoch);
int d2_kv_require_read(const D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t epoch);
int d2_kv_reset(D2KvGuard *k, uint64_t new_epoch);

typedef struct {
    uint32_t shard_id;
    uint64_t offset;
    uint64_t bytes;
    uint32_t codec;
    uint32_t dims[4];
    uint32_t ndims;
} D2TensorRange;
int d2_range_validate(const D2TensorRange *r, uint64_t shard_size);
int d2_range_contains(const D2TensorRange *r, uint64_t off, uint64_t bytes);

typedef enum { D2_COLD=0, D2_WARM=1, D2_HOT=2 } D2ResidencyState;
typedef struct {
    uint64_t key;
    uint64_t bytes;
    uint64_t epoch;
    uint32_t pin_count;
    D2ResidencyState state;
} D2ResidencyEntry;
typedef struct {
    D2ResidencyEntry *entries;
    size_t capacity;
    size_t count;
    uint64_t hot_budget;
    uint64_t warm_budget;
    uint64_t hot_bytes;
    uint64_t warm_bytes;
} D2Residency;
int d2_res_init(D2Residency *r, D2ResidencyEntry *entries, size_t capacity,
                uint64_t warm_budget, uint64_t hot_budget);
int d2_res_admit(D2Residency *r, uint64_t key, uint64_t bytes, uint64_t epoch, D2ResidencyState state);
int d2_res_pin(D2Residency *r, uint64_t key, uint64_t epoch);
int d2_res_unpin(D2Residency *r, uint64_t key, uint64_t epoch);
int d2_res_evict_unpinned(D2Residency *r, D2ResidencyState from_state, uint64_t bytes_needed);
int d2_res_check(const D2Residency *r);

typedef struct { uint64_t begin, end; uint64_t epoch; uint32_t shard_id; } D2RangeReq;
typedef struct {
    D2RangeReq *items;
    size_t cap, head, tail, count;
} D2RangeQueue;
int d2_rq_init(D2RangeQueue *q, D2RangeReq *items, size_t cap);
int d2_rq_push(D2RangeQueue *q, const D2RangeReq *r);
int d2_rq_pop(D2RangeQueue *q, D2RangeReq *out);

typedef struct { uint64_t epoch; } D2Epoch;
uint64_t d2_epoch_begin(D2Epoch *e);
int d2_epoch_check(const D2Epoch *e, uint64_t observed);

typedef struct {
    uint64_t creates, destroys, live, peak_live;
} D2Lifetime;
void d2_life_init(D2Lifetime *l);
int d2_life_create(D2Lifetime *l);
int d2_life_destroy(D2Lifetime *l);
int d2_life_finalize(const D2Lifetime *l);

typedef enum { D2_SLOT_FREE=0, D2_SLOT_SUBMITTED=1, D2_SLOT_SIGNALED=2 } D2SlotState;
typedef struct { uint64_t serial; D2SlotState state; } D2FenceSlot;
typedef struct { D2FenceSlot *slots; size_t n; uint64_t next_serial; } D2FenceRing;
int d2_fence_init(D2FenceRing *r, D2FenceSlot *slots, size_t n);
int d2_fence_acquire(D2FenceRing *r, size_t *slot, uint64_t *serial);
int d2_fence_signal(D2FenceRing *r, size_t slot, uint64_t serial);
int d2_fence_recycle(D2FenceRing *r, size_t slot, uint64_t serial);

typedef struct { uint64_t generation; int in_use; } D2DescriptorSlot;
typedef struct { D2DescriptorSlot *slots; size_t n; } D2DescriptorRing;
int d2_desc_init(D2DescriptorRing *r, D2DescriptorSlot *slots, size_t n);
int d2_desc_acquire(D2DescriptorRing *r, uint64_t generation, size_t *slot);
int d2_desc_release(D2DescriptorRing *r, size_t slot, uint64_t generation);

typedef struct {
    int last_result;
    uint64_t submit_serial;
    uint64_t complete_serial;
    int device_lost;
    char owner[64];
} D2DeviceHealth;
void d2_health_init(D2DeviceHealth *h);
void d2_health_submit(D2DeviceHealth *h, uint64_t serial);
void d2_health_complete(D2DeviceHealth *h, uint64_t serial, int result, const char *owner);
int d2_health_check(const D2DeviceHealth *h);

typedef struct { uint64_t last_serial; uint64_t stagnant_ticks; uint64_t max_stagnant_ticks; } D2ProgressWatch;
void d2_watch_init(D2ProgressWatch *w, uint64_t max_stagnant_ticks);
int d2_watch_tick(D2ProgressWatch *w, uint64_t complete_serial);

uint64_t d2_hash64(const void *data, size_t n, uint64_t seed);
uint64_t d2_state_digest(uint64_t token, uint64_t pos, uint64_t epoch,
                         uint64_t forward_calls, uint64_t commit_calls, uint64_t residency_bytes);

typedef struct {
    uint64_t count, min_ns, max_ns;
    long double sum_ns;
    uint64_t buckets[32];
} D2LongStats;
void d2_stats_init(D2LongStats *s);
void d2_stats_add(D2LongStats *s, uint64_t ns);
uint64_t d2_stats_mean(const D2LongStats *s);
uint64_t d2_stats_p50_approx(const D2LongStats *s);

typedef struct { FILE *fp; uint64_t records; } D2Journal;
int d2_journal_open(D2Journal *j, const char *path);
int d2_journal_record(D2Journal *j, const char *key, const char *value);
int d2_journal_record_u64(D2Journal *j, const char *key, uint64_t value);
int d2_journal_close(D2Journal *j);

int d2_scan_forbidden_symbols(const char *path, const char *const *symbols, size_t symbol_count,
                              size_t *matches);

#ifdef __cplusplus
}
#endif
#endif
