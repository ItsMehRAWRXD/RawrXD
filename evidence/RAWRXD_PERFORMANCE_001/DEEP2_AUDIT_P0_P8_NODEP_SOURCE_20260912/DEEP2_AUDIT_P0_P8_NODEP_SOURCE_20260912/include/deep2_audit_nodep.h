#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum D2AuditStatus : uint32_t {
    D2_AUDIT_OPEN = 0,
    D2_AUDIT_SOURCE_WIRED = 1,
    D2_AUDIT_READY = 2,
    D2_AUDIT_PASS = 3,
    D2_AUDIT_HOLD = 4
};

enum D2StageId : uint32_t {
    D2_STAGE_TOKENIZE = 0,
    D2_STAGE_EMBED = 1,
    D2_STAGE_BLOCKS = 2,
    D2_STAGE_FINAL_NORM = 3,
    D2_STAGE_LM_HEAD = 4,
    D2_STAGE_SAMPLE = 5,
    D2_STAGE_KV_COMMIT = 6,
    D2_STAGE_COUNT = 7
};

struct D2AuthorityState {
    uint32_t full_model_tps_authority;      /* sealed externally */
    uint32_t daily_streamer_ready;
    uint32_t stage_timing_authority;
    uint32_t packed_q2k_ready;
    uint32_t deviceio_ssvk_ready;
    uint32_t aggregate_bw_authority;
    uint32_t missing15_ready;
    uint32_t model_size_next4_ready;
    uint32_t ide_sse_cancel_ready;
    uint32_t promote;
    uint32_t tip_climb;
};

/* P0: Daily streamer live bind. No ownership assumptions cross this ABI. */
struct D2EngineOps {
    void* ctx;
    int (*open_model)(void* ctx, const char* model_path, uint64_t* out_model_cookie);
    int (*generate)(void* ctx, uint64_t model_cookie, const char* prompt,
                    uint32_t max_tokens, volatile uint32_t* cancel_flag,
                    int (*on_token)(void* user, const char* bytes, uint32_t len),
                    void* user, uint64_t* out_generated_tokens);
    int (*reset_context)(void* ctx, uint64_t model_cookie);
    int (*close_model)(void* ctx, uint64_t model_cookie);
};

struct D2DailySession {
    D2EngineOps ops;
    uint64_t model_cookie;
    volatile uint32_t cancel_flag;
    uint32_t open;
    uint32_t generations_completed;
    uint32_t survived_cancel;
};

int d2_daily_bind(D2DailySession* s, const D2EngineOps* ops, const char* model_path);
int d2_daily_generate(D2DailySession* s, const char* prompt, uint32_t max_tokens,
                      int (*on_token)(void*, const char*, uint32_t), void* user,
                      uint64_t* out_generated_tokens);
int d2_daily_cancel(D2DailySession* s);
int d2_daily_reset(D2DailySession* s);
int d2_daily_close(D2DailySession* s);
int d2_daily_ready(const D2DailySession* s);

/* P1: same-path stage timing authority. */
struct D2StageClock {
    uint64_t begin_ticks[D2_STAGE_COUNT];
    uint64_t elapsed_ticks[D2_STAGE_COUNT];
    uint64_t tick_hz;
    uint32_t active_mask;
    uint32_t sample_count;
};

uint64_t d2_clock_ticks(void);
uint64_t d2_clock_hz(void);
int d2_stage_clock_init(D2StageClock* c);
int d2_stage_begin(D2StageClock* c, D2StageId id);
int d2_stage_end(D2StageClock* c, D2StageId id);
int d2_stage_ns(const D2StageClock* c, D2StageId id, uint64_t* out_ns);
int d2_stage_timing_authoritative(const D2StageClock* c, uint32_t same_cert_path,
                                  uint32_t synthetic_timing, uint32_t all_required_stages_seen);

/* P2: packed Q2_K tiled execution boundary. */
struct D2PackedTile {
    const void* packed;
    uint64_t packed_bytes;
    const float* x;
    uint32_t cols;
    float* y;
    uint32_t row_begin;
    uint32_t row_count;
    uint64_t scratch_bytes;
    uint64_t materialized_weight_bytes;
};

typedef int (*D2PackedQ2KExecuteFn)(void* ctx, const D2PackedTile* tile);
struct D2PackedQ2KOps { void* ctx; D2PackedQ2KExecuteFn execute; };
int d2_q2k_validate_tile(const D2PackedTile* t);
int d2_q2k_execute_tiled(const D2PackedQ2KOps* ops, const D2PackedTile* base,
                         uint32_t rows_per_tile, uint32_t total_rows);

/* P3/P4: opaque SsVk device I/O + same-token aggregate lanes. */
struct D2DeviceRange {
    uint32_t gpu;
    uint64_t offset;
    uint64_t bytes;
    uint32_t row_begin;
    uint32_t row_count;
};
struct D2SubmitTicket { uint64_t opaque[4]; };
struct D2LaneReceipt {
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t local_weight_bytes;
    uint64_t real_forwards;
    uint32_t device_lost;
    uint32_t synthetic_io;
};
struct D2MergeReceipt {
    uint64_t reduce_ns;
    uint64_t inter_gpu_bytes;
    uint32_t compact_merge_real;
};
struct D2SsVkOps {
    void* ctx;
    int (*load_exact)(void* ctx, const D2DeviceRange* range);
    int (*enqueue)(void* ctx, const D2DeviceRange* range, uint64_t token_id, D2SubmitTicket* out);
    int (*collect)(void* ctx, const D2SubmitTicket* ticket, D2LaneReceipt* out);
    int (*reduce)(void* ctx, const D2SubmitTicket* a, const D2SubmitTicket* b, D2MergeReceipt* out);
};
struct D2AggregateMetrics {
    uint64_t overlap_ns;
    uint64_t critical_path_ns;
    uint64_t aggregate_effective_bps;
    uint64_t gpu0_local_bytes;
    uint64_t gpu1_local_bytes;
    uint64_t gpu0_real_forwards;
    uint64_t gpu1_real_forwards;
    uint64_t inter_gpu_bytes;
    uint32_t overlap_measured;
    uint32_t serial_chain;
    uint32_t device_lost;
    uint32_t synthetic_io;
    uint32_t compact_merge_real;
};
int d2_ssvk_validate(const D2SsVkOps* ops);
int d2_dual_submit(const D2SsVkOps* ops, const D2DeviceRange* lane0,
                   const D2DeviceRange* lane1, uint64_t token_id,
                   D2AggregateMetrics* out);
int d2_aggregate_authoritative(const D2AggregateMetrics* m,
                               uint32_t product_linked, uint32_t q2k_real,
                               uint32_t deviceio_real);

/* P5: Missing15 conjunction; no individual source may mint promotion. */
struct D2Missing15Bits { uint32_t bit[15]; };
int d2_missing15_all(const D2Missing15Bits* b);

/* P6: NEXT4 model-size independence checks. */
struct D2Next4State {
    uint32_t residency_solver;
    uint32_t packed_execution;
    uint32_t predictive_expert_cache;
    uint32_t adaptive_kv;
    uint64_t materialized_weight_bytes;
    uint64_t critical_path_nvme_reads_per_token;
};
int d2_next4_ready(const D2Next4State* s);

/* P7: IDE SSE stream + cancel, transport-agnostic byte sink. */
struct D2SseSink {
    void* ctx;
    int (*write_bytes)(void* ctx, const void* data, uint32_t bytes);
    volatile uint32_t* cancel_flag;
};
int d2_sse_emit_event(D2SseSink* sink, const char* event_name, const char* data, uint32_t data_len);
int d2_sse_emit_done(D2SseSink* sink);
int d2_cancel_requested(const volatile uint32_t* flag);

/* P8: promotion/TIP authority remains conjunctive and fail-closed. */
int d2_compute_promotion(const D2AuthorityState* s, uint32_t explicit_promote_request);
int d2_compute_tip_climb(const D2AuthorityState* s, uint32_t explicit_tip_request);

/* Current externally-sealed baseline is carried, never re-minted here. */
int d2_apply_external_full_tps_authority(D2AuthorityState* s, uint32_t sealed_authority);

#ifdef __cplusplus
}
#endif
