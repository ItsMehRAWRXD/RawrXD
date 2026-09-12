#include <stdio.h>
#include <string.h>
#include "d2_engine_ssvk_decode_bind.h"
#include "d2_persistent_decode_gate.h"
#include "d2_daily_streamer_live.h"
#include "d2_endurance_gate.h"

typedef struct Mock {
    uint64_t token;
    int model_open;
} Mock;

static void safe(D2DecodeReceipt* r) {
    r->aggregate_bw_authority = 1;
    r->product_linked = 1;
    r->packed_q2k_live = 1;
    r->material_same_token_overlap = 1;
    r->full_model_forward = 1;
    r->final_norm_real = 1;
    r->lm_head_real = 1;
    r->sampler_commit_real = 1;
    r->kv_advance_real = 1;
    r->output_parity = 1;
}

static int prep(void* u) { (void)u; return 0; }
static int begin(void* u, uint64_t i) { ((Mock*)u)->token = i; return 0; }
static int fwd(void* u, uint64_t i, D2DecodeReceipt* r) {
    (void)u; (void)i; safe(r);
    r->critical_path_ns = 9000000;
    r->overlap_ns = 8200000;
    r->finish_skew_ns = 100000;
    r->packed_bytes_gpu0 = 134184960;
    r->packed_bytes_gpu1 = 130056192;
    return 0;
}
static int head(void* u, uint64_t i, D2DecodeReceipt* r) {
    (void)u; (void)i; r->final_norm_real = 1; r->lm_head_real = 1; return 0;
}
static int sample(void* u, uint64_t i, uint32_t* tok, const char** s, size_t* n, D2DecodeReceipt* r) {
    static const char x[] = "x";
    (void)u; *tok = (uint32_t)(i + 1); *s = x; *n = 1; r->sampler_commit_real = 1; return 0;
}
static int kva(void* u, uint64_t i, uint32_t tok, D2DecodeReceipt* r) {
    (void)u; (void)i; (void)tok; r->kv_advance_real = 1; return 0;
}
static int prefetch(void* u, uint64_t i) { (void)u; (void)i; return 0; }
static int resetctx(void* u) { ((Mock*)u)->token = 0; return 0; }

static int openm(void* u, const char* p) { (void)p; ((Mock*)u)->model_open=1; return 0; }
static int closem(void* u) { ((Mock*)u)->model_open=0; return 0; }
static int prefill(void* u, const char* p, size_t n) { (void)u;(void)p;(void)n;return 0; }
static int emit(void* u, uint32_t t, const char* s, size_t n) { (void)u;(void)t;(void)s;(void)n;return 0; }

int main(void) {
    Mock m = {0};
    D2DecodeBindOps bo = {&m, prep, begin, fwd, head, sample, kva, prefetch, resetctx};
    D2DecodeBind bind;
    D2PersistentGate pg;
    D2DailyOps dop = {&m, openm, closem, prefill, emit};
    D2DailyStreamer ds;
    D2EndurancePlan plan = {"model.gguf", "hello", 5, 16, 2, 1, 0};
    D2EnduranceReport rep;

    if (d2_decode_bind_open(&bind, &bo) != D2X_OK) return 10;

    d2_persistent_gate_init(&pg, &bind, 16);
    if (d2_persistent_gate_run(&pg) != D2X_OK) return 11;
    if (!d2_persistent_gate_pass(&pg)) return 12;
    printf("DECODE_BIND_PERSISTENT_SELFTEST=PASS TOKENS=%llu\n",
           (unsigned long long)pg.pass_tokens);

    if (d2_decode_bind_reset(&bind) != D2X_OK) return 20;
    if (d2_daily_init(&ds, &bind, &dop) != D2X_OK) return 21;
    if (d2_endurance_run(&ds, &plan, 1, &rep) != D2X_OK) return 22;
    if (!d2_endurance_pass(&rep)) return 23;

    printf("DAILY_STREAMER_ENDURANCE_SELFTEST=PASS TOKENS=%llu GENS=%llu\n",
           (unsigned long long)rep.tokens,
           (unsigned long long)rep.generations);
    printf("CORE_SELFTEST=PASS\n");
    printf("LIVE_PRODUCT_RUN=NOT_RUN\n");
    printf("PROMOTE=0\n");
    return 0;
}
