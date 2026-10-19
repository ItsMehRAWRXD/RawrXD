#include <stdio.h>
#include <string.h>
#include "deep2_decode_finish_balance.h"
#include "deep2_persistent_decode.h"
#include "deep2_residency_solver.h"
#include "deep2_streamer_live.h"
#include "deep2_endurance.h"

typedef struct Mock {
uint64_t token;
uint32_t opened;
uint32_t prepared;
uint32_t kv;
} Mock;

static void fill_safe_timing(D2TokenTiming* t, uint64_t token) {
memset(t, 0, sizeof(*t));
t->token_index = token;
t->gpu0_start_ns = 1000000 + token * 10000;
t->gpu1_start_ns = 1020000 + token * 10000;
t->gpu0_end_ns = 5800000 + token * 10000;
t->gpu1_end_ns = 6000000 + token * 10000;
t->gpu0_work_units = 5500;
t->gpu1_work_units = 2692;
t->gpu0_packed_bytes = 5500 * 84;
t->gpu1_packed_bytes = 2692 * 84;
t->product_linked = 1;
t->packed_q2k_live = 1;
t->output_parity = 1;
t->material_same_token_overlap = 1;
d2_finalize_timing(t);
}

static int prep(void* u) { ((Mock*)u)->prepared = 1; return 0; }
static int kv(void* u, uint64_t maxctx) { (void)maxctx; ((Mock*)u)->kv = 1; return 0; }
static int prefetch(void* u, uint64_t t) { (void)u; (void)t; return 0; }
static int exec_tok(void* u, uint64_t t, D2TokenTiming* out) {
(void)u; fill_safe_timing(out, t); return 0;
}
static int advkv(void* u, uint64_t t) { ((Mock*)u)->token = t + 1; return 0; }
static int resetpd(void* u) { ((Mock*)u)->token = 0; return 0; }

static int openm(void* u, const char* p) { (void)p; ((Mock*)u)->opened = 1; return 0; }
static int closem(void* u) { ((Mock*)u)->opened = 0; return 0; }
static int resetm(void* u) { ((Mock*)u)->token = 0; return 0; }
static int prefill(void* u, const char* p, size_t n) { (void)u; (void)p; (void)n; return 0; }
static int decode(void* u, uint64_t ti, uint32_t* id, const char** s, size_t* n, D2TokenTiming* out) {
static const char x[] = "x";
(void)u;
*id = (uint32_t)ti;
*s = x;
*n = 1;
fill_safe_timing(out, ti);
return 0;
}
static int emit(void* u, const char* s, size_t n) { (void)u; (void)s; (void)n; return 0; }

int main(void) {
D2DecodeBalancer b;
D2DecodeBalancerConfig bc = {8192, 16, 57344, 3277, 68813};
D2TokenTiming t;
uint64_t w0, w1;
Mock m = {0};

D2PersistentDecode pd;
D2PersistentDecodeOps po = {&m, prep, kv, prefetch, exec_tok, advkv, resetpd};

D2ResidencyNode nodes[4] = {
    {1, 512ull<<20, 1000, D2_RES_ALLOW_GPU0|D2_RES_ALLOW_GPU1|D2_RES_HOT_EXEC, 0},
    {2, 512ull<<20, 900,  D2_RES_ALLOW_GPU0|D2_RES_ALLOW_GPU1|D2_RES_HOT_EXEC, 1},
    {3, 4ull<<30,   800,  D2_RES_ALLOW_GPU0|D2_RES_ALLOW_GPU1|D2_RES_KV|D2_RES_PIN_GPU0, 0},
    {4, 32ull<<30,  1,    D2_RES_ALLOW_RAM|D2_RES_ALLOW_MMAP|D2_RES_COLD_OK, UINT32_MAX}
};
D2ResidencyCapacity cap = {16ull<<30, 16ull<<30, 48ull<<30};
D2ResidencyPlacement pl[4];
D2ResidencyResult rr;

D2Streamer st;
D2StreamerOps so = {&m, openm, closem, resetm, prefill, decode, emit};
D2EnduranceCase ec = {"mock.gguf", "hi", 2, 16, 2, 1};
D2EnduranceResult er;

if (d2_balance_init(&b, &bc, 5500) != D2_OK) return 10;
fill_safe_timing(&t, 0);
if (d2_balance_observe_and_plan(&b, &t, &w0, &w1) != D2_OK) return 11;
if (w0 + w1 != 8192) return 12;
printf("BALANCER_SELFTEST=PASS W0=%llu W1=%llu\n",
       (unsigned long long)w0, (unsigned long long)w1);

if (d2_pd_open(&pd, &po, 128) != D2_OK) return 20;
for (int i = 0; i < 16; ++i) {
    D2TokenTiming q;
    if (d2_pd_step(&pd, &q) != D2_OK) return 21;
}
if (!d2_pd_authority_ready(&pd)) return 22;
printf("PERSISTENT_DECODE_SELFTEST=PASS TOKENS=%llu\n",
       (unsigned long long)pd.tokens_executed);

if (d2_residency_plan(nodes, 4, &cap, pl, &rr) != D2_OK) return 30;
if (!rr.fit || rr.full_materialization_required || rr.critical_path_mmap_required) return 31;
printf("RESIDENCY_SELFTEST=PASS GPU0=%llu GPU1=%llu RAM=%llu MMAP=%llu\n",
       (unsigned long long)rr.gpu0_used,
       (unsigned long long)rr.gpu1_used,
       (unsigned long long)rr.ram_used,
       (unsigned long long)rr.mmap_backed);

if (d2_streamer_init(&st, &so) != D2_OK) return 40;
if (d2_run_endurance(&st, &ec, 1, &er) != D2_OK) return 41;
if (!d2_endurance_pass(&er)) return 42;
printf("STREAMER_ENDURANCE_SELFTEST=PASS TOKENS=%llu GENS=%llu\n",
       (unsigned long long)er.tokens_generated,
       (unsigned long long)er.generations_run);

printf("CORE_SELFTEST=PASS\n");
printf("LIVE_PRODUCT_RUN=NOT_RUN\n");
printf("PROMOTE=0\n");
return 0;

}
