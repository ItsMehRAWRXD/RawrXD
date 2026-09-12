/* BIND16 selftest — synthetic 16/16 + 72-byte guard. LIVE=NOT_RUN PROMOTE=0 */
#include "d2_engine_ssvk_bind16.h"
#include <cstdio>
#include <cstring>
#include <vector>

struct Mock {
    int fail = 0;
};

static int mock_run(void* u, const D2PackedProductRequest* r,
                    D2PackedProductProof* p) {
    auto* m = static_cast<Mock*>(u);
    if (!m || !r || !p || m->fail) return -1;
    memset(p, 0, sizeof(*p));
    p->gpu0_start_ns = 1000;
    p->gpu1_start_ns = 1100;
    p->gpu0_end_ns = 9000;
    p->gpu1_end_ns = 9050;
    p->gpu0_packed_bytes = 100000;
    p->gpu1_packed_bytes = 90000;
    p->overlap_ns = 7900;
    p->critical_path_ns = 8050;
    p->overlap_shorter_pm = 900;
    p->overlap_critical_pm = 980;
    p->product_linked = 1;
    p->packed_q2k_live = 1;
    p->material_same_token_overlap = 1;
    p->aggregate_bw_authority = 1;
    p->gpu0_real_forwards = 1;
    p->gpu1_real_forwards = 1;
    p->compact_merge_real = 1;
    p->output_parity = 1;
    return 0;
}

static int one_token(D2EngineSsVkBind16* b, uint64_t ord,
                     const std::vector<unsigned char>& w,
                     std::vector<float>& x, std::vector<float>& y) {
    D2GpuCounterSnapshot before{};
    before.forward_slot0 = ord * 2;
    before.forward_slot1 = ord * 2;
    d2bind16_begin_token(b, ord, &before);
    D2PackedProductRequest req{};
    req.packed_weights = w.data();
    req.input = x.data();
    req.output = y.data();
    req.rows = 8;
    req.cols = 3072;
    req.weight_bytes = w.size();
    req.tensor_name = "selftest.q2k";
    if (!d2bind16_dispatch_q2k(b, &req)) return 0;
    D2GpuCounterSnapshot after = before;
    after.forward_slot0 += 1;
    after.forward_slot1 += 1;
    d2bind16_end_forward(b, &after, 1);
    d2bind16_note_tail(b, 1, 1, 1, 1, 0);
    return d2bind16_commit_token(b);
}

int main() {
    Mock m{};
    D2EngineSsVkBind16 b;
    d2bind16_init(&b);
    d2bind16_bind(&b, &mock_run, &m);
    const size_t rows = 8, cols = 3072;
    const size_t rowBytes = (cols / 256) * D2_Q2K_BLOCK_BYTES;
    std::vector<unsigned char> w(rows * rowBytes);
    std::vector<float> x(cols), y(rows);

    for (uint64_t i = 1; i <= D2_BIND16_REQUIRED_TOKENS; ++i) {
        if (!one_token(&b, i, w, x, y)) {
            std::printf("BIND16_TOKEN_FAIL ord=%llu\n",
                        (unsigned long long)i);
            return 10;
        }
    }
    const D2Bind16Window* win = d2bind16_window(&b);
    if (!win || !win->authority || win->tokens_pass != 16) return 11;
    std::puts("BIND16_WINDOW_16_16=PASS");

    D2GpuCounterSnapshot snap{};
    d2bind16_begin_token(&b, 99, &snap);
    D2PackedProductRequest bad{};
    bad.packed_weights = w.data();
    bad.input = x.data();
    bad.output = y.data();
    bad.rows = rows;
    bad.cols = cols;
    bad.weight_bytes = rows * (cols / 256) * 72;
    if (d2bind16_dispatch_q2k(&b, &bad)) return 20;
    if (!d2bind16_token(&b)->stale_72_byte_path_used) return 21;
    std::puts("STALE_72_BYTE_GUARD=PASS");

    std::puts("CORE_SELFTEST=PASS");
    std::puts("LIVE_PRODUCT_RUN=NOT_RUN");
    std::puts("PROMOTE=0");
    return 0;
}
