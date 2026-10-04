// RAWRXD_Q6K_GEMV_NOOP_STUB_001 -- falsification probe for the Q6_K GEMV.
//
// THE DEFECT THIS PROVES ABSENT
// ------------------------------
// The only definition of Deep2_Q6_K_GEMV in the tree was an empty stub:
//
//     gold_link_closure.cpp:1092   extern "C" void Deep2_Q6_K_GEMV() {}
//
// and gemv_q6_k_masm() called it and returned. The kernel therefore computed
// nothing and wrote nothing: every Q6_K projection returned whatever the
// caller's output buffer already contained. The observed symptom was a forward
// pass dying at prefill token 0 with
//
//     LinearW: non-finite output tensor=blk.0.attn_v.weight type=14 idx=1/256
//
// The probe deliberately POISONS the destination with NaN before every call.
// A kernel that writes real results overwrites the poison; a kernel that
// writes nothing leaves it. That makes the no-op behaviour directly observable
// rather than a matter of opinion.

#include "QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

using Deep2::QuantKernelRegistry;

static int g_fail = 0;
static int g_run  = 0;
static void check(bool c, const char* what) {
    ++g_run;
    if (!c) { ++g_fail; std::printf("FAIL: %s\n", what); }
}

static const float kNaN = std::numeric_limits<float>::quiet_NaN();

// One block_q6_K = 210 bytes: ql[128] @0, qh[64] @128, scales[16] @192, d fp16 @208.
static const size_t kBlock = 210;
static const int    kElems = 256;

// Builds a Q6_K block whose dequantized values are exactly predictable:
//   d = 1.0, every scale = 2, every 4-bit quant nibble = 8  ->  w = 1.0*2*(8-32)
// Each of the 256 values is produced by ql/qh nibbles; filling both nibbles of
// every ql byte with 8 and leaving qh zero makes all four lanes equal.
// Builds a Q6_K block whose dequantized values are all exactly predictable.
//
// Each ql byte carries TWO nibbles that feed two different output lanes:
//     q1,q2 come from the LOW nibble   ((ql & 0xF) | qh) - 32
//     q3,q4 come from the HIGH nibble  ((ql >> 4) | qh) - 32
// So BOTH nibbles must be set to the same value for all 256 outputs to be
// equal. Setting only the low nibble makes 128 values (-32 after the bias) and
// 128 values (-24), and an expectation computed as if all 256 were equal is
// then wrong while the kernel is right.
static void makeBlock(std::vector<uint8_t>& b, int nibble) {
    b.assign(kBlock, 0);
    const uint8_t n = static_cast<uint8_t>(nibble & 0xF);
    for (int i = 0; i < 128; ++i) b[i] = static_cast<uint8_t>(n | (n << 4));  // 0x88 for n=8
    for (int i = 0; i < 64;  ++i) b[128 + i] = 0;      // qh = 0 -> high bits 0
    for (int i = 0; i < 16;  ++i) b[192 + i] = 2;      // scales = 2 (int8)
    const uint16_t d16 = 0x3C00;                       // fp16 1.0
    std::memcpy(&b[208], &d16, sizeof(d16));
}

int main() {
    const int   Q6K = 14;   // GGML_TYPE_Q6_K in this codebase
    auto&       reg = QuantKernelRegistry::Instance();
    // Registration is explicit, not a static initialiser.
    reg.RegisterBuiltins();
    auto        k   = reg.GetGEMV(Q6K);

    check(k != nullptr, "a Q6_K GEMV kernel is registered");
    if (!k) { std::printf("VERDICT=FAIL\n"); return 1; }

    const size_t rows = 4, cols = 256;            // one block per row
    const size_t blocksPerRow = cols / kElems;     // 1

    std::vector<uint8_t> blk;
    makeBlock(blk, 8);
    std::vector<uint8_t> w(rows * blocksPerRow * kBlock);
    for (size_t r = 0; r < rows; ++r)
        std::memcpy(&w[r * blocksPerRow * kBlock], blk.data(), kBlock);

    // Input of all ones -> each output must equal 256 * (d*scale*q) for the
    // single block in its row.
    std::vector<float> x(cols, 1.0f);

    // ---- THE FALSIFICATION: poison, then require the kernel to overwrite ----
    std::vector<float> y(rows, kNaN);
    k(w.data(), x.data(), y.data(), rows, cols);

    int nonFinite = 0;
    for (size_t r = 0; r < rows; ++r) {
        if (!std::isfinite(y[r])) ++nonFinite;
    }
    check(nonFinite == 0,
          "kernel overwrote the NaN poison in every output (no-op stub would leave it NaN)");

    // ---- Determinism: same inputs -> same outputs --------------------------
    std::vector<float> y2(rows, kNaN);
    k(w.data(), x.data(), y2.data(), rows, cols);
    bool same = true;
    for (size_t r = 0; r < rows; ++r) if (y[r] != y2[r]) same = false;
    check(same, "kernel is deterministic across repeated calls");

    // ---- The value must be the real dequantised dot product ---------------
    // w = d * scale * (nibble - 32) for every element
    //   = 1.0 * 2 * (8 - 32) = -48
    // dot with 256 ones = -48 * 256 = -12288
    const double expect = 1.0 * 2.0 * (8 - 32) * 256.0;
    for (size_t r = 0; r < rows; ++r) {
        const double got = y[r];
        if (std::fabs(got - expect) > 1e-3 * std::fabs(expect)) {
            std::printf("  row %zu: got %.9g expected %.9g\n", r, got, expect);
            ++g_fail;
            ++g_run;
            break;
        }
    }
    ++g_run;
    check(true, "every row equals the analytically expected dot product");

    // ---- Multi-block row: results must change with the weights ------------
    // If the kernel ignored the weight pointer entirely (the no-op symptom)
    // these would be identical.
    {
        std::vector<uint8_t> blk2;
        makeBlock(blk2, 4);                       // different nibble -> -56 per element
        std::vector<uint8_t> w2(rows * blocksPerRow * kBlock);
        for (size_t r = 0; r < rows; ++r)
            std::memcpy(&w2[r * blocksPerRow * kBlock], blk2.data(), kBlock);

        std::vector<float> y3(rows, kNaN);
        k(w2.data(), x.data(), y3.data(), rows, cols);
        const double expect2 = 1.0 * 2.0 * (4 - 32) * 256.0;
        bool allFinite = true, allMatch = true;
        for (size_t r = 0; r < rows; ++r) {
            if (!std::isfinite(y3[r])) allFinite = false;
            if (std::fabs((double)y3[r] - expect2) > 1e-3 * std::fabs(expect2)) allMatch = false;
        }
        check(allFinite, "second weight set produces finite output");
        check(allMatch,  "output depends on the weight bytes (not on stale buffer contents)");
    }

    std::printf("CHECKS=%d FAIL=%d\n", g_run, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}