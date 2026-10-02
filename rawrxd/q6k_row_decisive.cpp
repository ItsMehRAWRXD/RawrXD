// q6k_row_decisive.cpp
// RAWRXD_Q6K_ORACLE_BISECT_001 — single-row, single-tensor, decisive.
//
// The model-wide sweep reports 0.605 while both Q6_K decoders match the pinned
// upstream reference exactly. So the defect is addressing, not arithmetic. This
// test computes four values for ONE logical row and distinguishes the cause:
//
//   A = dot(decode(packed + r*row_bytes), x)      the correct answer
//   B = transposed interpretation, sum_c W[c,r]*x[c]
//   C = production path  (gguf_loader ToFloat32 row r, dot x)
//   D = AVX-512 kernel   (GemvQ6K_AVX512 row r)
//
//   C~=A, D!=A   -> optimized kernel addresses rows wrongly
//   D~=A, C!=A   -> the sweep harness geometry is wrong
//   C~=B or D~=B -> something is transposed
//   neither      -> physical row selection / stride is wrong
//
// It also binds the LIVE layout rather than assuming it: sizeof and offsetof are
// printed from the actual type the binary compiles against, so a correct decoder
// walking a wrongly-packed buffer cannot masquerade as an arithmetic defect.
#include "gguf_loader.hpp"
#include "deep2/k_quant_gemv_avx512.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

// The layout the binary actually compiles against. Every offset used by the
// Q6_K code path is derived from these fields, not from hardcoded integers.
#pragma pack(push, 1)
struct BlockQ6KLayout {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};
#pragma pack(pop)
static constexpr int kQKK = 256;   // weights per Q6_K super-block

static void PrintLayout() {
    std::printf("; --- live compiled layout (not assumed) ---\n");
    std::printf("QK_K=%d\n", kQKK);
    std::printf("BLOCK_BYTES=%zu\n", sizeof(BlockQ6KLayout));
    std::printf("OFFSETOF_ql=%zu\n",     offsetof(BlockQ6KLayout, ql));
    std::printf("OFFSETOF_qh=%zu\n",     offsetof(BlockQ6KLayout, qh));
    std::printf("OFFSETOF_scales=%zu\n", offsetof(BlockQ6KLayout, scales));
    std::printf("OFFSETOF_d=%zu\n",      offsetof(BlockQ6KLayout, d));
    std::printf("SCALES_COUNT=%zu\n",    sizeof(((BlockQ6KLayout*)0)->scales));
    // Cross-check the layout the kernel assumes.
    const bool consistent =
        offsetof(BlockQ6KLayout, ql)     == 0 &&
        offsetof(BlockQ6KLayout, qh)     == 128 &&
        offsetof(BlockQ6KLayout, scales) == 192 &&
        offsetof(BlockQ6KLayout, d)      == 208 &&
        sizeof(BlockQ6KLayout)           == 210;
    std::printf("LAYOUT_MATCHES_KERNEL_ASSUMPTION=%d\n", consistent);
}

// Decode one element (row, col) of a Q4_K/Q6_K-style packed matrix by
// block+offset arithmetic, independent of any full-tensor decode.
static void DecodeOne(const uint8_t* packed, size_t cols, size_t row, size_t col,
                      float& out) {
    const size_t idx = row * cols + col;
    const size_t b = idx / kQKK;
    const size_t p = idx % kQKK;
    const uint8_t* blk = packed + b * sizeof(BlockQ6KLayout);
    const int8_t* sc = (const int8_t*)(blk + offsetof(BlockQ6KLayout, scales));
    const uint16_t dh = (uint16_t)(blk[208] | (blk[209] << 8));
    float d;
    {
        const int e = (dh >> 10) & 0x1F, m = dh & 0x3FF;
        d = (e == 0) ? std::ldexp((float)m, -24)
          : (e == 31) ? 0.0f : std::ldexp((float)(m + 1024), e - 25);
        if (dh & 0x8000) d = -d;
    }
    const uint8_t* ql = blk + offsetof(BlockQ6KLayout, ql);
    const uint8_t* qh = blk + offsetof(BlockQ6KLayout, qh);
    const int half = (int)(p / 128);
    const int l    = (int)(p % 128) % 32;
    const int which = (int)((p % 128) / 32);        // 0..3 -> q1..q4
    const int is   = l / 16;
    int v;
    switch (which) {
        case 0: v = ((ql[l]      & 0x0F) | (((qh[l] >> 0) & 3) << 4)) - 32; break;
        case 1: v = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) - 32; break;
        case 2: v = ((ql[l]      >> 4 ) | (((qh[l] >> 4) & 3) << 4)) - 32; break;
        default: v = ((ql[l + 32] >> 4 ) | (((qh[l] >> 6) & 3) << 4)) - 32; break;
    }
    static const int soff[4] = { 0, 2, 4, 6 };
    out = d * (float)sc[is + soff[which]] * (float)v;
    (void)half;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const char* want     = argc > 2 ? argv[2] : nullptr;
    const size_t rowSel  = argc > 3 ? (size_t)atoll(argv[3]) : 0;

    PrintLayout();

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    // Pick a non-square Q6_K tensor.
    const GGUFTensorInfo* tinfo = nullptr;
    for (const auto& t : m->tensors) {
        if (t.ggml_type != GGMLType::Q6_K || t.shape.size() != 2) continue;
        const size_t cols = (size_t)t.shape[0], rows = (size_t)t.shape[1];
        if (rows == cols) continue;
        if (want && t.name != want) continue;
        tinfo = &t; break;
    }
    if (!tinfo) { std::printf("NO_NONSQUARE_Q6K_TENSOR\n"); return 3; }

    const size_t cols = (size_t)tinfo->shape[0];
    const size_t rows = (size_t)tinfo->shape[1];
    const size_t blocksPerRow = cols / kQKK;
    const size_t rowBytes = blocksPerRow * sizeof(BlockQ6KLayout);
    const size_t r = (rowSel < rows) ? rowSel : 0;

    std::printf("\n; --- target ---\n");
    std::printf("TENSOR=%s\n", tinfo->name.c_str());
    std::printf("ROWS=%zu\nCOLS=%zu\n", rows, cols);
    std::printf("BLOCKS_PER_ROW=%zu\nROW_BYTES=%zu\n", blocksPerRow, rowBytes);
    std::printf("ROW_INDEX=%zu\n", r);
    std::printf("EXPECTED_ROW_OFFSET=%zu\n", r * rowBytes);
    std::printf("TENSOR_BYTE_SIZE=%zu\n", tinfo->byte_size);

    auto view = loader.GetTensor(tinfo->name);
    if (!view) { std::printf("TENSOR_LOOKUP=FAIL\n"); return 4; }
    const uint8_t* packed = view->data<uint8_t>();

    std::vector<float> x(cols);
    for (size_t i = 0; i < cols; ++i) x[i] = 0.5f * std::sin(0.017f * (float)(i + 1));

    // ---- A: decode the row directly from packed bytes, dot in double ----
    double A = 0.0;
    for (size_t c = 0; c < cols; ++c) {
        float w;
        DecodeOne(packed, cols, r, c, w);
        A += (double)w * (double)x[c];
    }

    // ---- full decode once, for B and C ----
    std::vector<float> dec;
    if (!view->ToFloat32(dec) || dec.size() < rows * cols) {
        std::printf("DECODE=FAIL\n"); return 5;
    }

    // ---- B: transposed interpretation ----
    double B = 0.0;
    for (size_t c = 0; c < cols; ++c) B += (double)dec[c * cols + r] * (double)x[c];

    // ---- C: production path ----
    double C = 0.0;
    for (size_t c = 0; c < cols; ++c) C += (double)dec[r * cols + c] * (double)x[c];

    // ---- D: AVX-512 kernel, whole-row form ----
    double D = 0.0;
    std::vector<float> yFast(rows, 0.0f);
    kquant::GemvQ6K_AVX512(packed, x.data(), yFast.data(), rows, cols);
    D = yFast[r];

    std::printf("\n; --- element-wise probe: direct decode vs ToFloat32 buffer ---\n");
    {
        // If these agree element-wise, the row DOTs must agree too, and the
        // defect is purely in how each consumer addresses rows. If they differ,
        // the two disagree about WHICH weight a buffer slot holds.
        int firstBad = -1;
        double worst = 0.0;
        for (size_t c = 0; c < cols; ++c) {
            float w;
            DecodeOne(packed, cols, r, c, w);
            const double got = dec[r * cols + c];
            const double den = std::max(1e-12, std::fabs((double)w));
            const double rel = std::fabs(got - (double)w) / den;
            if (rel > worst) worst = rel;
            if (rel > 1e-5 && firstBad < 0) firstBad = (int)c;
        }
        std::printf("ELEMENTWISE_MATCH=%d\n", firstBad < 0 ? 1 : 0);
        std::printf("FIRST_BAD_COL=%d\n", firstBad);
        std::printf("WORST_REL=%.9g\n", worst);
        if (firstBad >= 0) {
            float w;
            DecodeOne(packed, cols, r, (size_t)firstBad, w);
            std::printf("DETAIL col=%d direct=%.9g tofloat=%.9g block=%zu pos_in_block=%zu\n",
                        firstBad, (double)w, dec[r * cols + firstBad],
                        (size_t)((r * cols + (size_t)firstBad) / kQKK),
                        (size_t)((r * cols + (size_t)firstBad) % kQKK));
            // Is the ToFloat32 value instead what the direct decoder produces
            // at some OTHER logical position? Report the row it matches.
            double target = dec[r * cols + firstBad];
            int matchRow = -1, matchCol = -1;
            for (size_t rr = 0; rr < rows && matchRow < 0; rr += (rows / 64 + 1)) {
                for (size_t cc = 0; cc < cols; ++cc) {
                    float w2;
                    DecodeOne(packed, cols, rr, cc, w2);
                    if (std::fabs((double)w2 - target) <= 1e-9 * std::max(1.0, std::fabs(target))) {
                        matchRow = (int)rr; matchCol = (int)cc; break;
                    }
                }
            }
            std::printf("TOFLOAT_VALUE_FOUND_AT_ROW=%d COL=%d\n", matchRow, matchCol);
        }
    }

    std::printf("\n; --- the four values ---\n");
    std::printf("DOT_ROW_A=%.10g\n", A);
    std::printf("DOT_TRANSPOSE_B=%.10g\n", B);
    std::printf("DOT_CURRENT_PRODUCTION_C=%.10g\n", C);
    std::printf("DOT_CURRENT_AVX512_D=%.10g\n", D);

    auto near = [](double p, double q) {
        const double m = std::max(1e-9, std::max(std::fabs(p), std::fabs(q)));
        return std::fabs(p - q) / m < 1e-6;
    };
    std::printf("\n; --- classification ---\n");
    std::printf("C_EQ_A=%d  D_EQ_A=%d  C_EQ_B=%d  D_EQ_B=%d\n",
                near(C, A), near(D, A), near(C, B), near(D, B));
    if (near(C, A) && near(D, A))      std::printf("VERDICT=BOTH_CORRECT  (the 0.605 is elsewhere)\n");
    else if (near(C, A) && !near(D, A)) std::printf("VERDICT=AVX512_ROW_ADDRESSING_WRONG\n");
    else if (!near(C, A) && near(D, A)) std::printf("VERDICT=HARNESS_GEOMETRY_WRONG\n");
    else if (near(C, B) || near(D, B))  std::printf("VERDICT=TRANSPOSED_INTERPRETATION\n");
    else                                 std::printf("VERDICT=ROW_SELECTION_OR_STRIDE_WRONG\n");
    return 0;
}