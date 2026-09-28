// q4k_kernel_parity_test.cpp — DEEP2_Q4K_GEMV_PARITY_001
//
// Direct comparison: registered Q4_K GEMV (runtime dispatch, Q4K×Q8K hot
// path) vs independent canonical float dequant-dot on the REAL
// blk.4.ffn_gate.weight bytes of the 32B model.
//
#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

namespace Deep2 {
struct CanonQ4K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
static float canon_f16(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t e = (h >> 10) & 0x1F;
    uint32_t f = h & 0x03FF;
    if (e == 0) {
        float v = static_cast<float>(f) * 5.960464477539063e-08f;
        return (h & 0x8000) ? -v : v;
    }
    if (e == 31) {
        uint32_t bits = sign | 0x7F800000 | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((e - 15 + 127) << 23) | (f << 13);
    return reinterpret_cast<float&>(bits);
}
static void canon_scale_min(int j, const uint8_t* q, int& d, int& m) {
    if (j < 4) {
        d = q[j] & 63;
        m = q[j + 4] & 0x3F;
    } else {
        d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] & 0x3F) << 4);
    }
}
static void canon_dequant_row(const CanonQ4K& blk, float* y) {
    const float d = canon_f16(blk.d);
    const float dmin = canon_f16(blk.dmin);
    int sc[8], mn[8];
    for (int j = 0; j < 8; ++j) canon_scale_min(j, blk.scales, sc[j], mn[j]);
    for (int isb = 0; isb < 8; ++isb) {
        const float s = d * static_cast<float>(sc[isb]);
        const float mv = dmin * static_cast<float>(mn[isb]);
        const uint8_t* qsub = blk.qs + isb * 16;
        for (int l = 0; l < 16; ++l) {
            y[isb * 32 + l] = s * (qsub[l] & 0xF) - mv;
        }
        for (int l = 0; l < 16; ++l) {
            y[isb * 32 + 16 + l] = s * (qsub[l] >> 4) - mv;
        }
    }
}
} // namespace Deep2

using Deep2::QuantKernelRegistry;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: q4k_kernel_parity_test.exe <model.gguf>\n");
        return 2;
    }
    Deep2::GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "PARITY=HOLD stage=gguf_load\n");
        return 11;
    }
    const Deep2::GGUFTensor* t = loader.getTensor("blk.4.ffn_gate.weight");
    if (!t || !t->data || t->shape.size() < 2) {
        std::fprintf(stderr, "PARITY=HOLD stage=tensor_lookup\n");
        return 12;
    }
    const int64_t cols = t->shape[0];   // 5120
    const int64_t rows = t->shape[1];   // 27648
    const size_t rowBytes = static_cast<size_t>(cols) / 256 * 144;
    std::fprintf(stderr, "TENSOR rows=%lld cols=%lld type=%d rowBytes=%zu\n",
                 static_cast<long long>(rows), static_cast<long long>(cols),
                 static_cast<int>(t->type), rowBytes);

    const int kTestRows = 8;
    const uint8_t* base = t->data;

    // Independent canonical dequant of first 8 rows.
    std::vector<std::vector<float>> ref(kTestRows, std::vector<float>(cols));
    for (int r = 0; r < kTestRows; ++r) {
        Deep2::CanonQ4K blk;
        const uint8_t* rowBase = base + static_cast<size_t>(r) * rowBytes;
        for (size_t b = 0; b < static_cast<size_t>(cols) / 256; ++b) {
            std::memcpy(&blk, rowBase + b * 144, 144);
            Deep2::canon_dequant_row(blk, &ref[r][b * 256]);
        }
    }

    // Deterministic activation.
    std::vector<float> x(static_cast<size_t>(cols));
    for (int64_t i = 0; i < cols; ++i) {
        x[static_cast<size_t>(i)] = std::sin(static_cast<float>(i) * 0.01f) * 0.5f + 0.01f;
    }

    QuantKernelRegistry::Instance().Initialize();
    auto kernel = QuantKernelRegistry::Instance().GetGEMV(12);
    if (!kernel) {
        std::fprintf(stderr, "PARITY=HOLD stage=no_kernel\n");
        return 14;
    }
    std::vector<float> got(kTestRows, 0.0f);
    kernel(base, x.data(), got.data(), kTestRows, static_cast<size_t>(cols));

    int mismatches = 0;
    double worstRel = 0.0;
    for (int r = 0; r < kTestRows; ++r) {
        double sum = 0.0;
        for (int64_t i = 0; i < cols; ++i) {
            sum += static_cast<double>(ref[r][static_cast<size_t>(i)]) *
                   static_cast<double>(x[static_cast<size_t>(i)]);
        }
        const double a = got[static_cast<size_t>(r)];
        const double rel = std::fabs(a - sum) /
                           (std::fabs(sum) > 1e-9 ? std::fabs(sum) : 1.0);
        if (rel > worstRel) worstRel = rel;
        std::fprintf(stderr, "ROW %d kernel=%.9g canonical=%.9g rel=%.4g\n",
                     r, a, sum, rel);
        if (rel > 2e-3) ++mismatches;
    }
    std::fprintf(stderr,
        "GATE=DEEP2_Q4K_GEMV_PARITY_001\n"
        "ROWS_TESTED=%d MISMATCHES=%d WORST_REL_ERR=%.4g\n",
        kTestRows, mismatches, worstRel);
    std::fprintf(stderr, "PARITY=%s\n", mismatches == 0 ? "PASS" : "FAIL");
    return mismatches == 0 ? 0 : 1;
}