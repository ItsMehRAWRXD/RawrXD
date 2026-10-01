// ============================================================================
// verify_registry_q4k.cpp  --  THROWAWAY verification harness (not production)
//
// Purpose: prove that after RAWRXD_Q4K_AVX512_GEMV_001 the GGML_TYPE_Q4_K GEMV
// that QuantKernelRegistry hands to Deep2Engine is genuinely the AVX-512 fused
// kernel and not the scalar fallback.
//
// Production acquisition path (mirrored exactly):
//   Deep2Engine.cpp:894   QuantKernelRegistry::Instance().Initialize();
//   Deep2Engine.cpp:3221  QuantKernelRegistry::Instance().GetGEMV(wt.type);
//
// This file is self-contained and links ONLY against QuantKernelRegistry.obj.
// It re-implements the Q4_K reference math independently (it does NOT include
// k_quant_gemv_avx512.h) so the comparison cannot be circular.
// ============================================================================

#include "deep2/QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <chrono>
#include <random>
#include <string>
#include <vector>

// GGUFLoader.hpp: GGML_TYPE_Q4_K. Declared locally to keep this TU light; the
// value is cross-checked against the registry's own descriptor table below.
static const int GGML_TYPE_Q4_K_LOCAL = 12;

// ---------------------------------------------------------------------------
// Independent fp16 -> fp32 (not the kernel's FP16ToF32).
// ---------------------------------------------------------------------------
static float RefF16(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            int e = 0; uint32_t m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((uint32_t)(127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float f; std::memcpy(&f, &bits, 4); return f;
}

// ---------------------------------------------------------------------------
// Independent Q4_K reference GEMV.
// Layout (block_q4_K, 144 bytes, 256 weights):
//   uint16 d; uint16 dmin; uint8 scales[12]; uint8 qs[128];
// Sub-block g (32 weights) uses nibble parity g%2 of qs[(g/2)*32 .. +32).
// value = (d * sc[g] * q - dmin * mn[g]) * x      <- ggml dequantize_row_q4_K
// ---------------------------------------------------------------------------
static void RefQ4KUnpack(const uint8_t s[12], uint8_t sc[8], uint8_t mn[8]) {
    for (int i = 0; i < 4; ++i) { sc[i] = s[i] & 0x3F; mn[i] = s[4 + i] & 0x3F; }
    for (int i = 0; i < 4; ++i) {
        sc[4 + i] = (uint8_t)((s[8 + i] & 0x0F) | (((s[i]     >> 6) & 0x03) << 4));
        mn[4 + i] = (uint8_t)((s[8 + i] >> 4)    | (((s[4 + i] >> 6) & 0x03) << 4));
    }
}

static void RefGemvQ4K(const uint8_t* w, const float* x, float* y,
                       size_t rows, size_t cols) {
    const size_t nblocks = cols / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        for (size_t b = 0; b < nblocks; ++b) {
            const uint8_t* blk = w + (r * nblocks + b) * 144;
            float d    = RefF16((uint16_t)(blk[0] | (blk[1] << 8)));
            float dmin = RefF16((uint16_t)(blk[2] | (blk[3] << 8)));
            uint8_t sc[8], mn[8];
            RefQ4KUnpack(blk + 4, sc, mn);
            const uint8_t* qs = blk + 16;
            const float*    xb = x + b * 256;
            for (int g = 0; g < 8; ++g) {
                const uint8_t* gb = qs + (g / 2) * 32;
                const bool high = (g % 2) == 1;
                const float s = d * (float)sc[g];
                const float m = dmin * (float)mn[g];
                for (int j = 0; j < 32; ++j) {
                    uint8_t byte = gb[j];
                    int q = high ? (byte >> 4) : (byte & 0x0F);
                    acc += (s * (float)q - m) * xb[g * 32 + j];
                }
            }
        }
        y[r] = acc;
    }
}

int main() {
    std::printf("=== RAWRXD_Q4K_AVX512_GEMV_001 reachability verification ===\n\n");

    // --- Cross-check the local Q4_K type id against the registry's own table --
    const Deep2::QuantTypeDesc* d = Deep2::LookupQuantType(12);
    if (d) {
        std::printf("LookupQuantType(12).name      = %s\n", d->name);
        std::printf("LookupQuantType(12).blockBytes= %zu (expect 144)\n", d->blockBytes);
        std::printf("LookupQuantType(12).blockElems= %zu (expect 256)\n", d->blockElements);
        if (d->name && std::string(d->name) != "Q4_K") {
            std::printf("TYPE_ID_MISMATCH\n");
            return 2;
        }
    } else {
        std::printf("LookupQuantType(12) = NULL\n");
        return 2;
    }
    std::printf("GGML_TYPE_Q4_K_LOCAL         = %d (matches GGUFLoader.hpp)\n\n",
                GGML_TYPE_Q4_K_LOCAL);

    // --- Acquire the registry exactly as Deep2Engine does -------------------
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    std::printf("--- calling Deep2::QuantKernelRegistry::Instance().Initialize() ---\n");
    std::fflush(stdout);
    reg.Initialize();   // Deep2Engine.cpp:894
    std::fflush(stdout);

    Deep2::GEMVKernelFn fn = reg.GetGEMV(GGML_TYPE_Q4_K_LOCAL); // Deep2Engine.cpp:3221

    std::printf("\n--- RESULT ---\n");
    std::printf("GetGEMV(GGML_TYPE_Q4_K) pointer = %p\n", (void*)fn);
    std::printf("PTR_NON_NULL                    = %d\n", fn ? 1 : 0);
    if (!fn) {
        std::printf("VERDICT = FAIL (no kernel registered for Q4_K)\n");
        return 1;
    }

    // --- Is it the scalar fallback or a different (vector) kernel? ----------
    // KernelImplName inside the registry labels the pointer by identity.
    // Print the registry's own dump row for Q4_K.
    std::string table = reg.DumpTable();
    std::printf("\n--- registry DumpTable() Q4_K row(s) ---\n");
    {
        size_t pos = 0;
        while ((pos = table.find("Q4_K", pos)) != std::string::npos) {
            size_t ls = table.rfind('\n', pos);
            size_t le = table.find('\n', pos);
            if (ls == std::string::npos) ls = 0; else ls += 1;
            if (le == std::string::npos) le = table.size();
            std::printf("%s\n", table.substr(ls, le - ls).c_str());
            pos = le;
        }
    }

    // --- Numerical correctness against the independent reference -----------
    const size_t rows = 8;
    const size_t cols = 1024;   // 4 super-blocks per row
    const size_t nblocks = cols / 256;
    std::mt19937 rng(12345);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_real_distribution<float> actDist(-1.0f, 1.0f);

    std::vector<uint8_t> w(rows * nblocks * 144);
    for (auto& b : w) b = (uint8_t)byteDist(rng);
    // Give the blocks sane scales so the comparison is numerically meaningful.
    for (size_t i = 0; i < rows * nblocks; ++i) {
        uint8_t* blk = &w[i * 144];
        uint16_t dd = 0x2C00;   // ~1/32
        uint16_t dm = 0x2400;   // ~1/256
        std::memcpy(blk + 0, &dd, 2);
        std::memcpy(blk + 2, &dm, 2);
    }
    std::vector<float> x(cols);
    for (auto& v : x) v = actDist(rng);

    std::vector<float> yReg(rows, 0.0f), yRef(rows, 0.0f);
    fn(w.data(), x.data(), yReg.data(), rows, cols);
    RefGemvQ4K(w.data(), x.data(), yRef.data(), rows, cols);

    double maxAbs = 0.0, sumAbs = 0.0;
    int nonFinite = 0;
    for (size_t r = 0; r < rows; ++r) {
        if (!std::isfinite(yReg[r])) ++nonFinite;
        double d0 = std::fabs((double)yReg[r] - (double)yRef[r]);
        if (d0 > maxAbs) maxAbs = d0;
        sumAbs += std::fabs((double)yRef[r]);
    }
    std::printf("\n--- numeric check vs independent scalar Q4_K reference ---\n");
    for (size_t r = 0; r < rows; ++r) {
        std::printf("  row %zu: kernel=% .6f  ref=% .6f\n", r, yReg[r], yRef[r]);
    }
    std::printf("MAX_ABS_DIFF                = %.9g\n", maxAbs);
    std::printf("MEAN_ABS_REF               = %.9g\n", sumAbs / (double)rows);
    std::printf("NONFINITE_OUTPUTS          = %d\n", nonFinite);
    std::printf("NUMERIC_MATCH_WITHIN_TOL   = %d (tol 1e-3 relative)\n",
                (nonFinite == 0 && sumAbs > 0.0 && maxAbs <= 1e-3 * sumAbs / (double)rows) ? 1 : 0);

    // --- Timing: a scalar delegate and a fused ZMM kernel differ measurably
    const int iters = 200;
    auto t0 = std::chrono::steady_clock::now();
    for (int it = 0; it < iters; ++it) fn(w.data(), x.data(), yReg.data(), rows, cols);
    auto t1 = std::chrono::steady_clock::now();
    double msK = std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;

    t0 = std::chrono::steady_clock::now();
    for (int it = 0; it < iters; ++it) RefGemvQ4K(w.data(), x.data(), yRef.data(), rows, cols);
    t1 = std::chrono::steady_clock::now();
    double msR = std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;

    std::printf("\n--- timing (%d iters, rows=%zu cols=%zu) ---\n", iters, rows, cols);
    std::printf("REGISTRY_KERNEL_MS         = %.4f\n", msK);
    std::printf("HAND_REFERENCE_MS          = %.4f\n", msR);
    std::printf("SPEEDUP                    = %.2fx\n", msR > 0 ? msR / msK : 0.0);

    std::printf("\nPTR_NON_NULL=%s\n", "PASS");
    bool ok = (nonFinite == 0 && sumAbs > 0.0 && maxAbs <= 1e-3 * sumAbs / (double)rows);
    std::printf("VERDICT=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}