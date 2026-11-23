// gguf_quant_adapter_test.cpp -- verify native GGUF Q4_0 / Q4_K dequant against
// a direct reference implementation (matching ggml-quants.c) across randomized
// blocks: all sub-blocks, negative values, nonzero minima, full 6-bit metadata.
// Build: g++ -std=c++17 -O2 -I include -I src tools/gguf_quant_adapter_test.cpp -o gqa
#include "deep2/GgufQuantAdapter.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace rawrxd::gguf;

// Direct reference: Q4_0 (ggml dequantize_row_q4_0).
static void RefQ4_0(const uint8_t* blk, float* y) {
    float d = HalfToFloat(ReadF16(blk));
    const uint8_t* qs = blk + 2;
    for (int j = 0; j < 16; ++j) {
        int x0 = (qs[j] & 0x0F) - 8;
        int x1 = (qs[j] >> 4) - 8;
        y[j]      = x0 * d;
        y[j + 16] = x1 * d;
    }
}

// Direct reference: Q4_K (ggml dequantize_row_q4_K).
static void RefQ4_K(const uint8_t* blk, float* y) {
    float d = HalfToFloat(ReadF16(blk));
    float mn = HalfToFloat(ReadF16(blk + 2));
    const uint8_t* scales = blk + 4;
    const uint8_t* q = blk + 16;
    int is = 0; size_t qi = 0;
    for (int j = 0; j < 256; j += 64) {
        int sc, m;
        // get_scale_min_k4
        auto g = [&](int jj, int& dd, int& mm) {
            if (jj < 4) { dd = scales[jj] & 63; mm = scales[jj+4] & 63; }
            else { dd = (scales[jj+4] & 0x0F) | ((scales[jj-4] >> 6) << 4); mm = (scales[jj+4] >> 4) | ((scales[jj] >> 6) << 4); }
        };
        g(is, sc, m); float d1 = d*sc, m1 = mn*m;
        g(is+1, sc, m); float d2 = d*sc, m2 = mn*m;
        for (int l = 0; l < 32; ++l) y[j+l]      = d1*(q[qi+l]&0x0F) - m1;
        for (int l = 0; l < 32; ++l) y[j+32+l]  = d2*(q[qi+l]>>4) - m2;
        qi += 32; is += 2;
    }
}

int main() {
    std::mt19937 rng(12345);
    int fails = 0;

    // ---- Q4_0: 100 random blocks ----
    {
        int ok = 0;
        for (int b = 0; b < 100; ++b) {
            std::vector<uint8_t> blk(18);
            for (auto& x : blk) x = (uint8_t)rng();
            std::vector<float> got, exp(32);
            DequantizeQ4_0(blk.data(), 1, got);
            RefQ4_0(blk.data(), exp.data());
            bool match = true;
            for (int i = 0; i < 32; ++i) if (std::fabs(got[i]-exp[i]) > 1e-6) { match = false; break; }
            if (match) ok++;
            else { std::printf("Q4_0 mismatch block %d: got[0]=%g exp[0]=%g\n", b, got[0], exp[0]); }
        }
        std::printf("Q4_0: %d/100 blocks match reference %s\n", ok, ok==100?"PASS":"FAIL");
        if (ok != 100) fails++;
    }

    // ---- Q4_K: 100 random superblocks (nonzero mins, full metadata) ----
    {
        int ok = 0;
        for (int b = 0; b < 100; ++b) {
            std::vector<uint8_t> blk(144);
            for (auto& x : blk) x = (uint8_t)rng();
            std::vector<float> got, exp(256);
            DequantizeQ4_K(blk.data(), 1, got);
            RefQ4_K(blk.data(), exp.data());
            bool match = true;
            for (int i = 0; i < 256; ++i) if (std::fabs(got[i]-exp[i]) > 1e-6) { match = false; break; }
            if (match) ok++;
            else { std::printf("Q4_K mismatch block %d: got[0]=%g exp[0]=%g\n", b, got[0], exp[0]); }
        }
        std::printf("Q4_K: %d/100 superblocks match reference %s\n", ok, ok==100?"PASS":"FAIL");
        if (ok != 100) fails++;
    }

    std::printf("RESULT=%s fails=%d\n", fails == 0 ? "PASS" : "FAIL", fails);
    return fails == 0 ? 0 : 1;
}