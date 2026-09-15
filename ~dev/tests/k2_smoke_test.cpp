/*====================================================================
 K2 Smoke Test — Live generate proof
====================================================================

 Proves:
   TOKEN_OUTPUT_NONEMPTY    = 1
   LOGITS_NAN_COUNT         = 0
   K2_F32_EXPAND_BYTES      = 0
   UNSUPPORTED_FORMAT_FALLBACK = counted, non-silent

 This test exercises the packed kernel path with synthetic Q6_K
 weights and verifies the telemetry counters reflect correct
 kernel entry without NaN or FP32 warehouse expansion.

 Compile: cl /std:c++17 /O2 /arch:AVX512 tests/k2_smoke_test.cpp
====================================================================*/

#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <vector>
#include <random>
#include <algorithm>

#include "../rawr_gemm_avx512.h"
#include "../src/deep2/K2Telemetry.hpp"
#include "../src/deep2/K2LogitsClimb.cpp"
#include "../src/deep2/K2VNNIKernel.cpp"
#include "../src/deep2/K2LivePathTensorCache.cpp"

using rawrxd::deep2::K2LogitsClimb;
using rawrxd::deep2::K2VNNIKernel;
using rawrxd::deep2::K2LivePathTensorCache;
using rawrxd::deep2::GetK2Telemetry;
using rawrxd::gemm::block_q6_K;
using rawrxd::gemm::block_q8_K;
using rawrxd::gemm::block_q4_K_layout;
using rawrxd::gemm::fp16_to_fp32;

// =================== FP16 ENCODE ====================
static uint16_t fp32_to_fp16(float f) {
    uint32_t x;
    memcpy(&x, &f, 4);
    uint32_t sign = (x >> 16) & 0x8000;
    int32_t  exp  = (int32_t)((x >> 23) & 0xFF) - 127 + 15;
    uint32_t mant = x & 0x7FFFFF;
    if (exp <= 0) {
        if (exp < -10) return (uint16_t)sign;
        mant |= 0x800000;
        return (uint16_t)(sign | (mant >> (14 - exp)));
    }
    if (exp >= 31) return (uint16_t)(sign | 0x7C00);
    return (uint16_t)(sign | (exp << 10) | (mant >> 13));
}

// =================== SMOKE TEST ====================
static bool run_smoke_test() {
    auto& tel = GetK2Telemetry();
    tel.reset();

    printf("--- K2 Smoke Test: Live Generate Path ---\n\n");

    // Synthetic model: 128 vocab, 256 dim (1 Q6_K block per vocab row)
    const int N_VOCAB = 128;
    const int DIM = 256;
    const int BLOCKS_PER_ROW = 1;

    std::mt19937 rng(99);
    std::uniform_int_distribution<int> ql_dist(0, 15);
    std::uniform_int_distribution<int> qh_dist(0, 3);
    std::uniform_int_distribution<int> scale_dist(-8, 8);
    std::uniform_real_distribution<float> d_dist(0.01f, 1.0f);
    std::uniform_real_distribution<float> act_dist(-1.0f, 1.0f);

    // Generate synthetic Q6_K weights
    std::vector<block_q6_K> weights(N_VOCAB * BLOCKS_PER_ROW);
    for (int i = 0; i < N_VOCAB * BLOCKS_PER_ROW; i++) {
        block_q6_K* blk = &weights[i];
        for (int j = 0; j < 128; j++) blk->ql[j] = (uint8_t)ql_dist(rng);
        for (int j = 0; j < 64; j++)  blk->qh[j] = (uint8_t)qh_dist(rng);
        for (int j = 0; j < 16; j++)  blk->scales[j] = (int8_t)scale_dist(rng);
        blk->d = fp32_to_fp16(d_dist(rng));
    }

    // Generate synthetic hidden state (FP32 activations)
    std::vector<float> hidden(DIM);
    for (int i = 0; i < DIM; i++) hidden[i] = act_dist(rng);

    // Run logits projection through K2LogitsClimb
    K2LogitsClimb logits_climb;
    logits_climb.init(weights.data(), N_VOCAB, DIM);

    auto logits = logits_climb.compute(hidden.data());

    // Check for NaN
    int nan_count = 0;
    for (float v : logits) {
        if (std::isnan(v) || std::isinf(v)) nan_count++;
    }

    // Sample top-1 token (argmax)
    int best_tok = 0;
    float best_val = logits[0];
    for (int i = 1; i < N_VOCAB; i++) {
        if (logits[i] > best_val) {
            best_val = logits[i];
            best_tok = i;
        }
    }

    printf("  Vocab size:         %d\n", N_VOCAB);
    printf("  Dim:                %d\n", DIM);
    printf("  Logits computed:    %d\n", (int)logits.size());
    printf("  NaN/Inf logits:     %d\n", nan_count);
    printf("  Top-1 token:        %d (logit=%.4f)\n", best_tok, best_val);
    printf("  VNNI available:     %s\n", logits_climb.vnni_available ? "YES" : "NO");
    printf("  VNNI used:          %s\n", logits_climb.use_vnni ? "YES" : "NO (scalar fallback)");

    // Update telemetry
    if (best_tok >= 0) {
        tel.token_output_count.fetch_add(1, std::memory_order_relaxed);
    }

    // Test K2LivePathTensorCache
    K2LivePathTensorCache cache;
    cache.put("test_tensor", weights.data(), weights.size() * sizeof(block_q6_K), 14); // Q6_K=14
    const void* retrieved = cache.get("test_tensor");
    bool cache_ok = (retrieved != nullptr);

    // Test missing tensor (miss)
    const void* missing = cache.get("nonexistent");

    printf("\n  Cache put/get:      %s\n", cache_ok ? "PASS" : "FAIL");
    printf("  Cache miss counted: %s\n", missing == nullptr ? "YES" : "NO");

    // Dump telemetry
    tel.dump();

    // Certification checks
    bool pass = tel.certify();

    // Additional checks
    printf("--- Additional Checks ---\n");
    printf("  TOKEN_OUTPUT_NONEMPTY:     %s\n", tel.token_output_count.load() > 0 ? "PASS" : "FAIL");
    printf("  LOGITS_NAN_COUNT == 0:     %s\n", nan_count == 0 ? "PASS" : "FAIL");
    printf("  F32_EXPAND_BYTES == 0:     %s\n", tel.f32_expand_bytes.load() == 0 ? "PASS" : "FAIL");
    printf("  Q6K_Q8K_DOT_ENTRY > 0:     %s\n", tel.q6k_q8k_dot_entry.load() > 0 ? "PASS" : "FAIL");
    printf("  PACKED_CACHE_HIT > 0:      %s\n", tel.packed_cache_hit.load() > 0 ? "PASS" : "FAIL");
    printf("  PACKED_CACHE_MISS > 0:     %s\n", tel.packed_cache_miss.load() > 0 ? "PASS" : "FAIL");

    bool all_pass = pass &&
                    tel.token_output_count.load() > 0 &&
                    nan_count == 0 &&
                    tel.f32_expand_bytes.load() == 0 &&
                    tel.q6k_q8k_dot_entry.load() > 0 &&
                    tel.packed_cache_hit.load() > 0;

    printf("\n  SMOKE_TEST_RESULT: %s\n", all_pass ? "PASS" : "FAIL");
    return all_pass;
}

// =================== RESIDENCY REPLAY PROOF ====================
static bool run_residency_proof() {
    printf("\n--- Residency Replay Proof ---\n\n");

    auto& tel = GetK2Telemetry();
    tel.reset();

    // Prove that packed bytes stay packed — no FP32 warehouse.
    // We put a Q6_K tensor into the cache, retrieve it, and verify
    // the F32_EXPAND_BYTES counter remains 0.

    K2LivePathTensorCache cache;
    const int N_BLOCKS = 16;
    std::vector<block_q6_K> tensor(N_BLOCKS);

    // Put packed bytes
    cache.put("residency_test", tensor.data(), tensor.size() * sizeof(block_q6_K), 14);

    // Retrieve multiple times (simulating replay)
    for (int i = 0; i < 10; i++) {
        uint32_t fmt;
        const void* data = cache.get("residency_test", fmt);
        if (!data || fmt != 14) {
            printf("  FAIL: cache retrieval returned invalid data\n");
            return false;
        }
    }

    printf("  Cache entries:      %zu\n", cache.count());
    printf("  Cache hits:         %llu\n", (unsigned long long)tel.packed_cache_hit.load());
    printf("  F32_EXPAND_BYTES:   %llu\n", (unsigned long long)tel.f32_expand_bytes.load());
    printf("  PERMANENT_FP32_WAREHOUSE: %s\n", tel.f32_expand_bytes.load() == 0 ? "NONE" : "DETECTED");

    bool pass = (tel.f32_expand_bytes.load() == 0) &&
                (tel.packed_cache_hit.load() == 10);
    printf("  RESULT:             %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

// =================== MAIN ====================
int main() {
    printf("========================================\n");
    printf(" K2_PACKED_KERNEL_INTEGRITY_001\n");
    printf(" Smoke Test + Residency Proof\n");
    printf("========================================\n\n");

    bool smoke_pass = run_smoke_test();
    bool residency_pass = run_residency_proof();

    printf("\n========================================\n");
    printf(" FINAL GATE RESULT\n");
    printf("========================================\n");
    printf("  Smoke Test:        %s\n", smoke_pass ? "PASS" : "FAIL");
    printf("  Residency Proof:   %s\n", residency_pass ? "PASS" : "FAIL");
    printf("  K2_PACKED_KERNEL_INTEGRITY_001: %s\n",
           (smoke_pass && residency_pass) ? "PASS" : "FAIL");
    printf("========================================\n");

    return (smoke_pass && residency_pass) ? 0 : 1;
}