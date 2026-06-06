// test_ffn_core_phase31.cpp
// Phase 3.1 — FFN core certification harness
// Validates: dual-instance bit-perfect hash parity + 1000-iteration stability

#include "SovereignInferenceEngine.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>

using namespace RawrXD::AI;

static const char* MODEL_PATH = "D:\\ministral3_q4_0.gguf";

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    SovereignEngineConfig cfg{};
    cfg.model_path = MODEL_PATH;
    cfg.max_context_length = 4096;

    // ---- Dual-instance parity test ----
    printf("[FFN] Dual-instance parity test\n");
    SovereignInferenceEngine engineA(cfg);
    SovereignInferenceEngine engineB(cfg);
    if (!engineA.Initialize()) { fprintf(stderr, "FATAL: engineA init failed\n"); return 1; }
    if (!engineB.Initialize()) { fprintf(stderr, "FATAL: engineB init failed\n"); return 1; }

    // Deterministic input vector (same seed as attention test)
    const uint32_t n_embd = 4096;
    std::vector<float> input(n_embd);
    for (uint32_t i = 0; i < n_embd; ++i) {
        input[i] = static_cast<float>(i) * 0.001f;
    }

    SovereignInferenceEngine::FFNStageHashes hashesA{}, hashesB{};
    if (!engineA.RunFFNCore(input.data(), n_embd, hashesA)) {
        fprintf(stderr, "FATAL: engineA RunFFNCore failed\n");
        return 1;
    }
    if (!engineB.RunFFNCore(input.data(), n_embd, hashesB)) {
        fprintf(stderr, "FATAL: engineB RunFFNCore failed\n");
        return 1;
    }

    printf("[FFN] Instance A: gate=%016llX up=%016llX silu=%016llX down=%016llX\n",
           (unsigned long long)hashesA.hash_gate,
           (unsigned long long)hashesA.hash_up,
           (unsigned long long)hashesA.hash_silu,
           (unsigned long long)hashesA.hash_down);
    printf("[FFN] Instance B: gate=%016llX up=%016llX silu=%016llX down=%016llX\n",
           (unsigned long long)hashesB.hash_gate,
           (unsigned long long)hashesB.hash_up,
           (unsigned long long)hashesB.hash_silu,
           (unsigned long long)hashesB.hash_down);

    bool parity_ok = true;
    if (hashesA.hash_gate   != hashesB.hash_gate)   { parity_ok = false; printf("MISMATCH: gate\n"); }
    if (hashesA.hash_up     != hashesB.hash_up)     { parity_ok = false; printf("MISMATCH: up\n"); }
    if (hashesA.hash_silu   != hashesB.hash_silu)   { parity_ok = false; printf("MISMATCH: silu\n"); }
    if (hashesA.hash_down   != hashesB.hash_down)   { parity_ok = false; printf("MISMATCH: down\n"); }

    if (!parity_ok) {
        fprintf(stderr, "FATAL: FFN dual-instance parity FAILED\n");
        return 1;
    }
    printf("[FFN] Dual-instance parity PASS\n");

    // ---- 1000-iteration stability test (single reused engine) ----
    printf("[FFN] 1000-iteration stability test\n");
    SovereignInferenceEngine::FFNStageHashes first = hashesA;
    bool stable = true;
    for (int iter = 0; iter < 1000; ++iter) {
        SovereignInferenceEngine::FFNStageHashes h{};
        if (!engineA.RunFFNCore(input.data(), n_embd, h)) {
            fprintf(stderr, "FATAL: RunFFNCore failed at iter %d\n", iter);
            return 1;
        }
        if (h.hash_gate != first.hash_gate || h.hash_up != first.hash_up ||
            h.hash_silu != first.hash_silu || h.hash_down != first.hash_down) {
            fprintf(stderr, "FATAL: FFN hash drift at iter %d\n", iter);
            stable = false;
            break;
        }
    }
    if (!stable) {
        return 1;
    }
    printf("[FFN] 1000-iteration stability PASS\n");

    printf("[FFN] ALL TESTS PASS\n");
    return 0;
}
