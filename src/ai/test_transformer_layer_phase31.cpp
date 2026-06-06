// test_transformer_layer_phase31.cpp
// Phase 3.1 — Full transformer layer certification harness
// Validates: dual-instance bit-perfect hash parity + 1000-iteration stability
// Exercises: attention + RMSNorm + residual + FFN + RMSNorm + residual

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
    printf("[Layer] Dual-instance parity test\n");
    SovereignInferenceEngine engineA(cfg);
    SovereignInferenceEngine engineB(cfg);
    if (!engineA.Initialize()) { fprintf(stderr, "FATAL: engineA init failed\n"); return 1; }
    if (!engineB.Initialize()) { fprintf(stderr, "FATAL: engineB init failed\n"); return 1; }

    uint32_t token_id = 42;
    std::vector<float> logitsA, logitsB;
    if (!engineA.RunLayerForward(token_id, logitsA)) {
        fprintf(stderr, "FATAL: engineA RunTokenForward failed\n");
        return 1;
    }
    if (!engineB.RunLayerForward(token_id, logitsB)) {
        fprintf(stderr, "FATAL: engineB RunTokenForward failed\n");
        return 1;
    }

    if (logitsA.size() != logitsB.size()) {
        fprintf(stderr, "FATAL: logits size mismatch\n");
        return 1;
    }

    bool parity_ok = true;
    for (size_t i = 0; i < logitsA.size(); ++i) {
        if (logitsA[i] != logitsB[i]) {
            parity_ok = false;
            printf("MISMATCH: logits[%zu] A=%.6f B=%.6f\n", i, logitsA[i], logitsB[i]);
            break;
        }
    }

    if (!parity_ok) {
        fprintf(stderr, "FATAL: Layer dual-instance parity FAILED\n");
        return 1;
    }
    printf("[Layer] Dual-instance parity PASS\n");

    // ---- 1000-iteration stability test (single reused engine) ----
    printf("[Layer] 1000-iteration stability test\n");
    std::vector<float> first = logitsA;
    bool stable = true;
    for (int iter = 0; iter < 1000; ++iter) {
        std::vector<float> logits;
        if (!engineA.RunLayerForward(token_id, logits)) {
            fprintf(stderr, "FATAL: RunTokenForward failed at iter %d\n", iter);
            return 1;
        }
        if (logits.size() != first.size()) {
            fprintf(stderr, "FATAL: logits size drift at iter %d\n", iter);
            stable = false;
            break;
        }
        for (size_t i = 0; i < logits.size(); ++i) {
            if (logits[i] != first[i]) {
                fprintf(stderr, "FATAL: logits drift at iter %d index %zu\n", iter, i);
                stable = false;
                break;
            }
        }
        if (!stable) break;
    }
    if (!stable) {
        return 1;
    }
    printf("[Layer] 1000-iteration stability PASS\n");

    printf("[Layer] ALL TESTS PASS\n");
    return 0;
}
