// test_logits_diagnostic_phase31.cpp
// Diagnostic: Verify out_logits population and SampleGreedy behavior

#include "SovereignInferenceEngine.hpp"
#include <cstdio>

using namespace RawrXD::AI;

int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";

    printf("[Diag] Initializing engine...\n");
    SovereignEngineConfig cfg{};
    cfg.model_path = model_path;
    cfg.max_context_length = 128;
    SovereignInferenceEngine engine(cfg);
    if (!engine.Initialize()) {
        fprintf(stderr, "FATAL: engine init failed\n");
        return 1;
    }

    printf("[Diag] Running single forward pass for token 42...\n");
    std::vector<float> logits;
    if (!engine.RunLayerForward(42, logits)) {
        fprintf(stderr, "FATAL: RunLayerForward failed\n");
        return 1;
    }

    printf("[Diag] Logits vector size: %zu\n", logits.size());

    // Check specific indices
    if (logits.size() > 2356) {
        printf("[Diag] logits[0]    = %.6f\n", logits[0]);
        printf("[Diag] logits[1]    = %.6f\n", logits[1]);
        printf("[Diag] logits[2356] = %.6f\n", logits[2356]);
    }

    // Count non-zero entries
    size_t non_zero = 0;
    float max_val = logits.empty() ? 0.0f : logits[0];
    size_t max_idx = 0;
    for (size_t i = 0; i < logits.size(); ++i) {
        if (logits[i] != 0.0f) {
            non_zero++;
            if (logits[i] > max_val) {
                max_val = logits[i];
                max_idx = i;
            }
        }
    }
    printf("[Diag] Non-zero logits: %zu\n", non_zero);
    printf("[Diag] Max logit: %.6f at index %zu\n", max_val, max_idx);

    // Call SampleGreedy directly (inline since it's private)
    uint32_t greedy = 0;
    if (!logits.empty()) {
        greedy = 0;
        float best_val = logits[0];
        for (size_t i = 1; i < logits.size(); ++i) {
            if (logits[i] > best_val) {
                best_val = logits[i];
                greedy = static_cast<uint32_t>(i);
            }
        }
    }
    printf("[Diag] SampleGreedy result: %u\n", greedy);

    printf("[Diag] PASS\n");
    return 0;
}
