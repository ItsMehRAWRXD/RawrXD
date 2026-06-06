// test_multilayer_single_phase31.cpp
// Phase 3.1 — Single multi-layer forward pass smoke test
// Validates: 34-layer stack loads and executes without crash

#include "SovereignInferenceEngine.hpp"
#include <cstdio>

using namespace RawrXD::AI;

int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";

    printf("[MultiLayer] Initializing engine...\n");
    SovereignEngineConfig cfg{};
    cfg.model_path = model_path;
    cfg.max_context_length = 128;  // smaller ctx for faster test
    SovereignInferenceEngine engine(cfg);
    if (!engine.Initialize()) {
        fprintf(stderr, "FATAL: engine init failed\n");
        return 1;
    }

    printf("[MultiLayer] Running single 34-layer forward pass...\n");
    uint32_t token_id = 42;
    std::vector<float> logits;
    if (!engine.RunLayerForward(token_id, logits)) {
        fprintf(stderr, "FATAL: RunLayerForward failed\n");
        return 1;
    }

    printf("[MultiLayer] Forward pass complete. Logits size: %zu\n", logits.size());
    if (!logits.empty()) {
        float max_logit = logits[0];
        size_t max_idx = 0;
        for (size_t i = 1; i < logits.size(); ++i) {
            if (logits[i] > max_logit) {
                max_logit = logits[i];
                max_idx = i;
            }
        }
        printf("[MultiLayer] Max logit: %.6f at index %zu\n", max_logit, max_idx);
    }

    printf("[MultiLayer] PASS\n");
    return 0;
}
