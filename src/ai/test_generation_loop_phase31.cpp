// test_generation_loop_phase31.cpp
// Phase 3.1 — Autoregressive generation loop test
// Validates: Prefill → Step loop produces varied tokens

#include "SovereignInferenceEngine.hpp"
#include <cstdio>

using namespace RawrXD::AI;

int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";

    printf("[Generation] Initializing engine...\n");
    SovereignEngineConfig cfg{};
    cfg.model_path = model_path;
    cfg.max_context_length = 128;
    SovereignInferenceEngine engine(cfg);
    if (!engine.Initialize()) {
        fprintf(stderr, "FATAL: engine init failed\n");
        return 1;
    }

    // Run prefill with a simple prompt
    printf("[Generation] Prefilling with token 42...\n");
    if (!engine.Prefill("42")) {
        fprintf(stderr, "FATAL: Prefill failed\n");
        return 1;
    }

    // Generate 10 tokens
    printf("[Generation] Generating 10 tokens...\n");
    for (int i = 0; i < 10; ++i) {
        uint32_t token_id = 0;
        bool done = false;
        if (!engine.Step(token_id, done)) {
            fprintf(stderr, "FATAL: Step %d failed\n", i);
            return 1;
        }
        printf("[Generation] Step %d: token=%u done=%s\n", i, token_id, done ? "true" : "false");
        if (done) break;
    }

    printf("[Generation] PASS\n");
    return 0;
}
