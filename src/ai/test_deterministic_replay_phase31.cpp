// test_deterministic_replay_phase31.cpp
// Phase 3.1 — 2-Token Deterministic Replay Harness
// Validates that two SovereignInferenceEngine instances produce identical
// token sequences for the same prompt when temperature=0 and top_k=1.
//
// Build: ninja test_deterministic_replay_phase31
// Run:  .\test_deterministic_replay_phase31.exe <model.gguf> [prompt]

#include "SovereignInferenceEngine.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdint.h>
#include <windows.h>

using namespace RawrXD::AI;

static const char* kDefaultPrompt = "Hello";
static const uint32_t kMaxNewTokens = 2;   // Phase 3.1: exactly 2 tokens

struct ReplayResult {
    bool passed = false;
    bool tokens_match = false;
    bool states_match = false;
    bool timing_sane = false;
    std::vector<uint32_t> tokens_a;
    std::vector<uint32_t> tokens_b;
    SovereignInferenceEngine::Stats stats_a;
    SovereignInferenceEngine::Stats stats_b;
    const char* failure_reason = nullptr;
};

static ReplayResult RunDeterministicReplay(const char* model_path,
                                            const char* prompt,
                                            uint32_t max_tokens) {
    ReplayResult result;

    SovereignEngineConfig cfg{};
    cfg.model_path = model_path;
    cfg.temperature = 0.0f;
    cfg.top_k = 1;
    cfg.max_context_length = 128;   // small for fast test

    // Instance A
    SovereignInferenceEngine engine_a(cfg);
    if (!engine_a.Initialize()) {
        result.failure_reason = "engine_a.Initialize() failed";
        return result;
    }

    // Instance B (identical config)
    SovereignInferenceEngine engine_b(cfg);
    if (!engine_b.Initialize()) {
        result.failure_reason = "engine_b.Initialize() failed";
        return result;
    }

    // Generate from A
    if (!engine_a.Generate(prompt, result.tokens_a, max_tokens)) {
        result.failure_reason = "engine_a.Generate() failed";
        return result;
    }
    result.stats_a = engine_a.GetStats();

    // Generate from B
    if (!engine_b.Generate(prompt, result.tokens_b, max_tokens)) {
        result.failure_reason = "engine_b.Generate() failed";
        return result;
    }
    result.stats_b = engine_b.GetStats();

    // 1. Token-by-token identity
    result.tokens_match = (result.tokens_a == result.tokens_b);

    // 2. Full state identity (includes hidden state, seq_len, etc.)
    result.states_match = engine_a.StatesIdentical(engine_b);

    // 3. Timing sanity: both should complete in < 5 seconds for 2 tokens
    const uint64_t kMaxUs = 5ULL * 1000000ULL;
    result.timing_sane =
        (result.stats_a.generate_us < kMaxUs) &&
        (result.stats_b.generate_us < kMaxUs);

    result.passed = result.tokens_match && result.states_match && result.timing_sane;
    if (!result.passed) {
        if (!result.tokens_match)  result.failure_reason = "token mismatch";
        else if (!result.states_match) result.failure_reason = "state mismatch";
        else if (!result.timing_sane)  result.failure_reason = "timing exceeded 5s";
    }
    return result;
}

static void PrintResult(const ReplayResult& r, const char* prompt) {
    printf("\n=== Phase 3.1 Deterministic Replay Harness ===\n");
    printf("Prompt: \"%s\"\n", prompt);
    printf("Max new tokens: %u\n", kMaxNewTokens);
    printf("\n--- Instance A ---\n");
    printf("Tokens (%zu): ", r.tokens_a.size());
    for (auto t : r.tokens_a) printf("%u ", t);
    printf("\n");
    printf("Prefill: %llu us | Generate: %llu us | TPS: %.2f\n",
           (unsigned long long)r.stats_a.prefill_us,
           (unsigned long long)r.stats_a.generate_us,
           r.stats_a.tokens_per_second);

    printf("\n--- Instance B ---\n");
    printf("Tokens (%zu): ", r.tokens_b.size());
    for (auto t : r.tokens_b) printf("%u ", t);
    printf("\n");
    printf("Prefill: %llu us | Generate: %llu us | TPS: %.2f\n",
           (unsigned long long)r.stats_b.prefill_us,
           (unsigned long long)r.stats_b.generate_us,
           r.stats_b.tokens_per_second);

    printf("\n--- Checks ---\n");
    printf("Token identity:   %s\n", r.tokens_match ? "PASS" : "FAIL");
    printf("State identity:   %s\n", r.states_match ? "PASS" : "FAIL");
    printf("Timing sanity:    %s\n", r.timing_sane ? "PASS" : "FAIL");
    printf("\nOVERALL: %s\n", r.passed ? "PASS" : "FAIL");
    if (!r.passed && r.failure_reason) {
        printf("Reason: %s\n", r.failure_reason);
    }
}

int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    const char* prompt   = (argc > 2) ? argv[2] : kDefaultPrompt;

    printf("[Harness] Model: %s\n", model_path);
    printf("[Harness] Prompt: \"%s\"\n", prompt);

    ReplayResult result = RunDeterministicReplay(model_path, prompt, kMaxNewTokens);
    PrintResult(result, prompt);

    return result.passed ? 0 : 1;
}
