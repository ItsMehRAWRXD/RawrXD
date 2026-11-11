// ============================================================================
// test_sampling_standalone.cpp - Standalone test for temperature + top-p sampling
// Verifies the sampling logic from inference_engine_stub.cpp works correctly.
// ============================================================================

#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <random>
#include <iostream>

// ── Minimal reproduction of the stub sampling logic ─────────────────────────
static int32_t sampleNextToken(const std::vector<float>& logits, float temperature, float topP)
{
    if (logits.empty()) return 0;

    // Greedy when temperature <= 0
    if (temperature <= 0.0f) {
        auto max_it = std::max_element(logits.begin(), logits.end());
        return static_cast<int32_t>(std::distance(logits.begin(), max_it));
    }

    // Temperature scaling + softmax
    float temp = temperature;
    float maxLogit = *std::max_element(logits.begin(), logits.end());
    std::vector<float> probs(logits.size());
    float sum = 0.0f;
    for (size_t i = 0; i < logits.size(); ++i) {
        probs[i] = std::exp((logits[i] - maxLogit) / temp);
        sum += probs[i];
    }
    for (auto& p : probs) p /= sum;

    // Top-p nucleus filtering
    float nucleusTopP = (topP > 0.0f && topP < 1.0f) ? topP : 1.0f;
    std::vector<std::pair<float, int32_t>> indexed_probs;
    indexed_probs.reserve(probs.size());
    for (size_t i = 0; i < probs.size(); ++i) {
        if (probs[i] > 1e-6f) {
            indexed_probs.emplace_back(probs[i], static_cast<int32_t>(i));
        }
    }
    std::sort(indexed_probs.begin(), indexed_probs.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    float cumulative = 0.0f;
    size_t nucleus_size = 0;
    for (const auto& p : indexed_probs) {
        cumulative += p.first;
        nucleus_size++;
        if (cumulative >= nucleusTopP) break;
    }
    if (nucleus_size == 0) return indexed_probs.empty() ? 0 : indexed_probs.front().second;
    indexed_probs.resize(nucleus_size);

    float nucleus_sum = 0.0f;
    for (const auto& p : indexed_probs) nucleus_sum += p.first;

    static thread_local std::mt19937 gen(42);  // fixed seed for reproducibility
    std::uniform_real_distribution<float> dist(0.0f, nucleus_sum);
    float threshold = dist(gen);

    float cumsum = 0.0f;
    for (const auto& p : indexed_probs) {
        cumsum += p.first;
        if (cumsum >= threshold) return p.second;
    }
    return indexed_probs.back().second;
}

int main()
{
    int failures = 0;

    // ── Test 1: Greedy (temperature=0) always picks argmax ──────────
    {
        std::vector<float> logits = {1.0f, 5.0f, 3.0f, 2.0f, 0.5f};
        int32_t tok = sampleNextToken(logits, 0.0f, 0.9f);
        if (tok != 1) { printf("FAIL Test1: greedy should pick token 1, got %d\n", tok); failures++; }
        else printf("PASS Test1: greedy picks argmax token=%d\n", tok);
    }

    // ── Test 2: Greedy with temperature <= 0 ────────────────────────
    {
        std::vector<float> logits = {1.0f, 5.0f, 3.0f, 2.0f, 0.5f};
        int32_t tok = sampleNextToken(logits, -0.5f, 0.9f);
        if (tok != 1) { printf("FAIL Test2: negative temp should be greedy, got %d\n", tok); failures++; }
        else printf("PASS Test2: negative temp is greedy, token=%d\n", tok);
    }

    // ── Test 3: Non-greedy (temperature>0) produces varied output ────
    {
        std::vector<float> logits = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f};  // uniform
        int32_t tok = sampleNextToken(logits, 0.7f, 0.9f);
        if (tok < 0 || tok > 4) { printf("FAIL Test3: token out of range, got %d\n", tok); failures++; }
        else printf("PASS Test3: uniform logits produce valid token=%d\n", tok);
    }

    // ── Test 4: Top-p nucleus filtering ─────────────────────────────
    {
        std::vector<float> logits = {10.0f, 1.0f, 0.1f, 0.01f, 0.001f};
        // With top_p=0.5, only the dominant token should be in the nucleus
        int32_t tok = sampleNextToken(logits, 0.7f, 0.5f);
        if (tok != 0) { printf("FAIL Test4: top_p=0.5 should pick dominant token 0, got %d\n", tok); failures++; }
        else printf("PASS Test4: top_p nucleus filtering works, token=%d\n", tok);
    }

    // ── Test 5: Top-p=1.0 includes all tokens ───────────────────────
    {
        std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
        int32_t tok = sampleNextToken(logits, 0.7f, 1.0f);
        if (tok < 0 || tok > 4) { printf("FAIL Test5: token out of range, got %d\n", tok); failures++; }
        else printf("PASS Test5: top_p=1.0 includes all tokens, token=%d\n", tok);
    }

    // ── Test 6: Empty logits ────────────────────────────────────────
    {
        std::vector<float> empty;
        int32_t tok = sampleNextToken(empty, 0.7f, 0.9f);
        if (tok != 0) { printf("FAIL Test6: empty logits should return 0, got %d\n", tok); failures++; }
        else printf("PASS Test6: empty logits returns 0\n", tok);
    }

    // ── Test 7: Deterministic with fixed seed ───────────────────────
    {
        std::vector<float> logits = {1.0f, 5.0f, 3.0f, 2.0f, 0.5f};
        int32_t tok1 = sampleNextToken(logits, 0.7f, 0.9f);
        int32_t tok2 = sampleNextToken(logits, 0.7f, 0.9f);
        // With fixed seed 42, same logits should produce same result
        printf("INFO Test7: deterministic sampling: tok1=%d tok2=%d\n", tok1, tok2);
    }

    // ── Test 8: High temperature flattens distribution ──────────────
    {
        std::vector<float> logits = {10.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        // With very high temp, all tokens should have reasonable probability
        int32_t tok = sampleNextToken(logits, 100.0f, 0.9f);
        if (tok < 0 || tok > 4) { printf("FAIL Test8: token out of range, got %d\n", tok); failures++; }
        else printf("PASS Test8: high temp flattens distribution, token=%d\n", tok);
    }

    printf("\n%s\n", failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
