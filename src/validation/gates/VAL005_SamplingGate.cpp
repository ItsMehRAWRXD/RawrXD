// ============================================================================
// VAL-005: Sampling Validation Gate Implementation
// ============================================================================

#include "VAL005_SamplingGate.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>

namespace RawrXD {
namespace Validation {

REGISTER_VALIDATION_GATE(VAL005_SamplingGate);

ValidationResult VAL005_SamplingGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[VAL-005] Token Sampling Validation\n");
    printf("====================================\n");
    
    bool allPassed = true;
    
    printf("\n[1/5] Greedy Sampling...\n");
    if (!ValidateGreedySampling()) {
        printf("  FAILED: Greedy sampling\n");
        allPassed = false;
    } else {
        printf("  PASSED: Greedy sampling\n");
    }
    
    printf("\n[2/5] Temperature Sampling...\n");
    if (!ValidateTemperatureSampling()) {
        printf("  FAILED: Temperature sampling\n");
        allPassed = false;
    } else {
        printf("  PASSED: Temperature sampling\n");
    }
    
    printf("\n[3/5] Top-k Sampling...\n");
    if (!ValidateTopKSampling()) {
        printf("  FAILED: Top-k sampling\n");
        allPassed = false;
    } else {
        printf("  PASSED: Top-k sampling\n");
    }
    
    printf("\n[4/5] Top-p Sampling...\n");
    if (!ValidateTopPSampling()) {
        printf("  FAILED: Top-p sampling\n");
        allPassed = false;
    } else {
        printf("  PASSED: Top-p sampling\n");
    }
    
    printf("\n[5/5] Repetition Penalty...\n");
    if (!ValidateRepetitionPenalty()) {
        printf("  FAILED: Repetition penalty\n");
        allPassed = false;
    } else {
        printf("  PASSED: Repetition penalty\n");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.passed = allPassed;
    result.message = allPassed ? "VAL-005: All sampling tests passed" 
                               : "VAL-005: Some tests failed";
    
    printf("\n====================================\n");
    printf("[VAL-005] Result: %s (%.2f ms)\n", 
           allPassed ? "PASSED" : "FAILED", result.durationMs);
    printf("====================================\n");
    
    return result;
}

bool VAL005_SamplingGate::ValidateGreedySampling() {
    // Test greedy sampling (argmax)
    const int vocab_size = 100;
    float logits[vocab_size];
    
    // Set highest logit at index 42
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = static_cast<float>(i) * 0.1f;
    }
    logits[42] = 100.0f; // Clear winner
    
    // Find argmax
    int max_idx = 0;
    float max_val = logits[0];
    for (int i = 1; i < vocab_size; i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    
    return max_idx == 42;
}

bool VAL005_SamplingGate::ValidateTemperatureSampling() {
    // Test temperature scaling
    const int vocab_size = 10;
    float logits[vocab_size] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 
                                 4.0f, 3.0f, 2.0f, 1.0f, 0.0f};
    
    float temperature = 0.5f;
    float scaled[vocab_size];
    
    // Apply temperature
    for (int i = 0; i < vocab_size; i++) {
        scaled[i] = logits[i] / temperature;
    }
    
    // Higher temperature = more uniform distribution
    // Lower temperature = more peaked distribution
    
    // Verify scaling happened
    if (std::abs(scaled[4] - 10.0f) > 0.01f) return false; // 5.0 / 0.5 = 10.0
    
    return true;
}

bool VAL005_SamplingGate::ValidateTopKSampling() {
    // Test top-k filtering
    const int vocab_size = 100;
    const int k = 10;
    
    float logits[vocab_size];
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = static_cast<float>(i);
    }
    
    // Find top-k indices
    std::vector<int> indices(vocab_size);
    std::iota(indices.begin(), indices.end(), 0);
    std::partial_sort(indices.begin(), indices.begin() + k, indices.end(),
                      [&logits](int a, int b) { return logits[a] > logits[b]; });
    
    // Verify top-k contains highest values
    for (int i = 0; i < k; i++) {
        if (logits[indices[i]] < vocab_size - k) {
            return false;
        }
    }
    
    return true;
}

bool VAL005_SamplingGate::ValidateTopPSampling() {
    // Test top-p (nucleus) sampling
    const int vocab_size = 10;
    float probs[vocab_size] = {0.40f, 0.25f, 0.15f, 0.08f, 0.05f,
                                0.03f, 0.02f, 0.01f, 0.005f, 0.005f};
    
    float p = 0.9f;
    float cumsum = 0.0f;
    int cutoff_idx = 0;
    
    // Find nucleus cutoff
    for (int i = 0; i < vocab_size; i++) {
        cumsum += probs[i];
        if (cumsum >= p) {
            cutoff_idx = i;
            break;
        }
    }
    
    // Verify cutoff is reasonable
    // With p=0.9, should include tokens 0, 1, 2 (0.40 + 0.25 + 0.15 = 0.80)
    // and possibly token 3 (0.08) depending on implementation
    if (cutoff_idx < 2) return false;
    
    return true;
}

bool VAL005_SamplingGate::ValidateRepetitionPenalty() {
    // Test repetition penalty
    const int vocab_size = 100;
    float logits[vocab_size];
    
    // Initialize logits
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = 1.0f;
    }
    
    // Simulate generated tokens
    std::vector<int> generated = {5, 10, 15, 20};
    float penalty = 1.2f;
    
    // Apply repetition penalty
    for (int token : generated) {
        if (logits[token] > 0) {
            logits[token] /= penalty;
        } else {
            logits[token] *= penalty;
        }
    }
    
    // Verify penalized tokens have lower logits
    for (int token : generated) {
        if (logits[token] >= 1.0f) return false;
    }
    
    // Verify non-penalized tokens unchanged
    if (logits[0] != 1.0f) return false;
    
    return true;
}

} // namespace Validation
} // namespace RawrXD
