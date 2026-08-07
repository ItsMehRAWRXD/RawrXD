// ============================================================================
// Blocker #25: Logits Overflow Safety
// Constrains logits before sampler injection to prevent:
// - NaN/Inf from attention softmax
// - Extreme values causing sampler instability
// - Overflow in temperature scaling
// ============================================================================
#pragma once
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <limits>

namespace Deep2 {

class LogitsSafety {
public:
    // Clamp logits to safe range before temperature scaling
    static void ClampLogits(float* logits, size_t vocabSize, float minVal = -80.0f, float maxVal = 80.0f) {
        for (size_t i = 0; i < vocabSize; ++i) {
            if (std::isnan(logits[i]) || std::isinf(logits[i])) {
                logits[i] = 0.0f;
            } else {
                logits[i] = std::max(minVal, std::min(maxVal, logits[i]));
            }
        }
    }

    // Apply temperature scaling with overflow protection
    static void ApplyTemperatureSafe(float* logits, size_t vocabSize, float temperature) {
        if (temperature <= 0.0f) temperature = 1.0f;
        if (temperature < 0.01f) temperature = 0.01f; // Prevent division by near-zero
        
        // Find max for numerical stability
        float maxLogit = -std::numeric_limits<float>::infinity();
        for (size_t i = 0; i < vocabSize; ++i) {
            if (logits[i] > maxLogit) maxLogit = logits[i];
        }
        
        // Scale with max subtraction for stability
        float invTemp = 1.0f / temperature;
        for (size_t i = 0; i < vocabSize; ++i) {
            logits[i] = (logits[i] - maxLogit) * invTemp;
        }
    }

    // Softmax with numerical stability
    static void SoftmaxSafe(const float* input, float* output, size_t n) {
        if (n == 0) return;
        
        // Find max for numerical stability
        float maxVal = input[0];
        for (size_t i = 1; i < n; ++i) {
            if (input[i] > maxVal) maxVal = input[i];
        }
        
        // Compute exp(x - max) with clamping
        float sum = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            float expVal = std::exp(std::min(input[i] - maxVal, 88.0f)); // e^88 < FLT_MAX
            output[i] = expVal;
            sum += expVal;
        }
        
        // Normalize
        if (sum > 0.0f) {
            float invSum = 1.0f / sum;
            for (size_t i = 0; i < n; ++i) {
                output[i] *= invSum;
            }
        }
    }

    // Validate logits are safe (no NaN/Inf)
    static bool ValidateLogits(const float* logits, size_t vocabSize) {
        for (size_t i = 0; i < vocabSize; ++i) {
            if (std::isnan(logits[i]) || std::isinf(logits[i])) {
                return false;
            }
        }
        return true;
    }

    // Fix corrupted logits by replacing NaN/Inf with zeros
    static size_t FixCorruptedLogits(float* logits, size_t vocabSize) {
        size_t fixed = 0;
        for (size_t i = 0; i < vocabSize; ++i) {
            if (std::isnan(logits[i]) || std::isinf(logits[i])) {
                logits[i] = 0.0f;
                fixed++;
            }
        }
        return fixed;
    }
};

} // namespace Deep2
