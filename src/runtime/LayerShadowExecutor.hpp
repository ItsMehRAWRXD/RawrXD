#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <future>
#include <chrono>
#include "RuntimeTypes.hpp"
#include "LayerVersionRegistry.hpp"

namespace RawrXD {

struct VerificationResult {
    float cosine_similarity;
    float max_error;
    double latency_delta;
    bool accepted;
};

class LayerShadowExecutor {
public:
    LayerShadowExecutor(LayerRegistryManager& registry) : layerRegistry(registry) {}
    
    // Asynchronously evaluates a candidate kernel without blocking generation
    std::future<VerificationResult> EvaluateCandidateAsync(
        uint32_t layerId,
        LayerKernel candidateKernel,
        const TensorView& input,
        const TensorView& baselineOutput) {
        
        return std::async(std::launch::async, [this, layerId, candidateKernel, input, baselineOutput]() {
            auto start = std::chrono::steady_clock::now();
            
            // Execute candidate kernel
            std::vector<float> shadowData(baselineOutput.size);
            TensorView shadowOutput{shadowData.data(), shadowData.size()};
            bool success = candidateKernel.execute(input, shadowOutput);
            
            auto end = std::chrono::steady_clock::now();
            double latency = std::chrono::duration<double, std::milli>(end - start).count();
            
            if (!success) {
                return VerificationResult{0.0f, 1e9f, latency, false};
            }
            
            // Compare results
            float maxError = 0.0f;
            float dotProduct = 0.0f, normA = 0.0f, normB = 0.0f;
            
            for (size_t i = 0; i < input.size; ++i) {
                float diff = std::abs(baselineOutput.data[i] - shadowOutput.data[i]);
                maxError = std::max(maxError, diff);
                
                dotProduct += baselineOutput.data[i] * shadowOutput.data[i];
                normA += baselineOutput.data[i] * baselineOutput.data[i];
                normB += shadowOutput.data[i] * shadowOutput.data[i];
            }
            
            float cosineSim = (normA > 0 && normB > 0) ? dotProduct / (std::sqrt(normA) * std::sqrt(normB)) : 0.0f;
            
            // Compare against current baseline runtime performance
            // Normally you would fetch the baseline latency from the registry or telemetry
            double baselineLatency = 5.0; // Placeholder for 5ms
            double latencyDelta = latency - baselineLatency;
            
            // Rejection criteria
            bool accepted = (cosineSim > 0.999f) && (latencyDelta < 0.0);
            
            return VerificationResult{cosineSim, maxError, latencyDelta, accepted};
        });
    }

private:
    LayerRegistryManager& layerRegistry;
};

} // namespace RawrXD
