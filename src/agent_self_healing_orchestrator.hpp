#pragma once

#include "runtime/CoreTypes.hpp"
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <future>
#include <optional>
#include <iostream>

namespace RawrXD {

// All canonical type definitions live in CoreTypes.hpp
// (TensorView, LayerKernel, OptimizationSnapshot, GenerationConfig, ModelStats, Task)

class RuntimeUntuner {
public:
    void SaveBaseline(const OptimizationSnapshot& s) {
        baseline = s;
    }

    bool DetectRegression(const OptimizationSnapshot& current) {
        return current.tokens_per_second < baseline.tokens_per_second * 0.90;
    }

    void Restore() {
        Apply(baseline);
    }
private:
    OptimizationSnapshot baseline;
    void Apply(const OptimizationSnapshot& s) {
        // Un-tune or roll back settings
    }
};

struct LayerDecision {
    uint32_t layerId;
    bool verified;
    bool replaceable;
    float qualityScore;
    float latencyScore;
};

class LayerArbiter {
public:
    LayerDecision Evaluate(uint32_t layer, const TensorView& activation) {
        // Extract real metrics from activation tensor
        float mean = 0.0f, variance = 0.0f;
        size_t count = activation.size();
        if (count > 0) {
            for (size_t i = 0; i < count; ++i) {
                mean += activation.data[i];
            }
            mean /= count;
            for (size_t i = 0; i < count; ++i) {
                float diff = activation.data[i] - mean;
                variance += diff * diff;
            }
            variance /= count;
        }
        float confidence = 1.0f / (1.0f + std::sqrt(variance + 1e-6f));
        bool healthy = variance < 1.0f && !std::isnan(mean);
        return {layer, healthy, true, confidence, variance};
    }

    bool ReplaceLayer(uint32_t layer, const LayerKernel& replacement) {
        active_kernels[layer] = replacement;
        return true;
    }

    void ExecuteNonBlocking(uint32_t layer) {
        // Async execution of the layer kernel
    }
    
private:
    std::unordered_map<uint32_t, LayerKernel> active_kernels;
};

class LayerRegistry {
public:
    void Register(uint32_t id, LayerKernel kernel) {
        kernels[id] = kernel;
    }

    LayerKernel Get(uint32_t id) {
        return kernels[id];
    }

    void Swap(uint32_t id, LayerKernel kernel) {
        kernels[id] = kernel;
    }
private:
    std::unordered_map<uint32_t, LayerKernel> kernels;
};

// GenerationConfig, ModelStats, IModelProvider, Task now in CoreTypes.hpp

class SovereignMetaRuntime {
public:
    void AddProvider(const std::string& name, std::shared_ptr<IModelProvider> provider);
    IModelProvider* Select(const Task& task);

private:
    std::unordered_map<std::string, std::shared_ptr<IModelProvider>> providers;
    LayerArbiter arbiter;
    RuntimeUntuner untuner;
    LayerRegistry layer_registry;
};

} // namespace RawrXD
