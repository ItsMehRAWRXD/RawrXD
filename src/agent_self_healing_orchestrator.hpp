#pragma once

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

struct TensorView {
    float* data;
    size_t size;
};

struct OptimizationSnapshot {
    float temperature;
    float top_p;
    int top_k;
    int active_layers;
    bool fused_attention;
    size_t kv_cache_size;
    double tokens_per_second;
};

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

struct LayerKernel {
    std::string name;
    std::function<bool(const TensorView& input, TensorView& output)> execute;
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
        // Placeholder metric extraction
        return {layer, true, true, 0.95f, 0.05f};
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

struct GenerationConfig {
    float temperature;
    float top_p;
    int top_k;
    float repetition_penalty;
    uint32_t max_new_tokens;
    uint32_t nextn_predict_layers;
};

struct ModelStats {
    double tokens_per_sec;
    size_t memory_used;
};

class IModelProvider {
public:
    virtual ~IModelProvider() = default;
    virtual bool Load(const std::string& model) = 0;
    virtual std::string Generate(const std::string& prompt, const GenerationConfig& cfg) = 0;
    virtual ModelStats Stats() = 0;
};

struct Task {
    std::string prompt;
    bool requires_privacy = false;
    bool requires_speed = false;
    bool requires_reasoning = false;
};

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
