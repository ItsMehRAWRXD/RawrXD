#pragma once
/**
 * @file CoreTypes.hpp
 * @brief Canonical type definitions - eliminates ODR violations
 * 
 * All shared types live here. No more duplicate struct definitions.
 */

#include <functional>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace RawrXD {

struct TensorView {
    float* data;
    size_t size;
    size_t stride;
    std::vector<size_t> shape;
};

struct LayerKernel {
    std::string name;
    std::function<bool(const TensorView& input, TensorView& output)> execute;
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
    size_t num_parameters;
    std::string quantization;
};

struct Task {
    std::string prompt;
    bool requires_privacy = false;
    bool requires_speed = false;
    bool requires_reasoning = false;
};

class IModelProvider {
public:
    virtual ~IModelProvider() = default;
    virtual bool Load(const std::string& model) = 0;
    virtual std::string Generate(const std::string& prompt, const GenerationConfig& cfg) = 0;
    virtual ModelStats Stats() = 0;
};

} // namespace RawrXD
