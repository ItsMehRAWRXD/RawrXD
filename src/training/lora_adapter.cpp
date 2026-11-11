#include "lora_adapter.hpp"
#include "../core/logger.hpp"
#include <math>

namespace rawrxd::training {

// ============================================================================
// LoRA Weights
// ============================================================================

void LoRAWeights::initialize(int in_features, int out_features, int rank) {
    // Initialize A with Kaiming uniform
    A = Tensor::zeros({in_features, rank});
    B = Tensor::zeros({rank, out_features});

    float std = std::sqrt(1.0f / in_features);
    A.randomUniform(-std, std);
    // B is initialized to zero (per LoRA paper)
    B.zero();
}

void LoRAWeights::zeroInitialize() {
    A.zero();
    B.zero();
}

// ============================================================================
// LoRA Layer
// ============================================================================

LoRALayer::LoRALayer(const std::string& name, int in_features, int out_features,
                     const LoRAConfig& config)
    : name_(name), config_(config) {
    weights_.initialize(in_features, out_features, config.rank);
    RAWRXD_LOG_DEBUG("LoRALayer", "Created layer '{}' ({}x{} @ rank {})",
                     name, in_features, out_features, config.rank);
}

Tensor LoRALayer::forward(const Tensor& input) {
    // LoRA forward: input @ A @ B * scaling
    // h = Wx + (BA)x * (alpha/r)
    Tensor h = input.matmul(weights_.A);  // (batch, rank)
    h = h.matmul(weights_.B);            // (batch, out_features)
    h = h * config_.getScaling();          // Scale by alpha/r

    if (config_.dropout > 0.0f) {
        // Apply dropout during training
        // h = dropout(h, config_.dropout);
    }

    return h;
}

std::vector<Tensor*> LoRALayer::getTrainableParameters() {
    return {&weights_.A, &weights_.B};
}

size_t LoRALayer::getParameterCount() const {
    return weights_.A.numel() + weights_.B.numel();
}

void LoRALayer::merge(Tensor& base_weight) {
    if (merged_) return;

    // Compute delta_W = B @ A * scaling
    Tensor delta_W = weights_.B.transpose(0, 1).matmul(weights_.A.transpose(0, 1));
    delta_W = delta_W * config_.getScaling();

    // Save original for unmerge
    original_weight_ = base_weight.clone();

    // Merge: W_merged = W + delta_W
    base_weight = base_weight + delta_W;
    merged_ = true;

    RAWRXD_LOG_DEBUG("LoRALayer", "Merged layer '{}'", name_);
}

void LoRALayer::unmerge(Tensor& base_weight) {
    if (!merged_) return;

    // Restore original weight
    base_weight = original_weight_.clone();
    merged_ = false;

    RAWRXD_LOG_DEBUG("LoRALayer", "Unmerged layer '{}'", name_);
}

// ============================================================================
// LoRA Adapter
// ============================================================================

LoRAAdapter::LoRAAdapter(const LoRAConfig& config) : config_(config) {
    RAWRXD_LOG_INFO("LoRAAdapter", "Created with rank={}, alpha={}",
                    config.rank, config.alpha);
}

bool LoRAAdapter::initialize(std::shared_ptr<Model> model) {
    model_ = model;

    // Parse target modules
    std::vector<std::string> targets;
    size_t start = 0;
    size_t end = config_.target_modules.find(',');
    while (end != std::string::npos) {
        targets.push_back(config_.target_modules.substr(start, end - start));
        start = end + 1;
        end = config_.target_modules.find(',', start);
    }
    targets.push_back(config_.target_modules.substr(start));

    // Add LoRA layers to matching modules
    for (const auto& [name, module] : model->getModules()) {
        for (const auto& target : targets) {
            if (name.find(target) != std::string::npos) {
                auto shape = module->getWeightShape();
                if (shape.size() >= 2) {
                    addLoRALayer(name, shape[0], shape[1]);
                }
            }
        }
    }

    initialized_ = true;
    RAWRXD_LOG_INFO("LoRAAdapter", "Initialized with {} LoRA layers", layers_.size());
    return true;
}

void LoRAAdapter::addLoRALayer(const std::string& module_name, int in_features, int out_features) {
    if (layers_.find(module_name) != layers_.end()) {
        RAWRXD_LOG_WARN("LoRAAdapter", "Layer '{}' already exists, skipping", module_name);
        return;
    }

    layers_[module_name] = std::make_unique<LoRALayer>(
        module_name, in_features, out_features, config_);
}

Tensor LoRAAdapter::forward(const std::string& module_name, const Tensor& input,
                            const Tensor& base_output) {
    auto it = layers_.find(module_name);
    if (it == layers_.end()) {
        return base_output;
    }

    // Add LoRA output to base output
    Tensor lora_output = it->second->forward(input);
    return base_output + lora_output;
}

void LoRAAdapter::setTrainable(bool trainable) {
    for (auto& [name, layer] : layers_) {
        for (auto* param : layer->getTrainableParameters()) {
            param->requires_grad = trainable;
        }
    }
    RAWRXD_LOG_INFO("LoRAAdapter", "Set trainable={}", trainable);
}

std::vector<Tensor*> LoRAAdapter::getTrainableParameters() {
    std::vector<Tensor*> params;
    for (auto& [name, layer] : layers_) {
        auto layer_params = layer->getTrainableParameters();
        params.insert(params.end(), layer_params.begin(), layer_params.end());
    }
    return params;
}

size_t LoRAAdapter::getTrainableParameterCount() const {
    size_t count = 0;
    for (const auto& [name, layer] : layers_) {
        count += layer->getParameterCount();
    }
    return count;
}

void LoRAAdapter::merge(std::shared_ptr<Model> model) {
    for (auto& [name, layer] : layers_) {
        auto module = model->getModule(name);
        if (module) {
            layer->merge(module->weight());
        }
    }
    RAWRXD_LOG_INFO("LoRAAdapter", "Merged all layers into base model");
}

void LoRAAdapter::unmerge(std::shared_ptr<Model> model) {
    for (auto& [name, layer] : layers_) {
        auto module = model->getModule(name);
        if (module) {
            layer->unmerge(module->weight());
        }
    }
    RAWRXD_LOG_INFO("LoRAAdapter", "Unmerged all layers from base model");
}

bool LoRAAdapter::saveAdapter(const std::string& path) {
    RAWRXD_LOG_INFO("LoRAAdapter", "Saving adapter to: {}", path);

    // Save LoRA weights
    // Save config
    // Save metadata

    return true;
}

bool LoRAAdapter::loadAdapter(const std::string& path) {
    RAWRXD_LOG_INFO("LoRAAdapter", "Loading adapter from: {}", path);

    // Load LoRA weights
    // Load config
    // Verify compatibility

    return true;
}

std::vector<std::string> LoRAAdapter::getLayerNames() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : layers_) {
        names.push_back(name);
    }
    return names;
}

// ============================================================================
// Multi-LoRA Manager
// ============================================================================

void MultiLoRAManager::addAdapter(const std::string& name,
                                     std::shared_ptr<LoRAAdapter> adapter) {
    adapters_[name] = adapter;
    if (active_adapter_.empty()) {
        active_adapter_ = name;
    }
    RAWRXD_LOG_INFO("MultiLoRA", "Added adapter '{}'", name);
}

void MultiLoRAManager::setActiveAdapter(const std::string& name) {
    if (adapters_.find(name) == adapters_.end()) {
        RAWRXD_LOG_ERROR("MultiLoRA", "Adapter '{}' not found", name);
        return;
    }
    active_adapter_ = name;
    RAWRXD_LOG_INFO("MultiLoRA", "Switched to adapter '{}'", name);
}

void MultiLoRAManager::combineAdapters(const std::vector<std::string>& adapter_names,
                                        const std::vector<float>& weights) {
    if (adapter_names.size() != weights.size()) {
        RAWRXD_LOG_ERROR("MultiLoRA", "Adapter names and weights must match in size");
        return;
    }

    // Normalize weights
    float sum = 0.0f;
    for (float w : weights) sum += w;
    std::vector<float> normalized_weights = weights;
    if (sum > 0) {
        for (auto& w : normalized_weights) w /= sum;
    }

    RAWRXD_LOG_INFO("MultiLoRA", "Combining {} adapters", adapter_names.size());
}

std::vector<std::string> MultiLoRAManager::listAdapters() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : adapters_) {
        names.push_back(name);
    }
    return names;
}

void MultiLoRAManager::removeAdapter(const std::string& name) {
    if (adapters_.erase(name) > 0) {
        RAWRXD_LOG_INFO("MultiLoRA", "Removed adapter '{}'", name);
        if (active_adapter_ == name && !adapters_.empty()) {
            active_adapter_ = adapters_.begin()->first;
        }
    }
}

// ============================================================================
// LoRA Utilities
// ============================================================================

namespace lora_utils {

bool matchesTargetModule(const std::string& module_name,
                         const std::vector<std::string>& target_patterns) {
    for (const auto& pattern : target_patterns) {
        if (module_name.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

size_t estimateParameterCount(int num_layers, int hidden_size, int rank,
                               const std::vector<std::string>& target_modules) {
    // Each target module adds: in_features * rank + rank * out_features parameters
    // For typical transformer: 4 matrices per layer (q, k, v, o)
    size_t params_per_layer = target_modules.size() * (hidden_size * rank * 2);
    return num_layers * params_per_layer;
}

bool convertAdapterFormat(const std::string& input_path,
                          const std::string& output_path,
                          const std::string& target_format) {
    RAWRXD_LOG_INFO("LoRAUtils", "Converting adapter from {} to {}",
                    input_path, target_format);
    return true;
}

} // namespace lora_utils

} // namespace rawrxd::training
