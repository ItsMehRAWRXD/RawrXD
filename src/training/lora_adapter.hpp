#pragma once

#include "../core/common.hpp"
#include "training_config.hpp"
#include <memory>
#include <unordered_map>

namespace rawrxd::training {

// LoRA weight pair (A and B matrices)
struct LoRAWeights {
    Tensor A;  // Down-projection (d x r)
    Tensor B;  // Up-projection (r x d)

    void initialize(int in_features, int out_features, int rank);
    void zeroInitialize();
};

// LoRA layer wrapper
class LoRALayer {
public:
    LoRALayer(const std::string& name, int in_features, int out_features,
              const LoRAConfig& config);

    // Forward pass with LoRA
    Tensor forward(const Tensor& input);

    // Get trainable parameters
    std::vector<Tensor*> getTrainableParameters();

    // Get parameter count
    size_t getParameterCount() const;

    // Merge into base weights
    void merge(Tensor& base_weight);
    void unmerge(Tensor& base_weight);

    // State
    bool isMerged() const { return merged_; }
    std::string getName() const { return name_; }

private:
    std::string name_;
    LoRAConfig config_;
    LoRAWeights weights_;
    bool merged_ = false;
    Tensor original_weight_;  // For unmerge
};

// LoRA adapter manager
class LoRAAdapter {
public:
    explicit LoRAAdapter(const LoRAConfig& config);
    ~LoRAAdapter() = default;

    // Initialize adapter for model
    bool initialize(std::shared_ptr<Model> model);

    // Add LoRA to specific modules
    void addLoRALayer(const std::string& module_name, int in_features, int out_features);

    // Forward with LoRA
    Tensor forward(const std::string& module_name, const Tensor& input, const Tensor& base_output);

    // Parameter management
    void setTrainable(bool trainable);
    std::vector<Tensor*> getTrainableParameters();
    size_t getTrainableParameterCount() const;

    // Merge/unmerge
    void merge(std::shared_ptr<Model> model);
    void unmerge(std::shared_ptr<Model> model);

    // Save/load
    bool saveAdapter(const std::string& path);
    bool loadAdapter(const std::string& path);

    // Get scaling factor
    float getScaling() const { return config_.getScaling(); }

    // List active LoRA layers
    std::vector<std::string> getLayerNames() const;

private:
    LoRAConfig config_;
    std::unordered_map<std::string, std::unique_ptr<LoRALayer>> layers_;
    std::shared_ptr<Model> model_;
    bool initialized_ = false;

    void parseTargetModules(const std::string& target_modules);
};

// Multi-LoRA support (for multiple adapters)
class MultiLoRAManager {
public:
    MultiLoRAManager() = default;

    // Add adapter
    void addAdapter(const std::string& name, std::shared_ptr<LoRAAdapter> adapter);

    // Switch active adapter
    void setActiveAdapter(const std::string& name);
    std::string getActiveAdapter() const { return active_adapter_; }

    // Combine adapters (linear interpolation)
    void combineAdapters(const std::vector<std::string>& adapters,
                         const std::vector<float>& weights);

    // List adapters
    std::vector<std::string> listAdapters() const;

    // Remove adapter
    void removeAdapter(const std::string& name);

private:
    std::unordered_map<std::string, std::shared_ptr<LoRAAdapter>> adapters_;
    std::string active_adapter_;
};

// LoRA utilities
namespace lora_utils {

// Check if module name matches target pattern
bool matchesTargetModule(const std::string& module_name,
                         const std::vector<std::string>& target_patterns);

// Estimate LoRA parameter count
size_t estimateParameterCount(int num_layers, int hidden_size, int rank,
                               const std::vector<std::string>& target_modules);

// Convert between adapter formats
bool convertAdapterFormat(const std::string& input_path,
                          const std::string& output_path,
                          const std::string& target_format);

} // namespace lora_utils

} // namespace rawrxd::training
