// RawrXD Model Pruning Implementation
// Phase AK: Model Optimization Suite

#include "pruning.hpp"
#include <algorithm>
#include <cmath>
#include <chrono>
#include <numeric>

namespace rawrxd {
namespace optimization {

// Global pruning manager instance
static std::unique_ptr<PruningManager> g_pruning_manager;

PruningManager* getPruningManager() {
    return g_pruning_manager.get();
}

void setPruningManager(std::unique_ptr<PruningManager> manager) {
    g_pruning_manager = std::move(manager);
}

// PruningManager implementation
PruningManager::PruningManager() : initialized_(false) {}

PruningManager::~PruningManager() = default;

bool PruningManager::initialize() {
    // Register pruners
    pruners_[PruningStrategy::MAGNITUDE] = std::make_shared<MagnitudePruner>();
    pruners_[PruningStrategy::STRUCTURED] = std::make_shared<StructuredPruner>();
    
    initialized_ = true;
    return true;
}

SparseTensor PruningManager::prune(const float* data, const std::vector<int>& shape,
                                     const PruningConfig& config) {
    auto pruner = getPruner(config.strategy);
    if (!pruner) {
        throw std::runtime_error("Pruner not available for strategy");
    }
    
    return pruner->prune(data, shape, config.sparsity_target);
}

bool PruningManager::pruneModel(const std::string& input_path, const std::string& output_path,
                                const PruningConfig& config, PruningStats* stats) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // This is a simplified implementation
    // In production, this would:
    // 1. Load model
    // 2. Iterate through layers
    // 3. Prune each layer
    // 4. Optionally retrain
    // 5. Save pruned model
    
    if (stats) {
        auto end_time = std::chrono::high_resolution_clock::now();
        stats->processing_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    }
    
    return true;
}

std::shared_ptr<IPruner> PruningManager::getPruner(PruningStrategy strategy) {
    auto it = pruners_.find(strategy);
    if (it != pruners_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<PruningStrategy> PruningManager::getSupportedStrategies() const {
    std::vector<PruningStrategy> strategies;
    for (const auto& [strategy, _] : pruners_) {
        strategies.push_back(strategy);
    }
    return strategies;
}

bool PruningManager::isStrategySupported(PruningStrategy strategy) const {
    return pruners_.find(strategy) != pruners_.end();
}

std::string PruningManager::getStrategyName(PruningStrategy strategy) const {
    switch (strategy) {
        case PruningStrategy::MAGNITUDE: return "Magnitude";
        case PruningStrategy::STRUCTURED: return "Structured";
        case PruningStrategy::UNSTRUCTURED: return "Unstructured";
        case PruningStrategy::GRADIENT_BASED: return "Gradient-based";
        case PruningStrategy::MOVEMENT: return "Movement";
        case PruningStrategy::L0_REGULARIZATION: return "L0 Regularization";
        case PruningStrategy::LOTTERY_TICKET: return "Lottery Ticket";
        case PruningStrategy::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

std::string PruningManager::getStrategyDescription(PruningStrategy strategy) const {
    switch (strategy) {
        case PruningStrategy::MAGNITUDE:
            return "Removes weights with smallest absolute values";
        case PruningStrategy::STRUCTURED:
            return "Removes entire channels or neurons for hardware efficiency";
        case PruningStrategy::UNSTRUCTURED:
            return "Removes individual weights without structure constraints";
        case PruningStrategy::GRADIENT_BASED:
            return "Removes weights based on gradient magnitude";
        case PruningStrategy::MOVEMENT:
            return "Uses movement-based criteria for pruning";
        case PruningStrategy::L0_REGULARIZATION:
            return "Uses L0 regularization to induce sparsity";
        case PruningStrategy::LOTTERY_TICKET:
            return "Finds sparse subnetworks that train well";
        default:
            return "Custom pruning strategy";
    }
}

// MagnitudePruner implementation
SparseTensor MagnitudePruner::prune(const float* data, const std::vector<int>& shape,
                                     float sparsity_target) {
    SparseTensor result;
    result.shape = shape;
    
    // Calculate total elements
    size_t total_elements = 1;
    for (int dim : shape) {
        total_elements *= dim;
    }
    
    // Create vector of (index, magnitude) pairs
    std::vector<std::pair<size_t, float>> indexed_magnitudes;
    indexed_magnitudes.reserve(total_elements);
    
    for (size_t i = 0; i < total_elements; ++i) {
        indexed_magnitudes.push_back({i, std::abs(data[i])});
    }
    
    // Sort by magnitude (ascending)
    std::sort(indexed_magnitudes.begin(), indexed_magnitudes.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });
    
    // Calculate number of elements to keep
    size_t num_to_keep = static_cast<size_t>(total_elements * (1.0f - sparsity_target));
    
    // Keep top-k elements by magnitude
    result.values.reserve(num_to_keep);
    result.indices.reserve(num_to_keep);
    
    for (size_t i = indexed_magnitudes.size() - num_to_keep; i < indexed_magnitudes.size(); ++i) {
        size_t idx = indexed_magnitudes[i].first;
        result.indices.push_back(static_cast<int>(idx));
        result.values.push_back(data[idx]);
    }
    
    // Sort indices for cache efficiency
    std::vector<size_t> sort_order(result.indices.size());
    std::iota(sort_order.begin(), sort_order.end(), 0);
    std::sort(sort_order.begin(), sort_order.end(),
              [&result](size_t a, size_t b) {
                  return result.indices[a] < result.indices[b];
              });
    
    // Reorder values and indices
    std::vector<float> sorted_values;
    std::vector<int> sorted_indices;
    sorted_values.reserve(result.values.size());
    sorted_indices.reserve(result.indices.size());
    
    for (size_t idx : sort_order) {
        sorted_values.push_back(result.values[idx]);
        sorted_indices.push_back(result.indices[idx]);
    }
    
    result.values = std::move(sorted_values);
    result.indices = std::move(sorted_indices);
    result.sparsity = static_cast<float>(total_elements - result.values.size()) / total_elements;
    
    return result;
}

// StructuredPruner implementation
SparseTensor StructuredPruner::prune(const float* data, const std::vector<int>& shape,
                                      float sparsity_target) {
    SparseTensor result;
    result.shape = shape;
    
    // For structured pruning, we assume the last dimension is channels
    // and we prune entire channels based on their L1 norm
    
    if (shape.size() < 2) {
        // Fall back to magnitude pruning for 1D tensors
        MagnitudePruner fallback;
        return fallback.prune(data, shape, sparsity_target);
    }
    
    size_t channels = shape.back();
    size_t elements_per_channel = 1;
    for (size_t i = 0; i < shape.size() - 1; ++i) {
        elements_per_channel *= shape[i];
    }
    
    // Calculate L1 norm for each channel
    std::vector<std::pair<size_t, float>> channel_norms;
    channel_norms.reserve(channels);
    
    for (size_t c = 0; c < channels; ++c) {
        float l1_norm = 0.0f;
        for (size_t i = 0; i < elements_per_channel; ++i) {
            size_t idx = i * channels + c;
            l1_norm += std::abs(data[idx]);
        }
        channel_norms.push_back({c, l1_norm});
    }
    
    // Sort channels by L1 norm
    std::sort(channel_norms.begin(), channel_norms.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });
    
    // Determine which channels to keep
    size_t num_channels_to_keep = static_cast<size_t>(channels * (1.0f - sparsity_target));
    std::vector<bool> keep_channel(channels, false);
    
    for (size_t i = channel_norms.size() - num_channels_to_keep; i < channel_norms.size(); ++i) {
        keep_channel[channel_norms[i].first] = true;
    }
    
    // Collect remaining elements
    size_t total_elements = elements_per_channel * channels;
    for (size_t i = 0; i < total_elements; ++i) {
        size_t channel = i % channels;
        if (keep_channel[channel]) {
            result.indices.push_back(static_cast<int>(i));
            result.values.push_back(data[i]);
        }
    }
    
    result.sparsity = static_cast<float>(total_elements - result.values.size()) / total_elements;
    
    return result;
}

} // namespace optimization
} // namespace rawrxd
