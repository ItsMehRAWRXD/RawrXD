// RawrXD Model Pruning Interface
// Phase AK: Model Optimization Suite

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace rawrxd {
namespace optimization {

// Pruning strategies
enum class PruningStrategy {
    MAGNITUDE,          // Remove weights with smallest absolute values
    STRUCTURED,         // Remove entire channels/neurons
    UNSTRUCTURED,       // Remove individual weights
    GRADIENT_BASED,     // Remove based on gradient magnitude
    MOVEMENT,           // Movement-based pruning
    L0_REGULARIZATION,  // L0 regularization
    LOTTERY_TICKET,     // Lottery ticket hypothesis
    CUSTOM
};

// Pruning configuration
struct PruningConfig {
    PruningStrategy strategy;
    float sparsity_target;      // Target sparsity (0.0 - 1.0)
    int pruning_steps;          // Number of pruning iterations
    float pruning_rate;         // Rate of pruning per step
    bool retrain_after_prune;   // Retrain after pruning
    int retrain_epochs;         // Epochs for retraining
    float learning_rate;        // Learning rate for retraining
    
    PruningConfig()
        : strategy(PruningStrategy::MAGNITUDE)
        , sparsity_target(0.5f)
        , pruning_steps(10)
        , pruning_rate(0.1f)
        , retrain_after_prune(true)
        , retrain_epochs(5)
        , learning_rate(0.001f) {}
};

// Pruning statistics
struct PruningStats {
    float initial_sparsity;
    float final_sparsity;
    size_t parameters_before;
    size_t parameters_after;
    float accuracy_before;
    float accuracy_after;
    float compression_ratio;
    double processing_time_ms;
    
    PruningStats()
        : initial_sparsity(0.0f)
        , final_sparsity(0.0f)
        , parameters_before(0)
        , parameters_after(0)
        , accuracy_before(0.0f)
        , accuracy_after(0.0f)
        , compression_ratio(1.0f)
        , processing_time_ms(0.0) {}
};

// Sparse tensor representation
struct SparseTensor {
    std::vector<float> values;
    std::vector<int> indices;
    std::vector<int> shape;
    float sparsity;
    
    size_t nnz() const { return values.size(); }
    size_t totalElements() const {
        size_t total = 1;
        for (int dim : shape) total *= dim;
        return total;
    }
};

// Forward declarations
class IPruner;
class PruningPipeline;

/**
 * PruningManager - Central pruning management
 */
class PruningManager {
public:
    PruningManager();
    ~PruningManager();
    
    // Initialize pruning system
    bool initialize();
    
    // Prune tensor
    SparseTensor prune(const float* data, const std::vector<int>& shape,
                       const PruningConfig& config);
    
    // Prune model
    bool pruneModel(const std::string& input_path, const std::string& output_path,
                    const PruningConfig& config, PruningStats* stats = nullptr);
    
    // Get pruner for strategy
    std::shared_ptr<IPruner> getPruner(PruningStrategy strategy);
    
    // Supported strategies
    std::vector<PruningStrategy> getSupportedStrategies() const;
    bool isStrategySupported(PruningStrategy strategy) const;
    
    // Strategy information
    std::string getStrategyName(PruningStrategy strategy) const;
    std::string getStrategyDescription(PruningStrategy strategy) const;
    
private:
    std::unordered_map<PruningStrategy, std::shared_ptr<IPruner>> pruners_;
    bool initialized_;
};

/**
 * IPruner - Base pruner interface
 */
class IPruner {
public:
    virtual ~IPruner() = default;
    
    // Prune tensor
    virtual SparseTensor prune(const float* data, const std::vector<int>& shape,
                                float sparsity_target) = 0;
    
    // Get pruner info
    virtual PruningStrategy getStrategy() const = 0;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
};

/**
 * MagnitudePruner - Magnitude-based pruning
 */
class MagnitudePruner : public IPruner {
public:
    SparseTensor prune(const float* data, const std::vector<int>& shape,
                       float sparsity_target) override;
    PruningStrategy getStrategy() const override { return PruningStrategy::MAGNITUDE; }
    std::string getName() const override { return "Magnitude Pruning"; }
    std::string getDescription() const override {
        return "Removes weights with smallest absolute values";
    }
};

/**
 * StructuredPruner - Structured pruning
 */
class StructuredPruner : public IPruner {
public:
    SparseTensor prune(const float* data, const std::vector<int>& shape,
                       float sparsity_target) override;
    PruningStrategy getStrategy() const override { return PruningStrategy::STRUCTURED; }
    std::string getName() const override { return "Structured Pruning"; }
    std::string getDescription() const override {
        return "Removes entire channels or neurons";
    }
};

// Global pruning manager accessor
PruningManager* getPruningManager();
void setPruningManager(std::unique_ptr<PruningManager> manager);

} // namespace optimization
} // namespace rawrxd
