#pragma once

#include "../training_config.hpp"
#include <memory>

namespace rawrxd::training {

// Memory optimization techniques for training
class MemoryOptimizer {
public:
    // Gradient checkpointing - trade compute for memory
    class GradientCheckpointing {
    public:
        void enable();
        void disable();
        bool isEnabled() const { return enabled_; }

        // Mark layer for checkpointing
        void checkpointLayer(const std::string& layer_name);

        // Forward with checkpointing
        Tensor forward(const Tensor& input, const std::vector<std::string>& layer_names);

    private:
        bool enabled_ = false;
        std::vector<std::string> checkpointed_layers_;
        std::unordered_map<std::string, Tensor> saved_activations_;
    };

    // Activation checkpointing
    class ActivationCheckpointing {
    public:
        void checkpoint(const Tensor& activation, const std::string& key);
        Tensor retrieve(const std::string& key);
        void clear();

    private:
        std::unordered_map<std::string, Tensor> checkpoints_;
    };

    // CPU offloading for optimizer states
    class CPUOffload {
    public:
        void enable() { enabled_ = true; }
        void disable() { enabled_ = false; }

        // Offload tensor to CPU
        void offload(Tensor& tensor);

        // Prefetch to GPU before use
        void prefetch(Tensor& tensor);

        bool isEnabled() const { return enabled_; }

    private:
        bool enabled_ = false;
    };

    // ZeRO-style optimization (sharded optimizer states)
    class ZeROOptimizer {
    public:
        enum Stage {
            STAGE_0 = 0,  // No sharding
            STAGE_1 = 1,  // Shard optimizer states
            STAGE_2 = 2,  // Shard gradients + optimizer states
            STAGE_3 = 3   // Shard parameters + gradients + optimizer states
        };

        void setStage(Stage stage) { stage_ = stage; }
        Stage getStage() const { return stage_; }

        void shardParameters(std::vector<Tensor*>& parameters, int world_size, int rank);
        void shardGradients(std::vector<Tensor*>& gradients, int world_size, int rank);

    private:
        Stage stage_ = STAGE_0;
    };

    // Flash Attention for memory-efficient attention
    class FlashAttention {
    public:
        void enable() { enabled_ = true; }
        void disable() { enabled_ = false; }
        bool isEnabled() const { return enabled_; }

        // Compute attention with memory-efficient algorithm
        Tensor forward(const Tensor& query, const Tensor& key, const Tensor& value,
                       const std::optional<Tensor>& mask = std::nullopt);

    private:
        bool enabled_ = false;
    };

    // Memory profiling
    class MemoryProfiler {
    public:
        void startProfiling();
        void endProfiling();

        struct MemoryStats {
            size_t peak_allocated = 0;
            size_t current_allocated = 0;
            size_t peak_reserved = 0;
            size_t current_reserved = 0;
        };

        MemoryStats getStats() const;
        void printReport() const;

    private:
        bool profiling_ = false;
        MemoryStats stats_;
    };

    // Combined memory optimization
    static void optimizeForTraining(TrainingConfig& config,
                                     size_t available_memory_gb);

    // Estimate memory requirements
    static size_t estimateMemory(const TrainingConfig& config,
                                  size_t model_size_bytes);
};

} // namespace rawrxd::training
