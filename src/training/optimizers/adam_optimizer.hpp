#pragma once

#include "../training_config.hpp"
#include <vector>

namespace rawrxd::training {

// Adam/AdamW optimizer
class AdamOptimizer {
public:
    AdamOptimizer(float lr = 1e-3f,
                  float beta1 = 0.9f,
                  float beta2 = 0.999f,
                  float eps = 1e-8f,
                  float weight_decay = 0.01f,
                  bool adamw = true);

    // Initialize state for parameters
    void initialize(const std::vector<Tensor*>& parameters);

    // Single optimization step
    void step();

    // Zero gradients
    void zeroGrad();

    // Learning rate scheduling
    void setLearningRate(float lr) { learning_rate_ = lr; }
    float getLearningRate() const { return learning_rate_; }

    // State access
    uint64_t getStep() const { return step_; }

private:
    float learning_rate_;
    float beta1_;
    float beta2_;
    float eps_;
    float weight_decay_;
    bool adamw_;

    uint64_t step_ = 0;
    std::vector<Tensor*> parameters_;
    std::vector<Tensor> m_;  // First moment
    std::vector<Tensor> v_;  // Second moment
};

// 8-bit Adam optimizer (for memory efficiency)
class Adam8bitOptimizer : public AdamOptimizer {
public:
    Adam8bitOptimizer(float lr = 1e-3f,
                       float beta1 = 0.9f,
                       float beta2 = 0.999f,
                       float eps = 1e-8f,
                       float weight_decay = 0.01f);

    void step() override;

private:
    // Quantized state storage
    std::vector<std::vector<uint8_t>> m_quantized_;
    std::vector<std::vector<uint8_t>> v_quantized_;
};

// Lion optimizer (memory efficient)
class LionOptimizer {
public:
    LionOptimizer(float lr = 1e-4f,
                    float beta1 = 0.9f,
                    float beta2 = 0.99f,
                    float weight_decay = 0.0f);

    void initialize(const std::vector<Tensor*>& parameters);
    void step();
    void zeroGrad();

private:
    float learning_rate_;
    float beta1_;
    float beta2_;
    float weight_decay_;
    uint64_t step_ = 0;

    std::vector<Tensor*> parameters_;
    std::vector<Tensor> momentum_;  // Only one momentum vector (memory efficient)
};

// Optimizer factory
std::unique_ptr<AdamOptimizer> createOptimizer(OptimizerType type,
                                                const TrainingConfig& config);

} // namespace rawrxd::training
