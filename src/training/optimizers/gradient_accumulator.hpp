#pragma once

#include "../training_config.hpp"
#include <vector>
#include <mutex>

namespace rawrxd::training {

// Gradient accumulator for large batch simulation
class GradientAccumulator {
public:
    explicit GradientAccumulator(uint64_t accumulation_steps = 1);

    // Add gradient to accumulation
    void accumulate(const std::vector<Tensor>& gradients);

    // Check if ready to step
    bool isReady() const { return current_step_ >= accumulation_steps_; }

    // Get accumulated gradients and reset
    std::vector<Tensor> getAccumulatedGradients();

    // Reset accumulation
    void reset();

    // Scale gradients by accumulation steps
    void scaleGradients();

    // Current state
    uint64_t getCurrentStep() const { return current_step_; }
    uint64_t getAccumulationSteps() const { return accumulation_steps_; }
    void setAccumulationSteps(uint64_t steps) { accumulation_steps_ = steps; reset(); }

    // Effective batch size
    size_t getEffectiveBatchSize(size_t base_batch_size) const {
        return base_batch_size * accumulation_steps_;
    }

private:
    uint64_t accumulation_steps_;
    uint64_t current_step_ = 0;
    std::vector<Tensor> accumulated_gradients_;
    std::mutex mutex_;
};

// Gradient clipping
class GradientClipper {
public:
    explicit GradientClipper(float max_norm = 1.0f) : max_norm_(max_norm) {}

    // Clip gradients by norm
    float clipGradients(std::vector<Tensor>& gradients);

    // Clip by value
    void clipByValue(std::vector<Tensor>& gradients, float min_val, float max_val);

    // Get global norm
    static float computeGlobalNorm(const std::vector<Tensor>& gradients);

    void setMaxNorm(float max_norm) { max_norm_ = max_norm; }
    float getMaxNorm() const { return max_norm_; }

private:
    float max_norm_;
};

// Gradient scaling for mixed precision
class GradientScaler {
public:
    GradientScaler(float init_scale = 65536.0f,
                   float growth_factor = 2.0f,
                   float backoff_factor = 0.5f,
                   int growth_interval = 2000);

    // Scale loss before backward
    float scale(float loss) const { return loss * current_scale_; }

    // Unscale gradients
    void unscaleGradients(std::vector<Tensor>& gradients);

    // Update scale based on gradient inf/nan
    void update(bool found_inf);

    // Get current scale
    float getScale() const { return current_scale_; }
    int getGrowthInterval() const { return growth_interval_; }

    // State
    bool isEnabled() const { return enabled_; }
    void setEnabled(bool enabled) { enabled_ = enabled; }

private:
    float current_scale_;
    float growth_factor_;
    float backoff_factor_;
    int growth_interval_;
    int step_ = 0;
    bool enabled_ = true;
};

// Combined gradient handler
class GradientHandler {
public:
    GradientHandler(const TrainingConfig& config);

    // Process gradients (accumulate, clip, scale)
    bool processGradients(std::vector<Tensor>& gradients, bool is_last_microbatch);

    // Check if ready for optimizer step
    bool isReadyForStep() const;

    // Pre-step processing
    void preStep(std::vector<Tensor>& gradients);

    // Access components
    GradientAccumulator& getAccumulator() { return accumulator_; }
    GradientClipper& getClipper() { return clipper_; }
    GradientScaler& getScaler() { return scaler_; }

private:
    GradientAccumulator accumulator_;
    GradientClipper clipper_;
    GradientScaler scaler_;
    bool use_mixed_precision_;
};

} // namespace rawrxd::training
