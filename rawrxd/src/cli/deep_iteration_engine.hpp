#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <optional>
#include <cstdint>

namespace rawrxd::training {

// ───────────────────────────────────────────────────────────────
// Iteration configuration
// ───────────────────────────────────────────────────────────────
struct IterationConfig {
    uint32_t batch_size = 32;
    uint32_t micro_batch_size = 8;
    uint32_t gradient_accumulation_steps = 4;
    float learning_rate = 1e-4f;
    float warmup_ratio = 0.01f;
    uint32_t max_steps = 10000;
    uint32_t eval_every_n_steps = 500;
    uint32_t checkpoint_every_n_steps = 1000;
    bool enable_mixed_precision = true;
    bool enable_gradient_clipping = true;
    float max_grad_norm = 1.0f;
    std::string optimizer = "adamw";
    std::string scheduler = "cosine";
};

// ───────────────────────────────────────────────────────────────
// Iteration state
// ───────────────────────────────────────────────────────────────
struct IterationState {
    uint32_t current_step = 0;
    uint32_t current_epoch = 0;
    float current_loss = 0.0f;
    float current_lr = 0.0f;
    std::chrono::milliseconds step_time{0};
    std::chrono::milliseconds total_time{0};
    bool is_evaluating = false;
    bool is_checkpointsaving = false;
};

// ───────────────────────────────────────────────────────────────
// Metrics for a single iteration step
// ───────────────────────────────────────────────────────────────
struct StepMetrics {
    uint32_t step = 0;
    float loss = 0.0f;
    float perplexity = 0.0f;
    float accuracy = 0.0f;
    float grad_norm = 0.0f;
    std::chrono::milliseconds forward_time{0};
    std::chrono::milliseconds backward_time{0};
    std::chrono::milliseconds optimizer_time{0};
    // RAWRXD_UNSIMULATE_001
    //
    // A zero in a metrics struct is indistinguishable from a measurement of
    // zero. Every field above used to be filled by a formula that produced a
    // guaranteed loss decrease and constant 10/20/5ms timings, so a consumer
    // reading a "loss" of 0.5 could not tell it from a real one. `measured`
    // makes the difference explicit: when it is false, every other field in
    // this struct is undefined and must not be plotted, averaged or reported.
    // It is not set by any code path in this tree, because no forward or
    // backward pass is implemented.
    bool measured = false;
};

// ───────────────────────────────────────────────────────────────
// DeepIterationEngine — training iteration orchestrator
// ───────────────────────────────────────────────────────────────
class DeepIterationEngine {
public:
    DeepIterationEngine();
    ~DeepIterationEngine();

    // Configuration
    bool Configure(const IterationConfig& config);
    IterationConfig GetConfig() const;

    // Lifecycle
    bool Initialize();
    bool LoadCheckpoint(const std::string& path);
    bool SaveCheckpoint(const std::string& path);
    void StartTraining();
    void PauseTraining();
    void ResumeTraining();
    void StopTraining();
    bool IsTraining() const;
    bool IsPaused() const;

    // State
    IterationState GetState() const;
    void SetState(const IterationState& state);

    // Step execution (manual mode — caller drives)
    bool RunSingleStep();
    StepMetrics GetLastStepMetrics() const;

    // Batch management
    bool SetBatchData(const std::vector<std::vector<float>>& inputs,
                       const std::vector<std::vector<float>>& labels);
    bool AdvanceBatch();
    size_t GetTotalBatches() const;
    size_t GetCurrentBatchIndex() const;

    // Metrics and callbacks
    using StepCallback = std::function<void(const StepMetrics&)>;
    using EvalCallback = std::function<void(uint32_t step, float eval_loss, float eval_perplexity)>;
    using CheckpointCallback = std::function<void(const std::string& path, uint32_t step)>;

    void SetStepCallback(StepCallback cb);
    void SetEvalCallback(EvalCallback cb);
    void SetCheckpointCallback(CheckpointCallback cb);

    // Aggregate metrics
    std::vector<StepMetrics> GetRecentMetrics(size_t count) const;
    float GetAverageLoss(size_t last_n_steps) const;
    float GetBestLoss() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::training
