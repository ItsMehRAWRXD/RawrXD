#pragma once

#include "../training_config.hpp"
#include <deque>
#include <numeric>

namespace rawrxd::training {

// Metric tracker for training
class MetricsTracker {
public:
    explicit MetricsTracker(size_t window_size = 100);

    // Record metric
    void recordLoss(float loss);
    void recordLearningRate(float lr);
    void recordThroughput(float tokens_per_sec);
    void recordGradientNorm(float norm);

    // Get statistics
    float getAverageLoss() const;
    float getSmoothedLoss() const;
    float getBestLoss() const;
    float getWorstLoss() const;

    float getAverageThroughput() const;
    float getPeakThroughput() const;

    // Trends
    bool isImproving() const;  // Loss decreasing
    bool isConverged(float threshold = 1e-6f) const;

    // Reset
    void reset();

    // Export to JSON
    std::string toJson() const;

private:
    size_t window_size_;
    std::deque<float> losses_;
    std::deque<float> learning_rates_;
    std::deque<float> throughputs_;
    std::deque<float> gradient_norms_;

    float best_loss_ = std::numeric_limits<float>::max();
    float worst_loss_ = 0.0f;
};

// TensorBoard logger
class TensorBoardLogger {
public:
    explicit TensorBoardLogger(const std::string& log_dir);

    // Log scalars
    void logScalar(const std::string& tag, float value, uint64_t step);
    void logScalars(const std::string& main_tag,
                    const std::unordered_map<std::string, float>& values,
                    uint64_t step);

    // Log histogram
    void logHistogram(const std::string& tag,
                      const std::vector<float>& values,
                      uint64_t step);

    // Flush
    void flush();

private:
    std::string log_dir_;
    std::ofstream writer_;

    void writeScalar(const std::string& tag, float value, uint64_t step);
    void writeHistogram(const std::string& tag,
                        const std::vector<float>& values,
                        uint64_t step);
};

// Weights & Biases logger
class WandbLogger {
public:
    WandbLogger(const std::string& project,
                const std::string& run_name = "",
                const std::unordered_map<std::string, std::string>& config = {});
    ~WandbLogger();

    void log(const std::unordered_map<std::string, float>& metrics, uint64_t step);
    void logArtifact(const std::string& path, const std::string& type = "model");
    void finish();

private:
    std::string project_;
    std::string run_id_;
    bool initialized_ = false;
};

// Combined metrics logger
class MetricsLogger {
public:
    MetricsLogger(const TrainingConfig& config);

    void logStep(const TrainingMetrics& metrics);
    void logEpoch(const TrainingMetrics& metrics);
    void logValidation(float loss, uint64_t step);

    void addTensorBoard(const std::string& log_dir);
    void addWandb(const std::string& project, const std::string& run_name);

private:
    std::unique_ptr<TensorBoardLogger> tb_logger_;
    std::unique_ptr<WandbLogger> wandb_logger_;
    MetricsTracker tracker_;
};

} // namespace rawrxd::training
