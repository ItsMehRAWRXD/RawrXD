#pragma once

/**
 * @file local_trainer.hpp
 * @brief Local training engine for federated learning
 * @details On-device training with LoRA/QLoRA support
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd {
namespace federated {

/**
 * @brief Training configuration
 */
struct TrainingConfig {
    int epochs = 5;
    int batch_size = 32;
    float learning_rate = 0.001f;
    float weight_decay = 0.01f;
    bool use_lora = true;
    int lora_rank = 8;
    float lora_alpha = 16.0f;
    float lora_dropout = 0.05f;
    int gradient_accumulation_steps = 1;
    int max_sequence_length = 512;
    bool use_quantization = true;
    int quantization_bits = 8;
};

/**
 * @brief Training metrics
 */
struct TrainingMetrics {
    float loss;
    float accuracy;
    float perplexity;
    int samples_processed;
    int batches_processed;
    std::chrono::milliseconds duration;
};

/**
 * @brief Dataset sample
 */
struct TrainingSample {
    std::vector<int> input_ids;
    std::vector<int> attention_mask;
    std::vector<int> labels;
};

/**
 * @brief Local dataset
 */
class LocalDataset {
public:
    void addSample(const TrainingSample& sample);
    size_t size() const;
    TrainingSample getSample(size_t index) const;
    std::vector<TrainingSample> getBatch(size_t start, size_t count) const;
    void shuffle();
};

/**
 * @brief Local training engine
 *
 * Performs on-device training with:
 * - LoRA/QLoRA fine-tuning
 * - Gradient accumulation
 * - Memory-efficient training
 * - Quantization support
 */
class LocalTrainer {
public:
    LocalTrainer();
    ~LocalTrainer();

    /**
     * @brief Initialize trainer
     * @param config Training configuration
     * @return true if initialization successful
     */
    bool initialize(const TrainingConfig& config);

    /**
     * @brief Load global model from server
     * @param model_data Global model binary
     * @return true if loaded successfully
     */
    bool loadGlobalModel(const std::vector<uint8_t>& model_data);

    /**
     * @brief Train on local dataset
     * @param dataset Local training data
     * @return Training metrics
     */
    TrainingMetrics train(const LocalDataset& dataset);

    /**
     * @brief Compute gradients from local training
     * @return Flattened gradient vector
     */
    std::vector<float> computeGradients() const;

    /**
     * @brief Package model updates for transmission
     * @return Compressed update package
     */
    std::vector<uint8_t> packageUpdates() const;

    /**
     * @brief Get local model weights
     * @return Model weights
     */
    std::vector<float> getWeights() const;

    /**
     * @brief Set local model weights
     * @param weights New weights
     */
    void setWeights(const std::vector<float>& weights);

    /**
     * @brief Get sample count in local dataset
     */
    size_t getSampleCount() const;

    /**
     * @brief Get local loss
     */
    float getLocalLoss() const;

    /**
     * @brief Get local accuracy
     */
    float getLocalAccuracy() const;

    /**
     * @brief Check if training is in progress
     */
    bool isTraining() const;

    /**
     * @brief Stop training
     */
    void stopTraining();

    /**
     * @brief Register progress callback
     * @param callback Called after each batch
     */
    void onProgress(std::function<void(int batch, float loss)> callback);

    /**
     * @brief Get memory usage
     * @return Memory used in bytes
     */
    size_t getMemoryUsage() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Gradient accumulator
 */
class GradientAccumulator {
public:
    /**
     * @brief Initialize accumulator
     * @param num_steps Number of accumulation steps
     */
    explicit GradientAccumulator(int num_steps);

    /**
     * @brief Add gradients
     * @param gradients Gradients to accumulate
     */
    void accumulate(const std::vector<float>& gradients);

    /**
     * @brief Get accumulated gradients
     * @return Accumulated gradients
     */
    std::vector<float> getAccumulated() const;

    /**
     * @brief Reset accumulator
     */
    void reset();

    /**
     * @brief Check if ready to step
     */
    bool isReady() const;

private:
    int num_steps_;
    int current_step_;
    std::vector<float> accumulated_;
};

} // namespace federated
} // namespace rawrxd
