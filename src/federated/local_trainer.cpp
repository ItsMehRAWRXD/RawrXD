/**
 * @file local_trainer.cpp
 * @brief Local training engine implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "local_trainer.hpp"
#include <algorithm>
#include <random>
#include <numeric>

namespace rawrxd {
namespace federated {

// ============================================================================
// LocalDataset Implementation
// ============================================================================

void LocalDataset::addSample(const TrainingSample& sample) {
    samples_.push_back(sample);
}

size_t LocalDataset::size() const {
    return samples_.size();
}

TrainingSample LocalDataset::getSample(size_t index) const {
    if (index >= samples_.size()) {
        return {};
    }
    return samples_[index];
}

std::vector<TrainingSample> LocalDataset::getBatch(size_t start, size_t count) const {
    std::vector<TrainingSample> batch;
    size_t end = std::min(start + count, samples_.size());
    for (size_t i = start; i < end; ++i) {
        batch.push_back(samples_[i]);
    }
    return batch;
}

void LocalDataset::shuffle() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(samples_.begin(), samples_.end(), gen);
}

// ============================================================================
// LocalTrainer Implementation
// ============================================================================

class LocalTrainer::Impl {
public:
    TrainingConfig config_;
    std::vector<float> weights_;
    std::vector<float> gradients_;
    float current_loss_ = 0.0f;
    float current_accuracy_ = 0.0f;
    bool is_training_ = false;
    bool should_stop_ = false;
    std::function<void(int, float)> progress_callback_;
    size_t samples_processed_ = 0;

    bool initialize(const TrainingConfig& config) {
        config_ = config;
        return true;
    }

    bool loadGlobalModel(const std::vector<uint8_t>& model_data) {
        // Deserialize model weights
        size_t num_weights = model_data.size() / sizeof(float);
        weights_.resize(num_weights);
        std::memcpy(weights_.data(), model_data.data(), model_data.size());
        return true;
    }

    TrainingMetrics train(const LocalDataset& dataset) {
        TrainingMetrics metrics;
        is_training_ = true;
        should_stop_ = false;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Shuffle dataset
        LocalDataset shuffled_dataset = dataset;
        shuffled_dataset.shuffle();
        
        int total_batches = static_cast<int>(shuffled_dataset.size() / config_.batch_size);
        float total_loss = 0.0f;
        int correct_predictions = 0;
        int total_predictions = 0;
        
        for (int epoch = 0; epoch < config_.epochs && !should_stop_; ++epoch) {
            for (int batch = 0; batch < total_batches && !should_stop_; ++batch) {
                auto batch_samples = shuffled_dataset.getBatch(
                    batch * config_.batch_size, 
                    config_.batch_size
                );
                
                // Simulate forward pass and loss computation
                float batch_loss = computeBatchLoss(batch_samples);
                total_loss += batch_loss;
                
                // Simulate backward pass and gradient computation
                computeGradients(batch_samples);
                
                // Update weights
                updateWeights();
                
                // Track accuracy (simplified)
                correct_predictions += static_cast<int>(batch_samples.size() * 0.8f); // Simulated accuracy
                total_predictions += static_cast<int>(batch_samples.size());
                samples_processed_ += batch_samples.size();
                
                if (progress_callback_) {
                    progress_callback_(epoch * total_batches + batch, batch_loss);
                }
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        
        metrics.loss = total_loss / (total_batches * config_.epochs);
        metrics.accuracy = static_cast<float>(correct_predictions) / total_predictions;
        metrics.perplexity = std::exp(metrics.loss);
        metrics.samples_processed = static_cast<int>(samples_processed_);
        metrics.batches_processed = total_batches * config_.epochs;
        metrics.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        current_loss_ = metrics.loss;
        current_accuracy_ = metrics.accuracy;
        is_training_ = false;
        
        return metrics;
    }

    float computeBatchLoss(const std::vector<TrainingSample>& batch) {
        // Simplified loss computation
        // In reality, this would run the model forward pass
        float loss = 0.0f;
        for (const auto& sample : batch) {
            // Simulate cross-entropy loss
            loss += 0.5f + static_cast<float>(rand()) / RAND_MAX * 0.5f;
        }
        return loss / batch.size();
    }

    void computeGradients(const std::vector<TrainingSample>& batch) {
        // Simplified gradient computation
        // In reality, this would run backpropagation
        if (gradients_.empty()) {
            gradients_.resize(weights_.size(), 0.0f);
        }
        
        // Simulate gradient accumulation
        for (size_t i = 0; i < gradients_.size(); ++i) {
            gradients_[i] += (static_cast<float>(rand()) / RAND_MAX - 0.5f) * 0.01f;
        }
    }

    void updateWeights() {
        // Apply gradients with learning rate
        for (size_t i = 0; i < weights_.size() && i < gradients_.size(); ++i) {
            weights_[i] -= config_.learning_rate * gradients_[i];
        }
        
        // Clear gradients after update
        std::fill(gradients_.begin(), gradients_.end(), 0.0f);
    }

    std::vector<float> computeGradients() const {
        return gradients_;
    }

    std::vector<uint8_t> packageUpdates() const {
        // Package weight updates for transmission
        std::vector<uint8_t> package(weights_.size() * sizeof(float));
        std::memcpy(package.data(), weights_.data(), package.size());
        return package;
    }

    std::vector<float> getWeights() const {
        return weights_;
    }

    void setWeights(const std::vector<float>& weights) {
        weights_ = weights;
    }
};

LocalTrainer::LocalTrainer() : impl_(std::make_unique<Impl>()) {}
LocalTrainer::~LocalTrainer() = default;

bool LocalTrainer::initialize(const TrainingConfig& config) {
    return impl_->initialize(config);
}

bool LocalTrainer::loadGlobalModel(const std::vector<uint8_t>& model_data) {
    return impl_->loadGlobalModel(model_data);
}

TrainingMetrics LocalTrainer::train(const LocalDataset& dataset) {
    return impl_->train(dataset);
}

std::vector<float> LocalTrainer::computeGradients() const {
    return impl_->computeGradients();
}

std::vector<uint8_t> LocalTrainer::packageUpdates() const {
    return impl_->packageUpdates();
}

std::vector<float> LocalTrainer::getWeights() const {
    return impl_->getWeights();
}

void LocalTrainer::setWeights(const std::vector<float>& weights) {
    impl_->setWeights(weights);
}

size_t LocalTrainer::getSampleCount() const {
    return impl_->samples_processed_;
}

float LocalTrainer::getLocalLoss() const {
    return impl_->current_loss_;
}

float LocalTrainer::getLocalAccuracy() const {
    return impl_->current_accuracy_;
}

bool LocalTrainer::isTraining() const {
    return impl_->is_training_;
}

void LocalTrainer::stopTraining() {
    impl_->should_stop_ = true;
}

void LocalTrainer::onProgress(std::function<void(int, float)> callback) {
    impl_->progress_callback_ = callback;
}

size_t LocalTrainer::getMemoryUsage() const {
    // Estimate memory usage
    return impl_->weights_.size() * sizeof(float) + 
           impl_->gradients_.size() * sizeof(float);
}

// ============================================================================
// GradientAccumulator Implementation
// ============================================================================

GradientAccumulator::GradientAccumulator(int num_steps) 
    : num_steps_(num_steps), current_step_(0) {}

void GradientAccumulator::accumulate(const std::vector<float>& gradients) {
    if (accumulated_.empty()) {
        accumulated_ = gradients;
    } else {
        for (size_t i = 0; i < accumulated_.size() && i < gradients.size(); ++i) {
            accumulated_[i] += gradients[i];
        }
    }
    current_step_++;
}

std::vector<float> GradientAccumulator::getAccumulated() const {
    // Average the accumulated gradients
    std::vector<float> averaged = accumulated_;
    if (current_step_ > 0) {
        for (auto& grad : averaged) {
            grad /= current_step_;
        }
    }
    return averaged;
}

void GradientAccumulator::reset() {
    current_step_ = 0;
    accumulated_.clear();
}

bool GradientAccumulator::isReady() const {
    return current_step_ >= num_steps_;
}

} // namespace federated
} // namespace rawrxd
