/**
 * @file coordinator.cpp
 * @brief Federated learning coordinator implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "coordinator.hpp"
#include <algorithm>
#include <random>
#include <chrono>

namespace rawrxd {
namespace federated {

// ============================================================================
// FederatedCoordinator Implementation
// ============================================================================

class FederatedCoordinator::Impl {
public:
    AggregationStrategy strategy_;
    std::map<std::string, ClientInfo> clients_;
    std::vector<RoundResult> history_;
    int current_round_ = 0;
    bool converged_ = false;
    float convergence_threshold_ = 0.001f;
    int convergence_patience_ = 10;
    int rounds_since_improvement_ = 0;
    float best_loss_ = std::numeric_limits<float>::max();
    
    std::function<void(const RoundResult&)> round_callback_;
    std::vector<float> global_weights_;

    bool initialize(AggregationStrategy strategy, const std::string& model_path) {
        strategy_ = strategy;
        // Load initial global model
        // ... load from model_path ...
        return true;
    }

    bool registerClient(const std::string& client_id, const ClientInfo& info) {
        clients_[client_id] = info;
        return true;
    }

    void unregisterClient(const std::string& client_id) {
        clients_.erase(client_id);
    }

    std::vector<std::string> selectClients(size_t count) {
        std::vector<std::string> available;
        for (const auto& [id, info] : clients_) {
            if (info.is_available) {
                available.push_back(id);
            }
        }

        if (available.size() <= count) {
            return available;
        }

        // Random selection
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(available.begin(), available.end(), gen);
        
        return std::vector<std::string>(available.begin(), available.begin() + count);
    }

    RoundResult startRound(const RoundConfig& config) {
        RoundResult result;
        result.round_id = ++current_round_;
        auto start_time = std::chrono::high_resolution_clock::now();

        // Select clients
        auto selected = selectClients(config.num_clients);
        result.clients_selected = static_cast<int>(selected.size());

        if (selected.empty()) {
            result.success = false;
            result.error_message = "No clients available";
            return result;
        }

        // Distribute model
        size_t distributed = distributeModel(selected);
        
        // Collect gradients (simulated)
        std::vector<std::pair<std::string, std::vector<float>>> gradients;
        for (const auto& client_id : selected) {
            // Simulate receiving gradients from client
            std::vector<float> grad(global_weights_.size());
            // ... fill with actual gradients ...
            gradients.push_back({client_id, grad});
        }

        result.clients_completed = static_cast<int>(gradients.size());

        // Aggregate
        auto aggregated = aggregateGradients(gradients);
        
        // Update global model
        updateGlobalModel(aggregated);

        // Evaluate convergence
        result.aggregated_loss = evaluateLoss();
        result.aggregated_accuracy = evaluateAccuracy();

        auto end_time = std::chrono::high_resolution_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        result.success = true;

        // Check convergence
        if (result.aggregated_loss < best_loss_ - convergence_threshold_) {
            best_loss_ = result.aggregated_loss;
            rounds_since_improvement_ = 0;
        } else {
            rounds_since_improvement_++;
        }

        if (rounds_since_improvement_ >= convergence_patience_) {
            converged_ = true;
        }

        history_.push_back(result);
        
        if (round_callback_) {
            round_callback_(result);
        }

        return result;
    }

    size_t distributeModel(const std::vector<std::string>& client_ids) {
        // Send global model to clients
        return client_ids.size();
    }

    std::vector<float> aggregateGradients(
        const std::vector<std::pair<std::string, std::vector<float>>>& gradients
    ) {
        if (gradients.empty()) return {};

        size_t num_weights = gradients[0].second.size();
        std::vector<float> aggregated(num_weights, 0.0f);
        
        float total_weight = 0.0f;
        for (const auto& [client_id, grad] : gradients) {
            auto it = clients_.find(client_id);
            if (it != clients_.end()) {
                total_weight += it->second.dataset_size;
            }
        }

        for (const auto& [client_id, grad] : gradients) {
            auto it = clients_.find(client_id);
            float weight = (it != clients_.end()) ? 
                static_cast<float>(it->second.dataset_size) / total_weight : 
                1.0f / gradients.size();

            for (size_t i = 0; i < num_weights; ++i) {
                aggregated[i] += grad[i] * weight;
            }
        }

        return aggregated;
    }

    bool updateGlobalModel(const std::vector<float>& aggregated_gradients) {
        if (global_weights_.empty()) {
            global_weights_ = aggregated_gradients;
            return true;
        }

        // Apply gradients with learning rate
        float learning_rate = 0.001f;
        for (size_t i = 0; i < global_weights_.size() && i < aggregated_gradients.size(); ++i) {
            global_weights_[i] -= learning_rate * aggregated_gradients[i];
        }

        return true;
    }

    float evaluateLoss() {
        // Simulate loss evaluation
        return 1.0f / (1.0f + current_round_ * 0.1f);
    }

    float evaluateAccuracy() {
        // Simulate accuracy evaluation
        return 0.5f + (1.0f - 1.0f / (1.0f + current_round_ * 0.05f)) * 0.5f;
    }
};

FederatedCoordinator::FederatedCoordinator() : impl_(std::make_unique<Impl>()) {}
FederatedCoordinator::~FederatedCoordinator() = default;

bool FederatedCoordinator::initialize(AggregationStrategy strategy, const std::string& model_path) {
    return impl_->initialize(strategy, model_path);
}

bool FederatedCoordinator::registerClient(const std::string& client_id, const ClientInfo& info) {
    return impl_->registerClient(client_id, info);
}

void FederatedCoordinator::unregisterClient(const std::string& client_id) {
    impl_->unregisterClient(client_id);
}

RoundResult FederatedCoordinator::startRound(const RoundConfig& config) {
    return impl_->startRound(config);
}

std::vector<std::string> FederatedCoordinator::selectClients(size_t count) {
    return impl_->selectClients(count);
}

size_t FederatedCoordinator::distributeModel(const std::vector<std::string>& client_ids) {
    return impl_->distributeModel(client_ids);
}

std::vector<float> FederatedCoordinator::aggregateGradients(
    const std::vector<std::pair<std::string, std::vector<float>>>& gradients
) {
    return impl_->aggregateGradients(gradients);
}

bool FederatedCoordinator::updateGlobalModel(const std::vector<float>& aggregated_gradients) {
    return impl_->updateGlobalModel(aggregated_gradients);
}

ConvergenceMetrics FederatedCoordinator::evaluateConvergence() const {
    ConvergenceMetrics metrics;
    metrics.train_loss = impl_->evaluateLoss();
    metrics.train_accuracy = impl_->evaluateAccuracy();
    metrics.is_converged = impl_->converged_;
    metrics.rounds_since_improvement = impl_->rounds_since_improvement_;
    return metrics;
}

bool FederatedCoordinator::isConverged() const {
    return impl_->converged_;
}

int FederatedCoordinator::getCurrentRound() const {
    return impl_->current_round_;
}

size_t FederatedCoordinator::getClientCount() const {
    return impl_->clients_.size();
}

size_t FederatedCoordinator::getAvailableClientCount() const {
    size_t count = 0;
    for (const auto& [_, info] : impl_->clients_) {
        if (info.is_available) count++;
    }
    return count;
}

void FederatedCoordinator::setConvergenceCriteria(float threshold, int patience) {
    impl_->convergence_threshold_ = threshold;
    impl_->convergence_patience_ = patience;
}

void FederatedCoordinator::onRoundComplete(std::function<void(const RoundResult&)> callback) {
    impl_->round_callback_ = callback;
}

std::vector<RoundResult> FederatedCoordinator::getHistory() const {
    return impl_->history_;
}

} // namespace federated
} // namespace rawrxd
