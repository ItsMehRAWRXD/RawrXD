#pragma once

/**
 * @file coordinator.hpp
 * @brief Federated learning coordinator
 * @details Central coordinator for federated learning rounds
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace rawrxd {
namespace federated {

/**
 * @brief Privacy configuration
 */
struct PrivacyConfig {
    enum class Mechanism {
        NONE,           ///< No privacy mechanism
        DP_SGD,         ///< Differential privacy with SGD
        GAUSSIAN,       ///< Gaussian mechanism
        LAPLACE         ///< Laplace mechanism
    };
    
    Mechanism mechanism = Mechanism::NONE;
    float epsilon = 1.0f;       ///< Privacy budget epsilon
    float delta = 1e-5f;        ///< Privacy budget delta
    float noise_multiplier = 1.0f;
    int max_grad_norm = 1;      ///< Gradient clipping norm
};

/**
 * @brief Round configuration
 */
struct RoundConfig {
    int round_id = 0;                    ///< Round identifier
    int num_clients = 10;                ///< Number of clients to select
    int local_epochs = 5;                ///< Local training epochs
    float learning_rate = 0.001f;        ///< Learning rate
    int batch_size = 32;                 ///< Batch size
    PrivacyConfig privacy;               ///< Privacy configuration
    std::chrono::minutes timeout{30};    ///< Round timeout
    float min_clients_fraction = 0.8f;     ///< Minimum fraction of clients required
};

/**
 * @brief Client information
 */
struct ClientInfo {
    std::string client_id;
    size_t dataset_size;
    float compute_capacity;
    std::chrono::milliseconds latency;
    bool is_available;
    int rounds_participated;
};

/**
 * @brief Round result
 */
struct RoundResult {
    int round_id;
    bool success;
    int clients_selected;
    int clients_completed;
    float aggregated_loss;
    float aggregated_accuracy;
    std::chrono::milliseconds duration;
    std::string error_message;
};

/**
 * @brief Convergence metrics
 */
struct ConvergenceMetrics {
    float train_loss;
    float val_loss;
    float train_accuracy;
    float val_accuracy;
    float gradient_norm;
    int rounds_since_improvement;
    bool is_converged;
};

/**
 * @brief Federated learning coordinator
 *
 * Central server component that orchestrates federated learning:
 * - Client selection and management
 * - Round orchestration
 * - Model distribution and aggregation
 * - Convergence monitoring
 */
class FederatedCoordinator {
public:
    /**
     * @brief Aggregation strategy
     */
    enum class AggregationStrategy {
        FEDAVG,         ///< Federated averaging
        FEDPROX,        ///< Federated proximal
        FEDOPT,         ///< Federated optimization
        SCAFFOLD        ///< Stochastic controlled averaging
    };

    FederatedCoordinator();
    ~FederatedCoordinator();

    /**
     * @brief Initialize coordinator
     * @param strategy Aggregation strategy
     * @param model_path Path to initial global model
     * @return true if initialization successful
     */
    bool initialize(AggregationStrategy strategy, const std::string& model_path);

    /**
     * @brief Register a client
     * @param client_id Unique client identifier
     * @param info Client information
     * @return true if registered
     */
    bool registerClient(const std::string& client_id, const ClientInfo& info);

    /**
     * @brief Unregister a client
     * @param client_id Client identifier
     */
    void unregisterClient(const std::string& client_id);

    /**
     * @brief Start a federated round
     * @param config Round configuration
     * @return Round result
     */
    RoundResult startRound(const RoundConfig& config);

    /**
     * @brief Select clients for round
     * @param count Number of clients to select
     * @return Selected client IDs
     */
    std::vector<std::string> selectClients(size_t count);

    /**
     * @brief Distribute global model to clients
     * @param client_ids Target clients
     * @return Number of successful distributions
     */
    size_t distributeModel(const std::vector<std::string>& client_ids);

    /**
     * @brief Collect gradients from clients
     * @param timeout Maximum wait time
     * @return Collected gradients with client IDs
     */
    std::vector<std::pair<std::string, std::vector<float>>> collectGradients(
        std::chrono::milliseconds timeout
    );

    /**
     * @brief Aggregate collected gradients
     * @param gradients Client gradients
     * @return Aggregated gradients
     */
    std::vector<float> aggregateGradients(
        const std::vector<std::pair<std::string, std::vector<float>>>& gradients
    );

    /**
     * @brief Update global model with aggregated gradients
     * @param aggregated_gradients Aggregated gradients
     * @return true if update successful
     */
    bool updateGlobalModel(const std::vector<float>& aggregated_gradients);

    /**
     * @brief Get current global model
     * @return Global model binary
     */
    std::vector<uint8_t> getGlobalModel() const;

    /**
     * @brief Evaluate convergence
     * @return Convergence metrics
     */
    ConvergenceMetrics evaluateConvergence() const;

    /**
     * @brief Check if training has converged
     * @return true if converged
     */
    bool isConverged() const;

    /**
     * @brief Get current round number
     */
    int getCurrentRound() const;

    /**
     * @brief Get registered client count
     */
    size_t getClientCount() const;

    /**
     * @brief Get available client count
     */
    size_t getAvailableClientCount() const;

    /**
     * @brief Set convergence threshold
     * @param threshold Loss improvement threshold
     * @param patience Rounds without improvement
     */
    void setConvergenceCriteria(float threshold, int patience);

    /**
     * @brief Register round completion callback
     * @param callback Called when round completes
     */
    void onRoundComplete(std::function<void(const RoundResult&)> callback);

    /**
     * @brief Save global model checkpoint
     * @param path Save path
     * @return true if saved
     */
    bool saveCheckpoint(const std::string& path) const;

    /**
     * @brief Load global model checkpoint
     * @param path Checkpoint path
     * @return true if loaded
     */
    bool loadCheckpoint(const std::string& path);

    /**
     * @brief Get training history
     * @return Vector of round results
     */
    std::vector<RoundResult> getHistory() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Client selector strategies
 */
class ClientSelector {
public:
    /**
     * @brief Selection strategy
     */
    enum class Strategy {
        RANDOM,         ///< Random selection
        ROUND_ROBIN,    ///< Round-robin
        POWER_OF_CHOICE, ///< Power-of-choice
        IMPORTANCE      ///< Importance sampling
    };

    /**
     * @brief Select clients using strategy
     * @param available Available clients
     * @param count Number to select
     * @param strategy Selection strategy
     * @return Selected client IDs
     */
    static std::vector<std::string> select(
        const std::vector<ClientInfo>& available,
        size_t count,
        Strategy strategy
    );
};

} // namespace federated
} // namespace rawrxd
