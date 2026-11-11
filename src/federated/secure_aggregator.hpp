#pragma once

/**
 * @file secure_aggregator.hpp
 * @brief Secure aggregation for federated learning
 * @details Privacy-preserving gradient aggregation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <cstdint>
#include <memory>

namespace rawrxd {
namespace federated {

/**
 * @brief Security configuration
 */
struct SecurityConfig {
    enum class Protocol {
        FEDAVG,         ///< Standard averaging (no security)
        FEDAVG_DP,      ///< Differential privacy
        SECURE_AGG,     ///< Secure multi-party computation
        HOMOMORPHIC     ///< Homomorphic encryption
    };
    
    Protocol protocol = Protocol::FEDAVG_DP;
    int num_parties = 3;                ///< For secure aggregation
    int threshold = 2;                  ///< Reconstruction threshold
    float epsilon = 1.0f;               ///< DP epsilon
    float delta = 1e-5f;                ///< DP delta
    bool verify_proofs = true;          ///< Verify zero-knowledge proofs
};

/**
 * @brief Secret key for secure aggregation
 */
struct SecretKey {
    std::vector<uint8_t> key_data;
    std::string key_id;
};

/**
 * @brief Masked gradients
 */
struct MaskedGradients {
    std::vector<uint8_t> masked_data;
    std::vector<uint8_t> proof;         ///< Zero-knowledge proof
    std::string client_id;
};

/**
 * @brief Aggregation result
 */
struct AggregationResult {
    std::vector<float> aggregated_gradients;
    bool success;
    std::string error_message;
    std::chrono::milliseconds duration;
    size_t bytes_processed;
};

/**
 * @brief Secure aggregator
 *
 * Implements privacy-preserving gradient aggregation:
 * - Differential privacy (DP-SGD)
 * - Secure multi-party computation
 * - Homomorphic encryption
 * - Zero-knowledge proofs
 */
class SecureAggregator {
public:
    SecureAggregator();
    ~SecureAggregator();

    /**
     * @brief Initialize aggregator
     * @param config Security configuration
     * @return true if initialization successful
     */
    bool initialize(const SecurityConfig& config);

    /**
     * @brief Add client gradients
     * @param client_id Client identifier
     * @param gradients Client gradients
     * @return true if added successfully
     */
    bool addClientGradients(
        const std::string& client_id,
        const std::vector<float>& gradients
    );

    /**
     * @brief Mask gradients for secure aggregation
     * @param gradients Raw gradients
     * @param key Secret key
     * @return Masked gradients
     */
    MaskedGradients maskGradients(
        const std::vector<float>& gradients,
        const SecretKey& key
    );

    /**
     * @brief Add masked gradients
     * @param masked Masked gradients from client
     * @return true if added
     */
    bool addMaskedGradients(const MaskedGradients& masked);

    /**
     * @brief Aggregate all collected gradients
     * @return Aggregation result
     */
    AggregationResult aggregate();

    /**
     * @brief Aggregate with differential privacy
     * @param gradients Client gradients
     * @param epsilon Privacy budget
     * @param delta Privacy parameter
     * @return Aggregated gradients with noise
     */
    std::vector<float> aggregateWithDP(
        const std::vector<std::vector<float>>& gradients,
        float epsilon,
        float delta
    );

    /**
     * @brief Aggregate with secure multi-party computation
     * @param masked_gradients Masked gradients from clients
     * @return Aggregated gradients
     */
    std::vector<float> aggregateWithSMPC(
        const std::vector<MaskedGradients>& masked_gradients
    );

    /**
     * @brief Add Gaussian noise for differential privacy
     * @param gradients Gradients to noise
     * @param sigma Noise standard deviation
     */
    void addGaussianNoise(std::vector<float>& gradients, float sigma);

    /**
     * @brief Add Laplace noise for differential privacy
     * @param gradients Gradients to noise
     * @param b Scale parameter
     */
    void addLaplaceNoise(std::vector<float>& gradients, float b);

    /**
     * @brief Clip gradients for DP
     * @param gradients Gradients to clip
     * @param max_norm Maximum L2 norm
     */
    void clipGradients(std::vector<float>& gradients, float max_norm);

    /**
     * @brief Calculate gradient L2 norm
     * @param gradients Gradient vector
     * @return L2 norm
     */
    static float calculateNorm(const std::vector<float>& gradients);

    /**
     * @brief Generate secret key
     * @return New secret key
     */
    static SecretKey generateKey();

    /**
     * @brief Clear collected gradients
     */
    void clear();

    /**
     * @brief Get collected gradient count
     */
    size_t getCollectedCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Privacy accountant
 */
class PrivacyAccountant {
public:
    /**
     * @brief Initialize accountant
     * @param target_epsilon Target epsilon
     * @param target_delta Target delta
     */
    PrivacyAccountant(float target_epsilon, float target_delta);

    /**
     * @brief Account for a training step
     * @param noise_multiplier Noise multiplier used
     * @param sampling_probability Probability of sampling
     * @param steps Number of steps
     */
    void accountStep(
        float noise_multiplier,
        float sampling_probability,
        int steps
    );

    /**
     * @brief Get current epsilon spent
     */
    float getEpsilonSpent() const;

    /**
     * @brief Check if privacy budget exceeded
     */
    bool isBudgetExceeded() const;

    /**
     * @brief Get remaining epsilon
     */
    float getRemainingEpsilon() const;

    /**
     * @brief Reset accountant
     */
    void reset();

private:
    float target_epsilon_;
    float target_delta_;
    float epsilon_spent_;
};

} // namespace federated
} // namespace rawrxd
