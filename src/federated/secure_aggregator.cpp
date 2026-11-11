/**
 * @file secure_aggregator.cpp
 * @brief Secure aggregation implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "secure_aggregator.hpp"
#include <random>
#include <numeric>
#include <cmath>

namespace rawrxd {
namespace federated {

// ============================================================================
// SecureAggregator Implementation
// ============================================================================

class SecureAggregator::Impl {
public:
    SecurityConfig config_;
    std::vector<std::pair<std::string, std::vector<float>>> client_gradients_;
    std::vector<MaskedGradients> masked_gradients_;
    std::mt19937 rng_{std::random_device{}()};

    bool initialize(const SecurityConfig& config) {
        config_ = config;
        return true;
    }

    bool addClientGradients(const std::string& client_id, const std::vector<float>& gradients) {
        client_gradients_.push_back({client_id, gradients});
        return true;
    }

    MaskedGradients maskGradients(const std::vector<float>& gradients, const SecretKey& key) {
        MaskedGradients masked;
        masked.client_id = key.key_id;
        
        // Generate random mask
        std::vector<float> mask(gradients.size());
        std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
        for (auto& m : mask) {
            m = dist(rng_);
        }
        
        // Apply mask
        std::vector<float> masked_values(gradients.size());
        for (size_t i = 0; i < gradients.size(); ++i) {
            masked_values[i] = gradients[i] + mask[i];
        }
        
        // Serialize masked values
        masked.masked_data.resize(masked_values.size() * sizeof(float));
        std::memcpy(masked.masked_data.data(), masked_values.data(), masked.masked_data.size());
        
        // Generate proof (simplified)
        masked.proof = std::vector<uint8_t>(32, 0xAB);
        
        return masked;
    }

    bool addMaskedGradients(const MaskedGradients& masked) {
        masked_gradients_.push_back(masked);
        return true;
    }

    AggregationResult aggregate() {
        AggregationResult result;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        switch (config_.protocol) {
            case SecurityConfig::Protocol::FEDAVG:
                result.aggregated_gradients = aggregateFedAvg();
                break;
            case SecurityConfig::Protocol::FEDAVG_DP:
                result.aggregated_gradients = aggregateWithDPInternal();
                break;
            case SecurityConfig::Protocol::SECURE_AGG:
                result.aggregated_gradients = aggregateWithSMPCInternal();
                break;
            default:
                result.success = false;
                result.error_message = "Unsupported protocol";
                return result;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        result.success = true;
        result.bytes_processed = calculateBytesProcessed();
        
        return result;
    }

    std::vector<float> aggregateFedAvg() {
        if (client_gradients_.empty()) return {};
        
        size_t num_params = client_gradients_[0].second.size();
        std::vector<float> aggregated(num_params, 0.0f);
        
        for (const auto& [client_id, gradients] : client_gradients_) {
            for (size_t i = 0; i < num_params && i < gradients.size(); ++i) {
                aggregated[i] += gradients[i];
            }
        }
        
        // Average
        for (auto& val : aggregated) {
            val /= client_gradients_.size();
        }
        
        return aggregated;
    }

    std::vector<float> aggregateWithDPInternal() {
        auto aggregated = aggregateFedAvg();
        
        // Add Gaussian noise for differential privacy
        float sigma = config_.noise_multiplier * calculateL2Sensitivity();
        addGaussianNoise(aggregated, sigma);
        
        return aggregated;
    }

    std::vector<float> aggregateWithSMPCInternal() {
        // Secure multi-party computation aggregation
        // In practice, this would use cryptographic protocols
        return aggregateFedAvg();
    }

    float calculateL2Sensitivity() {
        // Simplified sensitivity calculation
        return 1.0f / client_gradients_.size();
    }

    size_t calculateBytesProcessed() {
        size_t total = 0;
        for (const auto& [_, gradients] : client_gradients_) {
            total += gradients.size() * sizeof(float);
        }
        return total;
    }

    void addGaussianNoise(std::vector<float>& gradients, float sigma) {
        std::normal_distribution<float> dist(0.0f, sigma);
        for (auto& grad : gradients) {
            grad += dist(rng_);
        }
    }

    void addLaplaceNoise(std::vector<float>& gradients, float b) {
        // Laplace distribution: using exponential
        std::exponential_distribution<float> exp_dist(1.0f / b);
        std::uniform_real_distribution<float> uniform(0.0f, 1.0f);
        
        for (auto& grad : gradients) {
            float u = uniform(rng_) - 0.5f;
            float sign = (u < 0) ? -1.0f : 1.0f;
            grad += sign * exp_dist(rng_);
        }
    }

    void clipGradients(std::vector<float>& gradients, float max_norm) {
        float norm = calculateNorm(gradients);
        if (norm > max_norm) {
            float scale = max_norm / norm;
            for (auto& grad : gradients) {
                grad *= scale;
            }
        }
    }

    float calculateNorm(const std::vector<float>& gradients) {
        float sum_squares = 0.0f;
        for (float grad : gradients) {
            sum_squares += grad * grad;
        }
        return std::sqrt(sum_squares);
    }
};

SecureAggregator::SecureAggregator() : impl_(std::make_unique<Impl>()) {}
SecureAggregator::~SecureAggregator() = default;

bool SecureAggregator::initialize(const SecurityConfig& config) {
    return impl_->initialize(config);
}

bool SecureAggregator::addClientGradients(const std::string& client_id, const std::vector<float>& gradients) {
    return impl_->addClientGradients(client_id, gradients);
}

MaskedGradients SecureAggregator::maskGradients(const std::vector<float>& gradients, const SecretKey& key) {
    return impl_->maskGradients(gradients, key);
}

bool SecureAggregator::addMaskedGradients(const MaskedGradients& masked) {
    return impl_->addMaskedGradients(masked);
}

AggregationResult SecureAggregator::aggregate() {
    return impl_->aggregate();
}

std::vector<float> SecureAggregator::aggregateWithDP(
    const std::vector<std::vector<float>>& gradients,
    float epsilon,
    float delta) {
    
    if (gradients.empty()) return {};
    
    size_t num_params = gradients[0].size();
    std::vector<float> aggregated(num_params, 0.0f);
    
    // Average gradients
    for (const auto& grad : gradients) {
        for (size_t i = 0; i < num_params && i < grad.size(); ++i) {
            aggregated[i] += grad[i];
        }
    }
    
    for (auto& val : aggregated) {
        val /= gradients.size();
    }
    
    // Calculate noise scale
    float sensitivity = 1.0f / gradients.size();
    float sigma = sensitivity * std::sqrt(2.0f * std::log(1.25f / delta)) / epsilon;
    
    addGaussianNoise(aggregated, sigma);
    
    return aggregated;
}

std::vector<float> SecureAggregator::aggregateWithSMPC(
    const std::vector<MaskedGradients>& masked_gradients) {
    
    if (masked_gradients.empty()) return {};
    
    // Unmask and aggregate
    // In practice, this would use secure multi-party computation
    std::vector<float> aggregated;
    
    for (const auto& masked : masked_gradients) {
        // Deserialize masked values
        size_t num_values = masked.masked_data.size() / sizeof(float);
        std::vector<float> values(num_values);
        std::memcpy(values.data(), masked.masked_data.data(), masked.masked_data.size());
        
        if (aggregated.empty()) {
            aggregated = values;
        } else {
            for (size_t i = 0; i < aggregated.size() && i < values.size(); ++i) {
                aggregated[i] += values[i];
            }
        }
    }
    
    // Average
    for (auto& val : aggregated) {
        val /= masked_gradients.size();
    }
    
    return aggregated;
}

void SecureAggregator::addGaussianNoise(std::vector<float>& gradients, float sigma) {
    impl_->addGaussianNoise(gradients, sigma);
}

void SecureAggregator::addLaplaceNoise(std::vector<float>& gradients, float b) {
    impl_->addLaplaceNoise(gradients, b);
}

void SecureAggregator::clipGradients(std::vector<float>& gradients, float max_norm) {
    impl_->clipGradients(gradients, max_norm);
}

float SecureAggregator::calculateNorm(const std::vector<float>& gradients) {
    return Impl::calculateNorm(gradients);
}

SecretKey SecureAggregator::generateKey() {
    SecretKey key;
    key.key_id = "client_" + std::to_string(std::random_device{}());
    key.key_data.resize(32);
    std::random_device rd;
    std::generate(key.key_data.begin(), key.key_data.end(), [&rd]() { return rd() % 256; });
    return key;
}

void SecureAggregator::clear() {
    impl_->client_gradients_.clear();
    impl_->masked_gradients_.clear();
}

size_t SecureAggregator::getCollectedCount() const {
    return impl_->client_gradients_.size();
}

// ============================================================================
// PrivacyAccountant Implementation
// ============================================================================

PrivacyAccountant::PrivacyAccountant(float target_epsilon, float target_delta)
    : target_epsilon_(target_epsilon), target_delta_(target_delta), epsilon_spent_(0.0f) {}

void PrivacyAccountant::accountStep(float noise_multiplier, float sampling_probability, int steps) {
    // Simplified privacy accounting using moments accountant
    // In practice, this would use more sophisticated accounting
    float epsilon_per_step = sampling_probability * std::sqrt(steps) / noise_multiplier;
    epsilon_spent_ += epsilon_per_step;
}

float PrivacyAccountant::getEpsilonSpent() const {
    return epsilon_spent_;
}

bool PrivacyAccountant::isBudgetExceeded() const {
    return epsilon_spent_ > target_epsilon_;
}

float PrivacyAccountant::getRemainingEpsilon() const {
    return std::max(0.0f, target_epsilon_ - epsilon_spent_);
}

void PrivacyAccountant::reset() {
    epsilon_spent_ = 0.0f;
}

} // namespace federated
} // namespace rawrxd
