#pragma once

#include "model_router.hpp"
#include <random>
#include <chrono>

namespace rawrxd::serving {

// Round-robin with sticky sessions
class StickyRoundRobinStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "sticky_round_robin"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void setSessionTimeout(std::chrono::minutes timeout) { session_timeout_ = timeout; }

private:
    std::atomic<size_t> next_index_{0};
    std::unordered_map<std::string, std::pair<std::string, std::chrono::steady_clock::time_point>> sessions_;
    mutable std::mutex sessions_mutex_;
    std::chrono::minutes session_timeout_{30};
};

// Latency-aware routing with exponential moving average
class LatencyAwareStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "latency_aware"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void reportLatency(const std::string& instance_id, float latency_ms);
    void setLatencyWeight(float weight) { latency_weight_ = weight; }

private:
    struct LatencyStats {
        float ema_latency = 0.0f;  // Exponential moving average
        uint64_t sample_count = 0;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, LatencyStats> latency_stats_;
    float alpha_ = 0.3f;  // EMA smoothing factor
    float latency_weight_ = 0.7f;
};

// Cost-based routing (for multi-tenant cost optimization)
class CostBasedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "cost_based"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void setInstanceCost(const std::string& instance_id, float cost_per_token);
    void setBudgetConstraint(float max_cost_per_request);

private:
    struct CostInfo {
        float cost_per_token = 0.0f;
        float total_cost = 0.0f;
        uint64_t tokens_served = 0;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, CostInfo> costs_;
    float max_cost_per_request_ = std::numeric_limits<float>::max();
};

// Geographic routing (for edge deployment)
class GeographicStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "geographic"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void setInstanceLocation(const std::string& instance_id, float lat, float lon);
    void setRequestLocation(const std::string& request_id, float lat, float lon);

private:
    struct Location {
        float latitude = 0.0f;
        float longitude = 0.0f;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Location> instance_locations_;
    std::unordered_map<std::string, Location> request_locations_;

    float calculateDistance(const Location& a, const Location& b);
};

// Load-based routing (for balancing GPU utilization)
class LoadBasedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "load_based"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void reportLoad(const std::string& instance_id, float gpu_utilization, float memory_utilization);
    void setLoadThreshold(float threshold) { load_threshold_ = threshold; }

private:
    struct LoadMetrics {
        float gpu_utilization = 0.0f;
        float memory_utilization = 0.0f;
        std::chrono::steady_clock::time_point timestamp;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, LoadMetrics> load_metrics_;
    float load_threshold_ = 0.8f;
};

// QoS-based routing (prioritize by SLA)
class QoSBasedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "qos_based"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void setInstanceQoS(const std::string& instance_id, int priority, float max_latency_sla);
    void setRequestQoS(const std::string& request_id, int priority, float deadline_ms);

private:
    struct QoSProfile {
        int priority = 0;
        float max_latency_sla = 1000.0f;
        float current_latency = 0.0f;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, QoSProfile> instance_qos_;
    std::unordered_map<std::string, QoSProfile> request_qos_;
};

// Ensemble routing (combine multiple strategies)
class EnsembleStrategy : public RoutingStrategy {
public:
    EnsembleStrategy();

    std::string getName() const override { return "ensemble"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void addStrategy(std::shared_ptr<RoutingStrategy> strategy, float weight);
    void removeStrategy(const std::string& strategy_name);
    void setStrategyWeight(const std::string& strategy_name, float weight);

private:
    struct WeightedStrategy {
        std::shared_ptr<RoutingStrategy> strategy;
        float weight;
    };

    std::vector<WeightedStrategy> strategies_;
    mutable std::mutex mutex_;

    void normalizeWeights();
};

// Machine learning-based routing (learn optimal routing)
class MLBasedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "ml_based"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void recordOutcome(const std::string& instance_id, float reward);
    void trainModel();
    void loadModel(const std::string& path);
    void saveModel(const std::string& path);

private:
    struct FeatureVector {
        float request_complexity = 0.0f;
        float expected_latency = 0.0f;
        float instance_load = 0.0f;
        float historical_accuracy = 0.0f;
    };

    // Simplified Q-table for demonstration
    std::unordered_map<std::string, std::unordered_map<std::string, float>> q_table_;
    float learning_rate_ = 0.1f;
    float discount_factor_ = 0.9f;
    float epsilon_ = 0.1f;  // Exploration rate

    std::mt19937 rng_{std::random_device{}()};
    mutable std::mutex mutex_;

    FeatureVector extractFeatures(const RoutingContext& context, const ModelInstance& instance);
    std::string selectAction(const FeatureVector& features, const std::vector<ModelInstance>& candidates);
    void updateQValue(const std::string& state, const std::string& action, float reward);
};

// Strategy factory
class RoutingStrategyFactory {
public:
    static std::unique_ptr<RoutingStrategy> create(const std::string& name);
    static std::vector<std::string> availableStrategies();
};

} // namespace rawrxd::serving
