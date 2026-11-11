#pragma once

#include "model_registry.hpp"
#include <functional>
#include <random>

namespace rawrxd::serving {

// Routing decision
struct RoutingDecision {
    std::string model_full_name;
    std::string instance_id;
    std::string strategy_used;
    float confidence = 1.0f;
    std::unordered_map<std::string, std::string> metadata;
};

// Routing context
struct RoutingContext {
    std::string request_id;
    std::string user_id;
    std::string session_id;
    std::vector<int> prompt_tokens;
    std::unordered_map<std::string, std::string> headers;
    std::chrono::steady_clock::time_point arrival_time;
    
    // Preferences
    std::optional<std::string> requested_model;
    std::optional<std::string> requested_version;
    std::optional<std::string> required_capability;
    float max_latency_ms = 0.0f;  // 0 = no limit
};

// Routing strategy interface
class RoutingStrategy {
public:
    virtual ~RoutingStrategy() = default;
    virtual std::string getName() const = 0;
    virtual RoutingDecision route(const RoutingContext& context,
                                   const std::vector<ModelInstance>& candidates) = 0;
};

// Round-robin routing
class RoundRobinStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "round_robin"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

private:
    std::atomic<size_t> next_index_{0};
};

// Least-latency routing
class LeastLatencyStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "least_latency"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void reportLatency(const std::string& instance_id, float latency_ms);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, float> latency_estimates_;
};

// Weighted routing (by capacity)
class WeightedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "weighted"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void setWeight(const std::string& instance_id, float weight);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, float> weights_;
    std::mt19937 rng_{std::random_device{}()};
};

// Capability-based routing
class CapabilityStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "capability"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    void registerCapability(const std::string& model_full_name,
                            const std::vector<std::string>& capabilities);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::string>> model_capabilities_;
};

// Content-based routing (prompt analysis)
class ContentBasedStrategy : public RoutingStrategy {
public:
    std::string getName() const override { return "content_based"; }
    RoutingDecision route(const RoutingContext& context,
                          const std::vector<ModelInstance>& candidates) override;

    // Register model for specific content types
    void registerContentPattern(const std::string& model_full_name,
                                   const std::vector<std::string>& patterns);

private:
    struct ContentPattern {
        std::string model_full_name;
        std::vector<std::string> keywords;
        float weight = 1.0f;
    };
    std::vector<ContentPattern> patterns_;
    mutable std::mutex mutex_;
    
    float scoreMatch(const std::vector<int>& tokens, const ContentPattern& pattern);
};

// Model router
class ModelRouter {
public:
    ModelRouter(std::shared_ptr<ModelRegistry> registry);
    ~ModelRouter() = default;

    // Initialize
    bool initialize();

    // Route request to model
    RoutingDecision route(const RoutingContext& context);
    
    // Route with specific strategy
    RoutingDecision routeWithStrategy(const RoutingContext& context,
                                        const std::string& strategy_name);

    // Strategy management
    void registerStrategy(std::unique_ptr<RoutingStrategy> strategy);
    void setDefaultStrategy(const std::string& strategy_name);
    std::vector<std::string> listStrategies() const;

    // Direct routing (bypass strategies)
    RoutingDecision routeToModel(const std::string& model_full_name);
    RoutingDecision routeToInstance(const std::string& instance_id);

    // Health-based filtering
    void setRequireHealthy(bool require) { require_healthy_ = require; }
    void setMaxLatencyMs(float max_latency) { max_latency_ms_ = max_latency; }

    // Statistics
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t successful_routes = 0;
        uint64_t failed_routes = 0;
        std::unordered_map<std::string, uint64_t> strategy_usage;
    };
    Stats getStats() const { return stats_; }

private:
    std::shared_ptr<ModelRegistry> registry_;
    std::unordered_map<std::string, std::unique_ptr<RoutingStrategy>> strategies_;
    std::string default_strategy_ = "round_robin";
    
    bool require_healthy_ = true;
    float max_latency_ms_ = 0.0f;
    
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    std::vector<ModelInstance> getCandidates(const RoutingContext& context);
    bool isInstanceSuitable(const ModelInstance& instance, const RoutingContext& context);
};

// Request transformer (for model-specific preprocessing)
class RequestTransformer {
public:
    // Transform request for specific model
    static RoutingContext transformForModel(const RoutingContext& context,
                                             const ModelMetadata& model);
    
    // Add model-specific parameters
    static void addModelParams(RoutingContext& context,
                                const ModelMetadata& model);
    
    // Tokenization adapter
    static std::vector<int> adaptTokenization(const std::vector<int>& tokens,
                                               const std::string& source_model,
                                               const std::string& target_model);
};

} // namespace rawrxd::serving
