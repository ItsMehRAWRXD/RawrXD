#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd {
namespace serving {

// Routing rule types
enum class RoutingRuleType {
    HEADER,           // Route based on HTTP header
    QUERY_PARAM,      // Route based on query parameter
    USER_ID,          // Route based on user ID
    SESSION,          // Route based on session
    GEOGRAPHIC,       // Route based on geography
    TIME_BASED,       // Route based on time
    WEIGHTED,         // Weighted distribution
    CANARY,           // Canary deployment
    BLUE_GREEN,       // Blue-green deployment
    CUSTOM            // Custom rule
};

// Routing rule
struct RoutingRule {
    std::string rule_id;
    std::string name;
    RoutingRuleType type;
    int priority = 0;  // Higher priority rules evaluated first
    bool enabled = true;
    
    // Match conditions
    struct Condition {
        std::string key;           // Header name, param name, etc.
        std::string operator_;     // "eq", "ne", "contains", "regex", "in"
        std::string value;
        bool case_sensitive = true;
    };
    std::vector<Condition> conditions;
    
    // Target configuration
    struct Target {
        std::string model_id;
        std::string version_id;
        float weight = 1.0f;       // For weighted routing
        std::unordered_map<std::string, std::string> metadata;
    };
    std::vector<Target> targets;
    
    // Rule metadata
    std::unordered_map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
};

// Routing context
struct RoutingContext {
    std::string request_id;
    std::string user_id;
    std::string session_id;
    std::string client_ip;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::chrono::system_clock::time_point timestamp;
    std::string geographic_region;
    
    // Additional context
    std::unordered_map<std::string, std::string> custom;
};

// Routing decision
struct RoutingDecision {
    std::string model_id;
    std::string version_id;
    std::string rule_id;  // Which rule matched
    float confidence;     // Routing confidence (0.0 - 1.0)
    std::unordered_map<std::string, std::string> metadata;
    bool from_cache;
};

// Traffic router for multi-model serving
class TrafficRouter {
public:
    TrafficRouter();
    ~TrafficRouter();
    
    // Rule management
    std::string addRule(const RoutingRule& rule);
    bool updateRule(const std::string& rule_id, const RoutingRule& rule);
    bool deleteRule(const std::string& rule_id);
    bool enableRule(const std::string& rule_id, bool enabled);
    
    std::optional<RoutingRule> getRule(const std::string& rule_id) const;
    std::vector<RoutingRule> listRules() const;
    std::vector<RoutingRule> listRulesByType(RoutingRuleType type) const;
    
    // Reorder rules by priority
    bool setRulePriority(const std::string& rule_id, int priority);
    
    // Routing
    RoutingDecision route(const RoutingContext& context);
    
    // Batch routing
    std::vector<RoutingDecision> routeBatch(const std::vector<RoutingContext>& contexts);
    
    // Cache control
    void enableCache(bool enabled);
    void clearCache();
    void setCacheTTL(std::chrono::seconds ttl);
    
    // Statistics
    struct RouteStats {
        size_t total_requests;
        size_t cache_hits;
        size_t cache_misses;
        std::unordered_map<std::string, size_t> rule_matches;
        std::unordered_map<std::string, size_t> model_routes;
    };
    RouteStats getStats() const;
    void resetStats();
    
    // Custom matcher
    using CustomMatcher = std::function<bool(const RoutingContext&, const RoutingRule&)>;
    void registerCustomMatcher(const std::string& name, CustomMatcher matcher);
    
    // Import/Export
    bool exportRules(const std::string& path) const;
    bool importRules(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Load balancer for model instances
class ModelLoadBalancer {
public:
    enum class Strategy {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        LEAST_LATENCY,
        WEIGHTED_ROUND_ROBIN,
        IP_HASH,
        RANDOM
    };
    
    struct Instance {
        std::string instance_id;
        std::string model_id;
        std::string version_id;
        std::string endpoint;
        float weight = 1.0f;
        bool healthy = true;
        size_t active_connections = 0;
        float avg_latency_ms = 0.0f;
        std::chrono::system_clock::time_point last_health_check;
    };
    
    explicit ModelLoadBalancer(Strategy strategy = Strategy::ROUND_ROBIN);
    ~ModelLoadBalancer();
    
    // Instance management
    void registerInstance(const Instance& instance);
    void unregisterInstance(const std::string& instance_id);
    void updateInstanceHealth(const std::string& instance_id, bool healthy);
    void updateInstanceMetrics(const std::string& instance_id, 
                                size_t connections,
                                float latency_ms);
    
    // Selection
    std::optional<Instance> selectInstance(const std::string& model_id,
                                             const std::string& version_id = "",
                                             const std::string& client_id = "");
    
    // Strategy
    void setStrategy(Strategy strategy);
    
    // Health checking
    void enableHealthChecks(bool enabled, std::chrono::seconds interval = std::chrono::seconds(30));
    void setHealthCheckEndpoint(const std::string& endpoint);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Traffic shadowing for testing
class TrafficShadow {
public:
    struct Config {
        std::string source_model;
        std::string source_version;
        std::string shadow_model;
        std::string shadow_version;
        float shadow_percentage = 0.0f;  // 0-100%
        bool compare_responses = false;
        float tolerance_percentage = 5.0f;  // Response diff tolerance
    };
    
    explicit TrafficShadow(const Config& config);
    ~TrafficShadow();
    
    // Shadow traffic
    bool shouldShadow(const std::string& request_id);
    void recordShadowResult(const std::string& request_id,
                           bool success,
                           float latency_ms,
                           const std::string& diff = "");
    
    // Statistics
    struct Stats {
        size_t total_shadowed;
        size_t successful_shadows;
        size_t failed_shadows;
        size_t mismatches;
        float avg_shadow_latency_ms;
    };
    Stats getStats() const;
    void resetStats();

private:
    Config config_;
    std::mt19937 rng_;
    std::atomic<size_t> total_shadowed_{0};
    std::atomic<size_t> successful_shadows_{0};
    std::atomic<size_t> failed_shadows_{0};
    std::atomic<size_t> mismatches_{0};
    std::atomic<float> total_latency_ms_{0.0f};
};

} // namespace serving
} // namespace rawrxd
