// RawrXD Load Balancer
// Phase AR: Auto-Scaling & Load Balancing

#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <random>

namespace rawrxd {
namespace scaling {

// Backend server info
struct BackendServer {
    std::string id;
    std::string address;
    int port;
    std::string region;
    std::vector<std::string> tags;
    
    // Health status
    bool healthy;
    std::chrono::system_clock::time_point last_health_check;
    int consecutive_failures;
    
    // Metrics
    size_t active_connections;
    size_t total_requests;
    double average_response_time_ms;
    double current_load;
    
    BackendServer()
        : port(8080)
        , healthy(true)
        , consecutive_failures(0)
        , active_connections(0)
        , total_requests(0)
        , average_response_time_ms(0.0)
        , current_load(0.0) {}
};

// Load balancing strategy
enum class BalancingStrategy {
    ROUND_ROBIN,
    LEAST_CONNECTIONS,
    WEIGHTED_ROUND_ROBIN,
    IP_HASH,
    RANDOM,
    LEAST_RESPONSE_TIME,
    CONSISTENT_HASH
};

// Load balancer configuration
struct LoadBalancerConfig {
    BalancingStrategy strategy;
    std::chrono::seconds health_check_interval;
    int health_check_timeout_ms;
    int max_failures_before_unhealthy;
    int recovery_failures_before_healthy;
    bool sticky_sessions;
    std::string session_cookie;
    
    // Circuit breaker
    bool enable_circuit_breaker;
    int circuit_breaker_threshold;
    std::chrono::seconds circuit_breaker_timeout;
    
    LoadBalancerConfig()
        : strategy(BalancingStrategy::ROUND_ROBIN)
        , health_check_interval(std::chrono::seconds(10))
        , health_check_timeout_ms(5000)
        , max_failures_before_unhealthy(3)
        , recovery_failures_before_healthy(2)
        , sticky_sessions(false)
        , session_cookie("RAWRXD_SESSION")
        , enable_circuit_breaker(true)
        , circuit_breaker_threshold(5)
        , circuit_breaker_timeout(std::chrono::seconds(30)) {}
};

// Routing decision
struct RoutingDecision {
    std::string backend_id;
    std::string backend_address;
    int backend_port;
    bool from_cache;
    std::chrono::microseconds decision_time_us;
    
    RoutingDecision()
        : backend_port(0)
        , from_cache(false)
        , decision_time_us(0) {}
};

// Request context
struct RequestContext {
    std::string client_ip;
    std::string session_id;
    std::string request_path;
    std::unordered_map<std::string, std::string> headers;
    size_t request_size;
    
    RequestContext() : request_size(0) {}
};

// Circuit breaker state
enum class CircuitState {
    CLOSED,     // Normal operation
    OPEN,       // Failing, rejecting requests
    HALF_OPEN   // Testing if recovered
};

// Circuit breaker
struct CircuitBreaker {
    CircuitState state;
    int failure_count;
    std::chrono::system_clock::time_point last_failure_time;
    std::chrono::system_clock::time_point open_time;
    
    CircuitBreaker()
        : state(CircuitState::CLOSED)
        , failure_count(0) {}
};

// Forward declarations
class LoadBalancer;
class HealthChecker;
class BackendPool;

// Strategy interface
class BalancingStrategyInterface {
public:
    virtual ~BalancingStrategyInterface() = default;
    virtual BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                         const RequestContext& context) = 0;
    virtual std::string getName() const = 0;
    virtual void updateMetrics(const std::string& backend_id, double response_time_ms) = 0;
};

/**
 * LoadBalancer - Intelligent load distribution
 */
class LoadBalancer {
public:
    LoadBalancer();
    ~LoadBalancer();
    
    // Initialize
    bool initialize(const LoadBalancerConfig& config);
    void shutdown();
    
    // Backend management
    bool addBackend(const BackendServer& backend);
    bool removeBackend(const std::string& backend_id);
    bool updateBackend(const std::string& backend_id, const BackendServer& backend);
    std::vector<BackendServer> getBackends() const;
    std::vector<BackendServer> getHealthyBackends() const;
    
    // Routing
    RoutingDecision route(const RequestContext& context);
    RoutingDecision route(const std::string& client_ip);
    
    // Strategy
    void setStrategy(BalancingStrategy strategy);
    void setStrategy(std::unique_ptr<BalancingStrategyInterface> strategy);
    BalancingStrategy getStrategy() const;
    
    // Health management
    void markHealthy(const std::string& backend_id);
    void markUnhealthy(const std::string& backend_id);
    bool isHealthy(const std::string& backend_id) const;
    
    // Statistics
    size_t getTotalRequests() const;
    size_t getActiveConnections() const;
    double getAverageResponseTime() const;
    
    // Circuit breaker
    CircuitState getCircuitState(const std::string& backend_id) const;
    void recordSuccess(const std::string& backend_id);
    void recordFailure(const std::string& backend_id);
    
private:
    LoadBalancerConfig config_;
    std::vector<BackendServer> backends_;
    std::unordered_map<std::string, CircuitBreaker> circuit_breakers_;
    std::unordered_map<std::string, std::string> session_backends_;
    
    std::unique_ptr<BalancingStrategyInterface> strategy_impl_;
    BalancingStrategy current_strategy_;
    
    mutable std::mutex mutex_;
    std::atomic<size_t> total_requests_;
    std::atomic<size_t> active_connections_;
    
    std::thread health_check_thread_;
    bool running_;
    
    // Internal methods
    void healthCheckLoop();
    bool performHealthCheck(BackendServer& backend);
    void updateCircuitBreaker(const std::string& backend_id, bool success);
    std::string getClientHash(const std::string& client_ip) const;
};

/**
 * HealthChecker - Backend health monitoring
 */
class HealthChecker {
public:
    HealthChecker();
    ~HealthChecker();
    
    bool initialize(std::chrono::seconds interval, int timeout_ms);
    void shutdown();
    
    // Health checks
    bool checkHealth(const BackendServer& backend);
    bool checkTCP(const std::string& address, int port, int timeout_ms);
    bool checkHTTP(const std::string& url, int timeout_ms);
    
    // Batch checks
    std::vector<std::pair<std::string, bool>> checkAll(
        const std::vector<BackendServer>& backends);
    
    // Callbacks
    using HealthChangeCallback = std::function<void(const std::string& backend_id, bool healthy)>;
    void setHealthChangeCallback(HealthChangeCallback callback);
    
private:
    std::chrono::seconds interval_;
    int timeout_ms_;
    HealthChangeCallback callback_;
    bool running_;
    std::thread check_thread_;
    
    void checkLoop();
};

/**
 * BackendPool - Connection pool management
 */
class BackendPool {
public:
    BackendPool();
    ~BackendPool();
    
    bool initialize(size_t max_connections_per_backend);
    void shutdown();
    
    // Connection management
    void* acquireConnection(const std::string& backend_id);
    void releaseConnection(const std::string& backend_id, void* connection);
    void invalidateConnection(const std::string& backend_id, void* connection);
    
    // Pool stats
    size_t getPoolSize(const std::string& backend_id) const;
    size_t getActiveConnections(const std::string& backend_id) const;
    size_t getIdleConnections(const std::string& backend_id) const;
    
    // Maintenance
    void pruneIdleConnections(std::chrono::seconds max_idle_time);
    void clearPool(const std::string& backend_id);
    void clearAllPools();
    
private:
    size_t max_connections_per_backend_;
    
    struct ConnectionPool {
        std::vector<void*> idle_connections;
        std::unordered_set<void*> active_connections;
    };
    
    std::unordered_map<std::string, ConnectionPool> pools_;
    mutable std::mutex mutex_;
};

// Strategy implementations
class RoundRobinStrategy : public BalancingStrategyInterface {
public:
    BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                 const RequestContext& context) override;
    std::string getName() const override { return "round_robin"; }
    void updateMetrics(const std::string& backend_id, double response_time_ms) override;
    
private:
    std::atomic<size_t> current_index_{0};
};

class LeastConnectionsStrategy : public BalancingStrategyInterface {
public:
    BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                 const RequestContext& context) override;
    std::string getName() const override { return "least_connections"; }
    void updateMetrics(const std::string& backend_id, double response_time_ms) override;
};

class WeightedRoundRobinStrategy : public BalancingStrategyInterface {
public:
    BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                 const RequestContext& context) override;
    std::string getName() const override { return "weighted_round_robin"; }
    void updateMetrics(const std::string& backend_id, double response_time_ms) override;
    void setBackendWeight(const std::string& backend_id, int weight);
    
private:
    std::unordered_map<std::string, int> weights_;
    std::atomic<size_t> current_index_{0};
    int current_weight_{0};
    int max_weight_{0};
};

class IPHashStrategy : public BalancingStrategyInterface {
public:
    BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                 const RequestContext& context) override;
    std::string getName() const override { return "ip_hash"; }
    void updateMetrics(const std::string& backend_id, double response_time_ms) override {}
    
private:
    size_t hashIP(const std::string& ip) const;
};

class LeastResponseTimeStrategy : public BalancingStrategyInterface {
public:
    BackendServer* selectBackend(const std::vector<BackendServer>& backends,
                                 const RequestContext& context) override;
    std::string getName() const override { return "least_response_time"; }
    void updateMetrics(const std::string& backend_id, double response_time_ms) override;
    
private:
    std::unordered_map<std::string, double> response_times_;
    mutable std::mutex mutex_;
};

// Global accessor
LoadBalancer* getLoadBalancer();
void setLoadBalancer(std::unique_ptr<LoadBalancer> balancer);

HealthChecker* getHealthChecker();
void setHealthChecker(std::unique_ptr<HealthChecker> checker);

BackendPool* getBackendPool();
void setBackendPool(std::unique_ptr<BackendPool> pool);

// Utility functions
std::string balancingStrategyToString(BalancingStrategy strategy);
BalancingStrategy stringToBalancingStrategy(const std::string& str);
std::string circuitStateToString(CircuitState state);

} // namespace scaling
} // namespace rawrxd
