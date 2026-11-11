// RawrXD Load Balancer Implementation
// Phase AR: Auto-Scaling & Load Balancing

#include "load_balancer.hpp"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <cstring>

namespace rawrxd {
namespace scaling {

// Global instances
static std::unique_ptr<LoadBalancer> g_load_balancer;
static std::unique_ptr<HealthChecker> g_health_checker;
static std::unique_ptr<BackendPool> g_backend_pool;

LoadBalancer* getLoadBalancer() {
    return g_load_balancer.get();
}

void setLoadBalancer(std::unique_ptr<LoadBalancer> balancer) {
    g_load_balancer = std::move(balancer);
}

HealthChecker* getHealthChecker() {
    return g_health_checker.get();
}

void setHealthChecker(std::unique_ptr<HealthChecker> checker) {
    g_health_checker = std::move(checker);
}

BackendPool* getBackendPool() {
    return g_backend_pool.get();
}

void setBackendPool(std::unique_ptr<BackendPool> pool) {
    g_backend_pool = std::move(pool);
}

// LoadBalancer implementation
LoadBalancer::LoadBalancer()
    : current_strategy_(BalancingStrategy::ROUND_ROBIN)
    , total_requests_(0)
    , active_connections_(0)
    , running_(false) {
}

LoadBalancer::~LoadBalancer() {
    shutdown();
}

bool LoadBalancer::initialize(const LoadBalancerConfig& config) {
    config_ = config;
    current_strategy_ = config_.strategy;
    
    // Initialize strategy
    setStrategy(current_strategy_);
    
    running_ = true;
    health_check_thread_ = std::thread(&LoadBalancer::healthCheckLoop, this);
    
    std::cout << "Load balancer initialized (strategy=" << balancingStrategyToString(current_strategy_) << ")" << std::endl;
    return true;
}

void LoadBalancer::shutdown() {
    running_ = false;
    
    if (health_check_thread_.joinable()) {
        health_check_thread_.join();
    }
    
    std::cout << "Load balancer shutdown" << std::endl;
}

bool LoadBalancer::addBackend(const BackendServer& backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if backend already exists
    for (const auto& b : backends_) {
        if (b.id == backend.id) {
            std::cerr << "Backend already exists: " << backend.id << std::endl;
            return false;
        }
    }
    
    backends_.push_back(backend);
    circuit_breakers_[backend.id] = CircuitBreaker();
    
    std::cout << "Backend added: " << backend.id << " at " << backend.address << ":" << backend.port << std::endl;
    return true;
}

bool LoadBalancer::removeBackend(const std::string& backend_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::remove_if(backends_.begin(), backends_.end(),
                             [&backend_id](const BackendServer& b) { return b.id == backend_id; });
    
    if (it == backends_.end()) {
        return false;
    }
    
    backends_.erase(it, backends_.end());
    circuit_breakers_.erase(backend_id);
    
    std::cout << "Backend removed: " << backend_id << std::endl;
    return true;
}

bool LoadBalancer::updateBackend(const std::string& backend_id, const BackendServer& backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& b : backends_) {
        if (b.id == backend_id) {
            b = backend;
            b.id = backend_id;  // Preserve ID
            return true;
        }
    }
    
    return false;
}

std::vector<BackendServer> LoadBalancer::getBackends() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return backends_;
}

std::vector<BackendServer> LoadBalancer::getHealthyBackends() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<BackendServer> healthy;
    for (const auto& backend : backends_) {
        if (backend.healthy && getCircuitState(backend.id) == CircuitState::CLOSED) {
            healthy.push_back(backend);
        }
    }
    
    return healthy;
}

RoutingDecision LoadBalancer::route(const RequestContext& context) {
    auto start = std::chrono::high_resolution_clock::now();
    
    RoutingDecision decision;
    
    // Check sticky session
    if (config_.sticky_sessions && !context.session_id.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = session_backends_.find(context.session_id);
        if (it != session_backends_.end()) {
            for (const auto& backend : backends_) {
                if (backend.id == it->second && backend.healthy) {
                    decision.backend_id = backend.id;
                    decision.backend_address = backend.address;
                    decision.backend_port = backend.port;
                    decision.from_cache = true;
                    
                    auto end = std::chrono::high_resolution_clock::now();
                    decision.decision_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                    
                    total_requests_++;
                    active_connections_++;
                    
                    return decision;
                }
            }
        }
    }
    
    // Get healthy backends
    auto healthy_backends = getHealthyBackends();
    
    if (healthy_backends.empty()) {
        decision.backend_id = "";
        return decision;
    }
    
    // Select backend using strategy
    BackendServer* selected = nullptr;
    if (strategy_impl_) {
        selected = strategy_impl_->selectBackend(healthy_backends, context);
    }
    
    if (!selected && !healthy_backends.empty()) {
        selected = &healthy_backends[0];
    }
    
    if (selected) {
        decision.backend_id = selected->id;
        decision.backend_address = selected->address;
        decision.backend_port = selected->port;
        
        // Store session mapping
        if (config_.sticky_sessions && !context.session_id.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            session_backends_[context.session_id] = selected->id;
        }
        
        // Update backend metrics
        for (auto& backend : backends_) {
            if (backend.id == selected->id) {
                backend.active_connections++;
                backend.total_requests++;
                break;
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    decision.decision_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    total_requests_++;
    active_connections_++;
    
    return decision;
}

RoutingDecision LoadBalancer::route(const std::string& client_ip) {
    RequestContext context;
    context.client_ip = client_ip;
    return route(context);
}

void LoadBalancer::setStrategy(BalancingStrategy strategy) {
    current_strategy_ = strategy;
    
    switch (strategy) {
        case BalancingStrategy::ROUND_ROBIN:
            strategy_impl_ = std::make_unique<RoundRobinStrategy>();
            break;
        case BalancingStrategy::LEAST_CONNECTIONS:
            strategy_impl_ = std::make_unique<LeastConnectionsStrategy>();
            break;
        case BalancingStrategy::WEIGHTED_ROUND_ROBIN:
            strategy_impl_ = std::make_unique<WeightedRoundRobinStrategy>();
            break;
        case BalancingStrategy::IP_HASH:
            strategy_impl_ = std::make_unique<IPHashStrategy>();
            break;
        case BalancingStrategy::LEAST_RESPONSE_TIME:
            strategy_impl_ = std::make_unique<LeastResponseTimeStrategy>();
            break;
        default:
            strategy_impl_ = std::make_unique<RoundRobinStrategy>();
            break;
    }
    
    std::cout << "Load balancing strategy set to: " << balancingStrategyToString(strategy) << std::endl;
}

void LoadBalancer::setStrategy(std::unique_ptr<BalancingStrategyInterface> strategy) {
    strategy_impl_ = std::move(strategy);
}

BalancingStrategy LoadBalancer::getStrategy() const {
    return current_strategy_;
}

void LoadBalancer::markHealthy(const std::string& backend_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& backend : backends_) {
        if (backend.id == backend_id) {
            backend.healthy = true;
            backend.consecutive_failures = 0;
            backend.last_health_check = std::chrono::system_clock::now();
            break;
        }
    }
}

void LoadBalancer::markUnhealthy(const std::string& backend_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& backend : backends_) {
        if (backend.id == backend_id) {
            backend.healthy = false;
            break;
        }
    }
}

bool LoadBalancer::isHealthy(const std::string& backend_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& backend : backends_) {
        if (backend.id == backend_id) {
            return backend.healthy;
        }
    }
    
    return false;
}

size_t LoadBalancer::getTotalRequests() const {
    return total_requests_.load();
}

size_t LoadBalancer::getActiveConnections() const {
    return active_connections_.load();
}

double LoadBalancer::getAverageResponseTime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (backends_.empty()) {
        return 0.0;
    }
    
    double total = 0.0;
    for (const auto& backend : backends_) {
        total += backend.average_response_time_ms;
    }
    
    return total / backends_.size();
}

CircuitState LoadBalancer::getCircuitState(const std::string& backend_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = circuit_breakers_.find(backend_id);
    if (it != circuit_breakers_.end()) {
        return it->second.state;
    }
    
    return CircuitState::CLOSED;
}

void LoadBalancer::recordSuccess(const std::string& backend_id) {
    updateCircuitBreaker(backend_id, true);
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& backend : backends_) {
        if (backend.id == backend_id) {
            backend.active_connections = std::max(0, static_cast<int>(backend.active_connections) - 1);
            break;
        }
    }
    
    active_connections_--;
}

void LoadBalancer::recordFailure(const std::string& backend_id) {
    updateCircuitBreaker(backend_id, false);
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& backend : backends_) {
        if (backend.id == backend_id) {
            backend.active_connections = std::max(0, static_cast<int>(backend.active_connections) - 1);
            break;
        }
    }
    
    active_connections_--;
}

void LoadBalancer::healthCheckLoop() {
    while (running_) {
        std::this_thread::sleep_for(config_.health_check_interval);
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& backend : backends_) {
            bool healthy = performHealthCheck(backend);
            
            if (healthy) {
                if (!backend.healthy) {
                    backend.consecutive_failures = 0;
                    backend.healthy = true;
                    std::cout << "Backend healthy: " << backend.id << std::endl;
                }
            } else {
                backend.consecutive_failures++;
                
                if (backend.consecutive_failures >= config_.max_failures_before_unhealthy) {
                    if (backend.healthy) {
                        backend.healthy = false;
                        std::cout << "Backend unhealthy: " << backend.id << std::endl;
                    }
                }
            }
            
            backend.last_health_check = std::chrono::system_clock::now();
        }
    }
}

bool LoadBalancer::performHealthCheck(BackendServer& backend) {
    // Simple TCP health check
    // In real implementation, would perform actual health check
    return backend.consecutive_failures < config_.max_failures_before_unhealthy;
}

void LoadBalancer::updateCircuitBreaker(const std::string& backend_id, bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& breaker = circuit_breakers_[backend_id];
    
    if (success) {
        if (breaker.state == CircuitState::HALF_OPEN) {
            breaker.state = CircuitState::CLOSED;
            breaker.failure_count = 0;
        }
    } else {
        breaker.failure_count++;
        breaker.last_failure_time = std::chrono::system_clock::now();
        
        if (breaker.state == CircuitState::CLOSED && 
            breaker.failure_count >= config_.circuit_breaker_threshold) {
            breaker.state = CircuitState::OPEN;
            breaker.open_time = std::chrono::system_clock::now();
            std::cout << "Circuit breaker opened for: " << backend_id << std::endl;
        }
    }
}

std::string LoadBalancer::getClientHash(const std::string& client_ip) const {
    // Simple hash for session affinity
    std::hash<std::string> hasher;
    return std::to_string(hasher(client_ip));
}

// HealthChecker implementation
HealthChecker::HealthChecker()
    : interval_(std::chrono::seconds(10))
    , timeout_ms_(5000)
    , running_(false) {
}

HealthChecker::~HealthChecker() {
    shutdown();
}

bool HealthChecker::initialize(std::chrono::seconds interval, int timeout_ms) {
    interval_ = interval;
    timeout_ms_ = timeout_ms;
    return true;
}

void HealthChecker::shutdown() {
    running_ = false;
    
    if (check_thread_.joinable()) {
        check_thread_.join();
    }
}

bool HealthChecker::checkHealth(const BackendServer& backend) {
    return checkTCP(backend.address, backend.port, timeout_ms_);
}

bool HealthChecker::checkTCP(const std::string& address, int port, int timeout_ms) {
    // Platform-specific TCP check would go here
    // For now, simulate success
    return true;
}

bool HealthChecker::checkHTTP(const std::string& url, int timeout_ms) {
    // HTTP health check would go here
    return true;
}

std::vector<std::pair<std::string, bool>> HealthChecker::checkAll(
    const std::vector<BackendServer>& backends) {
    
    std::vector<std::pair<std::string, bool>> results;
    
    for (const auto& backend : backends) {
        bool healthy = checkHealth(backend);
        results.emplace_back(backend.id, healthy);
    }
    
    return results;
}

void HealthChecker::setHealthChangeCallback(HealthChangeCallback callback) {
    callback_ = callback;
}

void HealthChecker::checkLoop() {
    // Implementation for continuous health checking
}

// BackendPool implementation
BackendPool::BackendPool() = default;

BackendPool::~BackendPool() {
    shutdown();
}

bool BackendPool::initialize(size_t max_connections_per_backend) {
    max_connections_per_backend_ = max_connections_per_backend;
    return true;
}

void BackendPool::shutdown() {
    clearAllPools();
}

void* BackendPool::acquireConnection(const std::string& backend_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& pool = pools_[backend_id];
    
    // Return idle connection if available
    if (!pool.idle_connections.empty()) {
        void* conn = pool.idle_connections.back();
        pool.idle_connections.pop_back();
        pool.active_connections.insert(conn);
        return conn;
    }
    
    // Check if we can create new connection
    if (pool.active_connections.size() + pool.idle_connections.size() >= max_connections_per_backend_) {
        return nullptr;
    }
    
    // Create new connection (simulated)
    void* conn = reinterpret_cast<void*>(1);  // Placeholder
    pool.active_connections.insert(conn);
    return conn;
}

void BackendPool::releaseConnection(const std::string& backend_id, void* connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pools_.find(backend_id);
    if (it == pools_.end()) {
        return;
    }
    
    auto& pool = it->second;
    pool.active_connections.erase(connection);
    pool.idle_connections.push_back(connection);
}

void BackendPool::invalidateConnection(const std::string& backend_id, void* connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pools_.find(backend_id);
    if (it == pools_.end()) {
        return;
    }
    
    auto& pool = it->second;
    pool.active_connections.erase(connection);
    // Don't return to idle pool
}

size_t BackendPool::getPoolSize(const std::string& backend_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pools_.find(backend_id);
    if (it != pools_.end()) {
        return it->second.idle_connections.size() + it->second.active_connections.size();
    }
    
    return 0;
}

size_t BackendPool::getActiveConnections(const std::string& backend_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pools_.find(backend_id);
    if (it != pools_.end()) {
        return it->second.active_connections.size();
    }
    
    return 0;
}

size_t BackendPool::getIdleConnections(const std::string& backend_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pools_.find(backend_id);
    if (it != pools_.end()) {
        return it->second.idle_connections.size();
    }
    
    return 0;
}

void BackendPool::pruneIdleConnections(std::chrono::seconds max_idle_time) {
    // Implementation would remove idle connections older than max_idle_time
}

void BackendPool::clearPool(const std::string& backend_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pools_.erase(backend_id);
}

void BackendPool::clearAllPools() {
    std::lock_guard<std::mutex> lock(mutex_);
    pools_.clear();
}

// RoundRobinStrategy implementation
BackendServer* RoundRobinStrategy::selectBackend(const std::vector<BackendServer>& backends,
                                                  const RequestContext& context) {
    if (backends.empty()) {
        return nullptr;
    }
    
    size_t index = current_index_.fetch_add(1) % backends.size();
    return const_cast<BackendServer*>(&backends[index]);
}

void RoundRobinStrategy::updateMetrics(const std::string& backend_id, double response_time_ms) {
    // No-op for round robin
}

// LeastConnectionsStrategy implementation
BackendServer* LeastConnectionsStrategy::selectBackend(const std::vector<BackendServer>& backends,
                                                        const RequestContext& context) {
    if (backends.empty()) {
        return nullptr;
    }
    
    const BackendServer* selected = &backends[0];
    size_t min_connections = backends[0].active_connections;
    
    for (const auto& backend : backends) {
        if (backend.active_connections < min_connections) {
            min_connections = backend.active_connections;
            selected = &backend;
        }
    }
    
    return const_cast<BackendServer*>(selected);
}

void LeastConnectionsStrategy::updateMetrics(const std::string& backend_id, double response_time_ms) {
    // No-op
}

// WeightedRoundRobinStrategy implementation
BackendServer* WeightedRoundRobinStrategy::selectBackend(const std::vector<BackendServer>& backends,
                                                          const RequestContext& context) {
    if (backends.empty()) {
        return nullptr;
    }
    
    // Simple weighted round robin
    size_t index = current_index_.fetch_add(1) % backends.size();
    return const_cast<BackendServer*>(&backends[index]);
}

void WeightedRoundRobinStrategy::updateMetrics(const std::string& backend_id, double response_time_ms) {
    // No-op
}

void WeightedRoundRobinStrategy::setBackendWeight(const std::string& backend_id, int weight) {
    weights_[backend_id] = weight;
}

// IPHashStrategy implementation
BackendServer* IPHashStrategy::selectBackend(const std::vector<BackendServer>& backends,
                                              const RequestContext& context) {
    if (backends.empty()) {
        return nullptr;
    }
    
    size_t hash = hashIP(context.client_ip);
    size_t index = hash % backends.size();
    return const_cast<BackendServer*>(&backends[index]);
}

size_t IPHashStrategy::hashIP(const std::string& ip) const {
    std::hash<std::string> hasher;
    return hasher(ip);
}

// LeastResponseTimeStrategy implementation
BackendServer* LeastResponseTimeStrategy::selectBackend(const std::vector<BackendServer>& backends,
                                                         const RequestContext& context) {
    if (backends.empty()) {
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    const BackendServer* selected = &backends[0];
    double min_response_time = response_times_[backends[0].id];
    
    for (const auto& backend : backends) {
        double response_time = response_times_[backend.id];
        if (response_time < min_response_time) {
            min_response_time = response_time;
            selected = &backend;
        }
    }
    
    return const_cast<BackendServer*>(selected);
}

void LeastResponseTimeStrategy::updateMetrics(const std::string& backend_id, double response_time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    response_times_[backend_id] = response_time_ms;
}

// Utility functions
std::string balancingStrategyToString(BalancingStrategy strategy) {
    switch (strategy) {
        case BalancingStrategy::ROUND_ROBIN: return "round_robin";
        case BalancingStrategy::LEAST_CONNECTIONS: return "least_connections";
        case BalancingStrategy::WEIGHTED_ROUND_ROBIN: return "weighted_round_robin";
        case BalancingStrategy::IP_HASH: return "ip_hash";
        case BalancingStrategy::RANDOM: return "random";
        case BalancingStrategy::LEAST_RESPONSE_TIME: return "least_response_time";
        case BalancingStrategy::CONSISTENT_HASH: return "consistent_hash";
        default: return "unknown";
    }
}

BalancingStrategy stringToBalancingStrategy(const std::string& str) {
    if (str == "round_robin") return BalancingStrategy::ROUND_ROBIN;
    if (str == "least_connections") return BalancingStrategy::LEAST_CONNECTIONS;
    if (str == "weighted_round_robin") return BalancingStrategy::WEIGHTED_ROUND_ROBIN;
    if (str == "ip_hash") return BalancingStrategy::IP_HASH;
    if (str == "random") return BalancingStrategy::RANDOM;
    if (str == "least_response_time") return BalancingStrategy::LEAST_RESPONSE_TIME;
    if (str == "consistent_hash") return BalancingStrategy::CONSISTENT_HASH;
    return BalancingStrategy::ROUND_ROBIN;
}

std::string circuitStateToString(CircuitState state) {
    switch (state) {
        case CircuitState::CLOSED: return "CLOSED";
        case CircuitState::OPEN: return "OPEN";
        case CircuitState::HALF_OPEN: return "HALF_OPEN";
        default: return "UNKNOWN";
    }
}

} // namespace scaling
} // namespace rawrxd
