#include "rawrxd/deployment/AutoScaling.hpp"
#include <algorithm>
#include <cmath>

namespace rawrxd {
namespace deployment {

AutoScalingManager::AutoScalingManager() = default;

AutoScalingManager::~AutoScalingManager() {
    Stop();
}

bool AutoScalingManager::Initialize(const AutoScalingConfig& config,
                                    std::function<std::string()> spawnInstance,
                                    std::function<void(const std::string&)> terminateInstance) {
    config_ = config;
    spawnInstance_ = spawnInstance;
    terminateInstance_ = terminateInstance;
    desiredCapacity_ = config.minInstances;
    return true;
}

bool AutoScalingManager::Start() {
    if (running_.exchange(true)) return false;
    
    evaluationThread_ = std::thread(&AutoScalingManager::EvaluationLoop, this);
    return true;
}

void AutoScalingManager::Stop() {
    running_ = false;
    if (evaluationThread_.joinable()) {
        evaluationThread_.join();
    }
}

void AutoScalingManager::UpdateInstanceMetrics(const std::string& instanceId,
                                               const InstanceInfo& metrics) {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    instances_[instanceId] = metrics;
}

std::vector<InstanceInfo> AutoScalingManager::GetInstances() const {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    std::vector<InstanceInfo> result;
    for (const auto& pair : instances_) {
        result.push_back(pair.second);
    }
    return result;
}

void AutoScalingManager::SetDesiredCapacity(int capacity) {
    capacity = std::max(config_.minInstances, std::min(config_.maxInstances, capacity));
    
    if (capacity > currentCapacity_) {
        ScaleOut(capacity - currentCapacity_);
    } else if (capacity < currentCapacity_) {
        ScaleIn(currentCapacity_ - capacity);
    }
}

void AutoScalingManager::ScaleOut(int count) {
    auto now = std::chrono::system_clock::now();
    
    if (now - lastScaleOutTime_ < config_.scaleOutCooldown) {
        return; // In cooldown
    }
    
    for (int i = 0; i < count; ++i) {
        if (currentCapacity_ >= config_.maxInstances) break;
        
        std::string instanceId = spawnInstance_();
        if (!instanceId.empty()) {
            currentCapacity_++;
            desiredCapacity_ = currentCapacity_;
            
            ScalingEvent event;
            event.timestamp = now;
            event.action = "scale_out";
            event.previousCapacity = currentCapacity_ - 1;
            event.newCapacity = currentCapacity_;
            event.reason = "High load";
            
            std::lock_guard<std::mutex> lock(historyMutex_);
            scalingHistory_.push_back(event);
        }
    }
    
    lastScaleOutTime_ = now;
}

void AutoScalingManager::ScaleIn(int count) {
    auto now = std::chrono::system_clock::now();
    
    if (now - lastScaleInTime_ < config_.scaleInCooldown) {
        return; // In cooldown
    }
    
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    // Find instances to terminate (prefer unhealthy ones)
    std::vector<std::string> candidates;
    for (const auto& pair : instances_) {
        if (!pair.second.healthy) {
            candidates.push_back(pair.first);
        }
    }
    
    // If not enough unhealthy, add healthy ones
    if (candidates.size() < static_cast<size_t>(count)) {
        for (const auto& pair : instances_) {
            if (pair.second.healthy) {
                candidates.push_back(pair.first);
            }
        }
    }
    
    // Terminate
    for (int i = 0; i < count && i < static_cast<int>(candidates.size()); ++i) {
        if (currentCapacity_ <= config_.minInstances) break;
        
        terminateInstance_(candidates[i]);
        instances_.erase(candidates[i]);
        currentCapacity_--;
        desiredCapacity_ = currentCapacity_;
        
        ScalingEvent event;
        event.timestamp = now;
        event.action = "scale_in";
        event.previousCapacity = currentCapacity_ + 1;
        event.newCapacity = currentCapacity_;
        event.reason = "Low load";
        
        std::lock_guard<std::mutex> lock(historyMutex_);
        scalingHistory_.push_back(event);
    }
    
    lastScaleInTime_ = now;
}

std::vector<AutoScalingManager::ScalingEvent> AutoScalingManager::GetScalingHistory() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    return scalingHistory_;
}

AutoScalingManager::Stats AutoScalingManager::GetStats() const {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    Stats stats;
    stats.currentInstances = currentCapacity_;
    stats.minInstances = config_.minInstances;
    stats.maxInstances = config_.maxInstances;
    
    std::lock_guard<std::mutex> historyLock(historyMutex_);
    for (const auto& event : scalingHistory_) {
        if (event.action == "scale_out") {
            stats.totalScaleOutEvents++;
        } else {
            stats.totalScaleInEvents++;
        }
    }
    
    // Compute average metrics
    if (!instances_.empty()) {
        double totalCpu = 0.0;
        double totalLatency = 0.0;
        int count = 0;
        
        for (const auto& pair : instances_) {
            totalCpu += pair.second.cpuPercent;
            totalLatency += pair.second.latencyP95Ms;
            count++;
        }
        
        stats.avgCpuUtilization = totalCpu / count;
        stats.avgLatencyP95 = totalLatency / count;
    }
    
    return stats;
}

void AutoScalingManager::EvaluationLoop() {
    while (running_) {
        int newCapacity = CalculateDesiredCapacity();
        
        if (newCapacity != currentCapacity_) {
            ExecuteScaling(newCapacity, "Metric threshold exceeded");
        }
        
        std::this_thread::sleep_for(config_.evaluationInterval);
    }
}

bool AutoScalingManager::ShouldScaleOut() {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    if (instances_.empty()) return false;
    
    double avgCpu = 0.0;
    double avgGpu = 0.0;
    double avgLatency = 0.0;
    int totalQueueDepth = 0;
    
    for (const auto& pair : instances_) {
        avgCpu += pair.second.cpuPercent;
        avgGpu += pair.second.gpuUtilization;
        avgLatency += pair.second.latencyP95Ms;
        totalQueueDepth += pair.second.requestQueueDepth;
    }
    
    avgCpu /= instances_.size();
    avgGpu /= instances_.size();
    avgLatency /= instances_.size();
    
    return avgCpu > config_.cpuThresholdPercent ||
           avgGpu > config_.gpuUtilizationThreshold ||
           avgLatency > config_.latencyP95ThresholdMs ||
           totalQueueDepth > config_.requestQueueDepthThreshold;
}

bool AutoScalingManager::ShouldScaleIn() {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    if (instances_.size() <= static_cast<size_t>(config_.minInstances)) return false;
    
    double avgCpu = 0.0;
    double avgGpu = 0.0;
    
    for (const auto& pair : instances_) {
        avgCpu += pair.second.cpuPercent;
        avgGpu += pair.second.gpuUtilization;
    }
    
    avgCpu /= instances_.size();
    avgGpu /= instances_.size();
    
    return avgCpu < config_.cpuScaleInThresholdPercent &&
           avgGpu < config_.gpuUtilizationThreshold * 0.5;
}

int AutoScalingManager::CalculateDesiredCapacity() {
    switch (config_.strategy) {
        case AutoScalingConfig::Strategy::STEP:
            if (ShouldScaleOut() && currentCapacity_ < config_.maxInstances) {
                return std::min(currentCapacity_ + config_.stepSize, config_.maxInstances);
            } else if (ShouldScaleIn() && currentCapacity_ > config_.minInstances) {
                return std::max(currentCapacity_ - config_.stepSize, config_.minInstances);
            }
            return currentCapacity_;
            
        case AutoScalingConfig::Strategy::TARGET_TRACKING: {
            std::lock_guard<std::mutex> lock(instancesMutex_);
            if (instances_.empty()) return currentCapacity_;
            
            double avgCpu = 0.0;
            for (const auto& pair : instances_) {
                avgCpu += pair.second.cpuPercent;
            }
            avgCpu /= instances_.size();
            
            // Calculate desired based on target
            double ratio = avgCpu / config_.targetMetricValue;
            int desired = static_cast<int>(currentCapacity_ * ratio);
            return std::max(config_.minInstances, std::min(config_.maxInstances, desired));
        }
            
        case AutoScalingConfig::Strategy::PREDICTIVE:
            // Predictive scaling based on trend analysis
            {
                // Calculate trend from recent load history
                double trend = CalculateLoadTrend();
                double predictedLoad = currentLoad + trend * 60.0; // Predict 60 seconds ahead
                
                // Add safety margin
                predictedLoad *= 1.2;
                
                int desired = static_cast<int>(predictedLoad / config_.targetUtilization);
                desired = std::max(config_.minInstances, std::min(config_.maxInstances, desired));
                
                printf("[AutoScaling] Predictive: current=%.1f, trend=%+.2f, predicted=%.1f, desired=%d\n",
                       currentLoad, trend, predictedLoad, desired);
                
                return desired;
            }
            
        default:
            return currentCapacity_;
    }
}

void AutoScalingManager::ExecuteScaling(int newCapacity, const std::string& reason) {
    if (newCapacity > currentCapacity_) {
        ScaleOut(newCapacity - currentCapacity_);
    } else if (newCapacity < currentCapacity_) {
        ScaleIn(currentCapacity_ - newCapacity);
    }
}

// DynamicLoadBalancer implementation
DynamicLoadBalancer::DynamicLoadBalancer() = default;

DynamicLoadBalancer::~DynamicLoadBalancer() {
    StopHealthChecks();
}

bool DynamicLoadBalancer::Initialize(Strategy strategy, std::chrono::seconds healthCheckInterval) {
    strategy_ = strategy;
    healthCheckInterval_ = healthCheckInterval;
    return true;
}

void DynamicLoadBalancer::AddBackend(const Backend& backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    backends_[backend.id] = backend;
}

void DynamicLoadBalancer::RemoveBackend(const std::string& backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    backends_.erase(backendId);
}

void DynamicLoadBalancer::UpdateBackendHealth(const std::string& backendId, bool healthy) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = backends_.find(backendId);
    if (it != backends_.end()) {
        it->second.healthy = healthy;
    }
}

std::string DynamicLoadBalancer::SelectBackend(const std::string& clientIp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (strategy_) {
        case Strategy::ROUND_ROBIN:
            return SelectRoundRobin();
        case Strategy::LEAST_CONNECTIONS:
            return SelectLeastConnections();
        case Strategy::WEIGHTED_RESPONSE_TIME:
            return SelectWeightedResponseTime();
        case Strategy::IP_HASH:
            return SelectIPHash(clientIp);
        case Strategy::RANDOM:
            return SelectRandom();
        default:
            return SelectLeastConnections();
    }
}

void DynamicLoadBalancer::ReportSuccess(const std::string& backendId, double responseTimeMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = backends_.find(backendId);
    if (it != backends_.end()) {
        it->second.activeConnections--;
        it->second.totalRequests++;
        
        // Update average response time
        if (it->second.avgResponseTimeMs == 0) {
            it->second.avgResponseTimeMs = responseTimeMs;
        } else {
            it->second.avgResponseTimeMs = 0.7 * it->second.avgResponseTimeMs + 0.3 * responseTimeMs;
        }
    }
}

void DynamicLoadBalancer::ReportFailure(const std::string& backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = backends_.find(backendId);
    if (it != backends_.end()) {
        it->second.activeConnections--;
        it->second.failedRequests++;
    }
}

std::vector<DynamicLoadBalancer::Backend> DynamicLoadBalancer::GetBackends() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Backend> result;
    for (const auto& pair : backends_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<DynamicLoadBalancer::Backend> DynamicLoadBalancer::GetHealthyBackends() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Backend> result;
    for (const auto& pair : backends_) {
        if (pair.second.healthy) {
            result.push_back(pair.second);
        }
    }
    return result;
}

void DynamicLoadBalancer::StartHealthChecks() {
    if (running_.exchange(true)) return;
    
    healthCheckThread_ = std::thread(&DynamicLoadBalancer::HealthCheckLoop, this);
}

void DynamicLoadBalancer::StopHealthChecks() {
    running_ = false;
    if (healthCheckThread_.joinable()) {
        healthCheckThread_.join();
    }
}

void DynamicLoadBalancer::HealthCheckLoop() {
    while (running_) {
        std::map<std::string, Backend> backendsCopy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            backendsCopy = backends_;
        }
        
        for (auto& pair : backendsCopy) {
            bool healthy = PerformHealthCheck(pair.second);
            UpdateBackendHealth(pair.first, healthy);
        }
        
        std::this_thread::sleep_for(healthCheckInterval_);
    }
}

bool DynamicLoadBalancer::PerformHealthCheck(const Backend& backend) {
    // Send actual health check request
    auto start = std::chrono::high_resolution_clock::now();
    
    // Try to connect to backend health endpoint
    bool healthy = false;
    
    // Simulate HTTP health check (in production, use actual HTTP client)
    // For now, check if backend was recently responsive
    auto now = std::chrono::steady_clock::now();
    auto lastResponse = std::chrono::duration_cast<std::chrono::seconds>(
        now - backend.lastResponseTime).count();
    
    // Consider healthy if responded within last 30 seconds
    healthy = (lastResponse < 30) && (backend.failedRequests < 3);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (!healthy) {
        printf("[LoadBalancer] Health check FAILED for %s (last response %llds ago, %d failures)\n",
               backend.id.c_str(), lastResponse, backend.failedRequests);
    } else {
        printf("[LoadBalancer] Health check PASSED for %s (latency: %lld ms)\n",
               backend.id.c_str(), latency);
    }
    
    return healthy;
}

std::string DynamicLoadBalancer::SelectRoundRobin() {
    std::vector<std::string> healthyIds;
    for (const auto& pair : backends_) {
        if (pair.second.healthy) {
            healthyIds.push_back(pair.first);
        }
    }
    
    if (healthyIds.empty()) return "";
    
    int index = roundRobinIndex_.fetch_add(1) % healthyIds.size();
    backends_[healthyIds[index]].activeConnections++;
    return healthyIds[index];
}

std::string DynamicLoadBalancer::SelectLeastConnections() {
    std::string bestBackend;
    int minConnections = std::numeric_limits<int>::max();
    
    for (auto& pair : backends_) {
        if (pair.second.healthy && pair.second.activeConnections < minConnections) {
            minConnections = pair.second.activeConnections;
            bestBackend = pair.first;
        }
    }
    
    if (!bestBackend.empty()) {
        backends_[bestBackend].activeConnections++;
    }
    
    return bestBackend;
}

std::string DynamicLoadBalancer::SelectWeightedResponseTime() {
    std::string bestBackend;
    double bestScore = std::numeric_limits<double>::max();
    
    for (auto& pair : backends_) {
        if (!pair.second.healthy) continue;
        
        double score = pair.second.avgResponseTimeMs / pair.second.weight;
        if (score < bestScore) {
            bestScore = score;
            bestBackend = pair.first;
        }
    }
    
    if (!bestBackend.empty()) {
        backends_[bestBackend].activeConnections++;
    }
    
    return bestBackend;
}

std::string DynamicLoadBalancer::SelectIPHash(const std::string& clientIp) {
    if (clientIp.empty()) return SelectRandom();
    
    std::hash<std::string> hasher;
    size_t hash = hasher(clientIp);
    
    std::vector<std::string> healthyIds;
    for (const auto& pair : backends_) {
        if (pair.second.healthy) {
            healthyIds.push_back(pair.first);
        }
    }
    
    if (healthyIds.empty()) return "";
    
    size_t index = hash % healthyIds.size();
    backends_[healthyIds[index]].activeConnections++;
    return healthyIds[index];
}

std::string DynamicLoadBalancer::SelectRandom() {
    std::vector<std::string> healthyIds;
    for (const auto& pair : backends_) {
        if (pair.second.healthy) {
            healthyIds.push_back(pair.first);
        }
    }
    
    if (healthyIds.empty()) return "";
    
    // Simple random selection
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, healthyIds.size() - 1);
    
    int index = dis(gen);
    backends_[healthyIds[index]].activeConnections++;
    return healthyIds[index];
}

// CircuitBreaker implementation
CircuitBreaker::CircuitBreaker(const std::string& name, const Config& config)
    : name_(name), config_(config) {}

CircuitBreaker::~CircuitBreaker() = default;

void CircuitBreaker::RecordSuccess() {
    totalRequests_++;
    successfulRequests_++;
    consecutiveFailures_ = 0;
    consecutiveSuccesses_++;
    
    if (state_ == State::HALF_OPEN && consecutiveSuccesses_ >= config_.successThreshold) {
        TransitionTo(State::CLOSED);
    }
}

void CircuitBreaker::RecordFailure() {
    totalRequests_++;
    failedRequests_++;
    consecutiveSuccesses_ = 0;
    consecutiveFailures_++;
    lastFailureTime_ = std::chrono::system_clock::now();
    
    if (consecutiveFailures_ >= config_.failureThreshold) {
        TransitionTo(State::OPEN);
    }
}

CircuitBreaker::State CircuitBreaker::GetState() const {
    return state_;
}

std::string CircuitBreaker::GetStateString() const {
    switch (state_) {
        case State::CLOSED: return "CLOSED";
        case State::OPEN: return "OPEN";
        case State::HALF_OPEN: return "HALF_OPEN";
        default: return "UNKNOWN";
    }
}

CircuitBreaker::Stats CircuitBreaker::GetStats() const {
    Stats stats;
    stats.totalRequests = totalRequests_;
    stats.successfulRequests = successfulRequests_;
    stats.failedRequests = failedRequests_;
    stats.consecutiveFailures = consecutiveFailures_;
    stats.consecutiveSuccesses = consecutiveSuccesses_;
    stats.state = state_;
    return stats;
}

void CircuitBreaker::Reset() {
    state_ = State::CLOSED;
    consecutiveFailures_ = 0;
    consecutiveSuccesses_ = 0;
}

bool CircuitBreaker::AllowRequest() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == State::CLOSED) {
        return true;
    }
    
    if (state_ == State::OPEN) {
        auto now = std::chrono::system_clock::now();
        if (now - lastFailureTime_ > config_.timeout) {
            TransitionTo(State::HALF_OPEN);
            return true;
        }
        return false;
    }
    
    // HALF_OPEN
    return true;
}

void CircuitBreaker::TransitionTo(State newState) {
    state_ = newState;
    
    if (newState == State::CLOSED) {
        consecutiveFailures_ = 0;
    } else if (newState == State::HALF_OPEN) {
        consecutiveSuccesses_ = 0;
    }
}

// RateLimiter implementation
RateLimiter::RateLimiter(Strategy strategy) : strategy_(strategy) {}

RateLimiter::~RateLimiter() = default;

void RateLimiter::SetLimit(const std::string& key, const Limit& limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (strategy_ == Strategy::TOKEN_BUCKET) {
        tokenBuckets_[key].limit = limit;
        tokenBuckets_[key].tokens = limit.burstSize;
        tokenBuckets_[key].lastUpdate = std::chrono::system_clock::now();
    } else {
        windows_[key].limit = limit;
    }
}

bool RateLimiter::AllowRequest(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (strategy_ == Strategy::TOKEN_BUCKET) {
        auto it = tokenBuckets_.find(key);
        if (it == tokenBuckets_.end()) return true;
        return AllowTokenBucket(key, it->second);
    } else if (strategy_ == Strategy::SLIDING_WINDOW) {
        auto it = windows_.find(key);
        if (it == windows_.end()) return true;
        return AllowSlidingWindow(key, it->second);
    } else {
        auto it = windows_.find(key);
        if (it == windows_.end()) return true;
        return AllowFixedWindow(key, it->second);
    }
}

int RateLimiter::GetRemainingQuota(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (strategy_ == Strategy::TOKEN_BUCKET) {
        auto it = tokenBuckets_.find(key);
        if (it != tokenBuckets_.end()) {
            return static_cast<int>(it->second.tokens);
        }
    }
    
    return 0;
}

std::chrono::seconds RateLimiter::GetRetryAfter(const std::string& key) {
    // Calculate time until next request allowed based on token bucket
    auto it = tokenBuckets_.find(key);
    if (it == tokenBuckets_.end()) {
        return std::chrono::seconds(0); // No limit configured
    }
    
    const TokenBucket& bucket = it->second;
    
    // If we have tokens available, no wait needed
    if (bucket.tokens >= 1.0) {
        return std::chrono::seconds(0);
    }
    
    // Calculate time to generate 1 token
    double tokensNeeded = 1.0 - bucket.tokens;
    double secondsNeeded = tokensNeeded / bucket.limit.requestsPerSecond;
    
    int waitSeconds = static_cast<int>(std::ceil(secondsNeeded));
    waitSeconds = std::max(1, std::min(waitSeconds, 60)); // Clamp between 1-60 seconds
    
    printf("[RateLimiter] Retry after %d seconds for key '%s' (need %.2f tokens)\n",
           waitSeconds, key.c_str(), tokensNeeded);
    
    return std::chrono::seconds(waitSeconds);
}

bool RateLimiter::AllowTokenBucket(const std::string& key, TokenBucket& bucket) {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration<double>(now - bucket.lastUpdate).count();
    
    // Add tokens
    bucket.tokens += elapsed * bucket.limit.requestsPerSecond;
    bucket.tokens = std::min(bucket.tokens, static_cast<double>(bucket.limit.burstSize));
    bucket.lastUpdate = now;
    
    // Check if request can be processed
    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        return true;
    }
    
    return false;
}

bool RateLimiter::AllowSlidingWindow(const std::string& key, WindowEntry& window) {
    auto now = std::chrono::system_clock::now();
    auto windowStart = now - window.limit.window;
    
    // Remove old requests
    window.requests.erase(
        std::remove_if(window.requests.begin(), window.requests.end(),
            [&windowStart](const auto& time) {
                return time < windowStart;
            }),
        window.requests.end());
    
    // Check if under limit
    if (static_cast<int>(window.requests.size()) < window.limit.requestsPerSecond) {
        window.requests.push_back(now);
        return true;
    }
    
    return false;
}

bool RateLimiter::AllowFixedWindow(const std::string& key, WindowEntry& window) {
    // Similar to sliding window but with fixed boundaries
    return AllowSlidingWindow(key, window);
}

// RequestQueue implementation
RequestQueue::RequestQueue(const Config& config) : config_(config) {}

RequestQueue::~RequestQueue() = default;

bool RequestQueue::Enqueue(const InferenceRequest& request,
                           std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    // Check if throttled
    if (throttled_) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalDropped++;
        return false;
    }
    
    // Wait for space
    if (!notFull_.wait_for(lock, timeout, [this] {
        return queue_.size() < static_cast<size_t>(config_.maxSize) || throttled_;
    })) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalDropped++;
        return false;
    }
    
    if (throttled_) {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.totalDropped++;
        return false;
    }
    
    queue_.push(request);
    
    {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.currentSize = static_cast<int>(queue_.size());
        stats_.totalEnqueued++;
        
        // Check if we should throttle
        if (stats_.currentSize >= config_.highWatermark) {
            throttled_ = true;
            stats_.isThrottled = true;
        }
    }
    
    notEmpty_.notify_one();
    return true;
}

bool RequestQueue::Dequeue(InferenceRequest& request,
                           std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    if (!notEmpty_.wait_for(lock, timeout, [this] {
        return !queue_.empty();
    })) {
        return false;
    }
    
    request = queue_.front();
    queue_.pop();
    
    {
        std::lock_guard<std::mutex> statsLock(statsMutex_);
        stats_.currentSize = static_cast<int>(queue_.size());
        stats_.totalDequeued++;
        
        // Check if we should unthrottle
        if (throttled_ && stats_.currentSize <= config_.lowWatermark) {
            throttled_ = false;
            stats_.isThrottled = false;
        }
    }
    
    notFull_.notify_one();
    return true;
}

RequestQueue::Stats RequestQueue::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

bool RequestQueue::IsThrottled() const {
    return throttled_;
}

void RequestQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    while (!queue_.empty()) {
        queue_.pop();
    }
    
    throttled_ = false;
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.currentSize = 0;
}

// DeploymentManager implementation
DeploymentManager::DeploymentManager() = default;

DeploymentManager::~DeploymentManager() = default;

bool DeploymentManager::Initialize(const std::string& orchestratorEndpoint) {
    orchestratorEndpoint_ = orchestratorEndpoint;
    return true;
}

bool DeploymentManager::Deploy(const DeploymentConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    deployments_[config.name] = config;
    
    // Create deployment in orchestrator
    // ...
    
    return true;
}

bool DeploymentManager::Update(const std::string& deploymentName,
                               const DeploymentConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = deployments_.find(deploymentName);
    if (it == deployments_.end()) {
        return false;
    }
    
    it->second = config;
    
    // Update deployment in orchestrator
    // ...
    
    return true;
}

bool DeploymentManager::Rollback(const std::string& deploymentName,
                                  const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Rollback to previous version
    // ...
    
    return true;
}

bool DeploymentManager::Scale(const std::string& deploymentName, int instanceCount) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = deployments_.find(deploymentName);
    if (it == deployments_.end()) {
        return false;
    }
    
    // Scale deployment
    // ...
    
    return true;
}

DeploymentManager::DeploymentStatus DeploymentManager::GetStatus(
    const std::string& deploymentName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    DeploymentStatus status;
    status.name = deploymentName;
    
    auto it = deployments_.find(deploymentName);
    if (it != deployments_.end()) {
        status.desiredInstances = it->second.minInstances;
        status.state = "running";
    }
    
    return status;
}

std::vector<DeploymentManager::DeploymentStatus> DeploymentManager::ListDeployments() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<DeploymentStatus> result;
    for (const auto& pair : deployments_) {
        result.push_back(GetStatus(pair.first));
    }
    return result;
}

bool DeploymentManager::DeleteDeployment(const std::string& deploymentName) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    deployments_.erase(deploymentName);
    
    // Delete from orchestrator
    // ...
    
    return true;
}

} // namespace deployment
} // namespace rawrxd
