#pragma once

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <queue>

namespace rawrxd {
namespace deployment {

// Scaling configuration
struct AutoScalingConfig {
    // Scale out triggers
    double cpuThresholdPercent = 70.0;
    double memoryThresholdPercent = 80.0;
    double gpuUtilizationThreshold = 80.0;
    double latencyP95ThresholdMs = 1000.0;
    int requestQueueDepthThreshold = 50;
    
    // Scale in triggers
    double cpuScaleInThresholdPercent = 30.0;
    double memoryScaleInThresholdPercent = 40.0;
    int minInstances = 1;
    int maxInstances = 10;
    
    // Timing
    std::chrono::seconds scaleOutCooldown{60};
    std::chrono::seconds scaleInCooldown{300};
    std::chrono::seconds evaluationInterval{30};
    
    // Scaling strategy
    enum class Strategy {
        STEP,           // Add/remove fixed number
        TARGET_TRACKING, // Maintain target metric
        PREDICTIVE      // Predictive scaling
    };
    Strategy strategy = Strategy::STEP;
    int stepSize = 1;
    double targetMetricValue = 70.0;
};

// Instance info
struct InstanceInfo {
    std::string instanceId;
    std::string address;
    int port = 0;
    bool healthy = true;
    std::chrono::system_clock::time_point startTime;
    
    // Metrics
    double cpuPercent = 0.0;
    double memoryPercent = 0.0;
    double gpuUtilization = 0.0;
    double latencyP95Ms = 0.0;
    int activeRequests = 0;
    int requestQueueDepth = 0;
};

// Auto-scaling manager
class AutoScalingManager {
public:
    AutoScalingManager();
    ~AutoScalingManager();

    // Initialize
    bool Initialize(const AutoScalingConfig& config,
                    std::function<std::string()> spawnInstance,
                    std::function<void(const std::string&)> terminateInstance);
    
    // Start auto-scaling
    bool Start();
    
    // Stop auto-scaling
    void Stop();
    
    // Update instance metrics
    void UpdateInstanceMetrics(const std::string& instanceId,
                               const InstanceInfo& metrics);
    
    // Get current instances
    std::vector<InstanceInfo> GetInstances() const;
    
    // Get desired capacity
    int GetDesiredCapacity() const { return desiredCapacity_; }
    
    // Manual scaling
    void SetDesiredCapacity(int capacity);
    void ScaleOut(int count = 1);
    void ScaleIn(int count = 1);
    
    // Get scaling history
    struct ScalingEvent {
        std::chrono::system_clock::time_point timestamp;
        std::string action; // "scale_out" or "scale_in"
        int previousCapacity;
        int newCapacity;
        std::string reason;
    };
    std::vector<ScalingEvent> GetScalingHistory() const;
    
    // Get statistics
    struct Stats {
        int currentInstances = 0;
        int minInstances = 0;
        int maxInstances = 0;
        int totalScaleOutEvents = 0;
        int totalScaleInEvents = 0;
        double avgCpuUtilization = 0.0;
        double avgLatencyP95 = 0.0;
    };
    Stats GetStats() const;

private:
    AutoScalingConfig config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, InstanceInfo> instances_;
    mutable std::mutex instancesMutex_;
    
    int desiredCapacity_ = 0;
    int currentCapacity_ = 0;
    
    std::chrono::system_clock::time_point lastScaleOutTime_;
    std::chrono::system_clock::time_point lastScaleInTime_;
    
    std::vector<ScalingEvent> scalingHistory_;
    mutable std::mutex historyMutex_;
    
    std::thread evaluationThread_;
    
    std::function<std::string()> spawnInstance_;
    std::function<void(const std::string&)> terminateInstance_;
    
    void EvaluationLoop();
    bool ShouldScaleOut();
    bool ShouldScaleIn();
    int CalculateDesiredCapacity();
    void ExecuteScaling(int newCapacity, const std::string& reason);
};

// Load balancer with health checks
class DynamicLoadBalancer {
public:
    enum class Strategy {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        WEIGHTED_RESPONSE_TIME,
        IP_HASH,
        RANDOM
    };
    
    struct Backend {
        std::string id;
        std::string address;
        int port = 0;
        int weight = 1;
        bool healthy = true;
        int activeConnections = 0;
        double avgResponseTimeMs = 0.0;
        int totalRequests = 0;
        int failedRequests = 0;
        std::chrono::system_clock::time_point lastHealthCheck;
    };
    
    DynamicLoadBalancer();
    ~DynamicLoadBalancer();
    
    // Initialize
    bool Initialize(Strategy strategy = Strategy::LEAST_CONNECTIONS,
                    std::chrono::seconds healthCheckInterval = std::chrono::seconds(10));
    
    // Add/remove backends
    void AddBackend(const Backend& backend);
    void RemoveBackend(const std::string& backendId);
    void UpdateBackendHealth(const std::string& backendId, bool healthy);
    
    // Select backend
    std::string SelectBackend(const std::string& clientIp = "");
    
    // Report result
    void ReportSuccess(const std::string& backendId, double responseTimeMs);
    void ReportFailure(const std::string& backendId);
    
    // Get backends
    std::vector<Backend> GetBackends() const;
    std::vector<Backend> GetHealthyBackends() const;
    
    // Start/stop health checks
    void StartHealthChecks();
    void StopHealthChecks();

private:
    Strategy strategy_;
    std::map<std::string, Backend> backends_;
    mutable std::mutex mutex_;
    std::atomic<int> roundRobinIndex_{0};
    
    std::thread healthCheckThread_;
    std::atomic<bool> running_{false};
    std::chrono::seconds healthCheckInterval_;
    
    void HealthCheckLoop();
    bool PerformHealthCheck(const Backend& backend);
    std::string SelectRoundRobin();
    std::string SelectLeastConnections();
    std::string SelectWeightedResponseTime();
    std::string SelectIPHash(const std::string& clientIp);
    std::string SelectRandom();
};

// Circuit breaker
class CircuitBreaker {
public:
    enum class State {
        CLOSED,      // Normal operation
        OPEN,        // Failing, reject requests
        HALF_OPEN    // Testing if service recovered
    };
    
    struct Config {
        int failureThreshold = 5;
        std::chrono::seconds timeout{30};
        int successThreshold = 3;
    };
    
    CircuitBreaker(const std::string& name, const Config& config);
    ~CircuitBreaker();
    
    // Execute with circuit breaker
    template<typename Func>
    auto Execute(Func&& func) -> decltype(func()) {
        if (!AllowRequest()) {
            throw std::runtime_error("Circuit breaker is open");
        }
        
        try {
            auto result = func();
            RecordSuccess();
            return result;
        } catch (...) {
            RecordFailure();
            throw;
        }
    }
    
    // Manual record
    void RecordSuccess();
    void RecordFailure();
    
    // Get state
    State GetState() const;
    std::string GetStateString() const;
    
    // Get stats
    struct Stats {
        int totalRequests = 0;
        int successfulRequests = 0;
        int failedRequests = 0;
        int consecutiveFailures = 0;
        int consecutiveSuccesses = 0;
        State state = State::CLOSED;
    };
    Stats GetStats() const;
    
    // Reset
    void Reset();

private:
    std::string name_;
    Config config_;
    std::atomic<State> state_{State::CLOSED};
    
    std::atomic<int> consecutiveFailures_{0};
    std::atomic<int> consecutiveSuccesses_{0};
    std::atomic<int> totalRequests_{0};
    std::atomic<int> successfulRequests_{0};
    std::atomic<int> failedRequests_{0};
    
    std::chrono::system_clock::time_point lastFailureTime_;
    mutable std::mutex mutex_;
    
    bool AllowRequest();
    void TransitionTo(State newState);
};

// Rate limiter
class RateLimiter {
public:
    enum class Strategy {
        TOKEN_BUCKET,
        SLIDING_WINDOW,
        FIXED_WINDOW
    };
    
    struct Limit {
        int requestsPerSecond = 10;
        int burstSize = 20;
        std::chrono::seconds window{60};
    };
    
    RateLimiter(Strategy strategy = Strategy::TOKEN_BUCKET);
    ~RateLimiter();
    
    // Configure limit for key
    void SetLimit(const std::string& key, const Limit& limit);
    
    // Check if request allowed
    bool AllowRequest(const std::string& key);
    
    // Get remaining quota
    int GetRemainingQuota(const std::string& key);
    
    // Get retry after
    std::chrono::seconds GetRetryAfter(const std::string& key);

private:
    Strategy strategy_;
    
    struct TokenBucket {
        double tokens = 0;
        std::chrono::system_clock::time_point lastUpdate;
        Limit limit;
    };
    
    struct WindowEntry {
        std::vector<std::chrono::system_clock::time_point> requests;
        Limit limit;
    };
    
    std::map<std::string, TokenBucket> tokenBuckets_;
    std::map<std::string, WindowEntry> windows_;
    mutable std::mutex mutex_;
    
    bool AllowTokenBucket(const std::string& key, TokenBucket& bucket);
    bool AllowSlidingWindow(const std::string& key, WindowEntry& window);
    bool AllowFixedWindow(const std::string& key, WindowEntry& window);
};

// Request queue with backpressure
class RequestQueue {
public:
    struct Config {
        int maxSize = 1000;
        int highWatermark = 800;
        int lowWatermark = 200;
        std::chrono::seconds maxWaitTime{30};
    };
    
    RequestQueue(const Config& config);
    ~RequestQueue();
    
    // Enqueue request
    bool Enqueue(const InferenceRequest& request,
                 std::chrono::milliseconds timeout);
    
    // Dequeue request
    bool Dequeue(InferenceRequest& request,
                  std::chrono::milliseconds timeout);
    
    // Get queue stats
    struct Stats {
        int currentSize = 0;
        int maxSize = 0;
        int totalEnqueued = 0;
        int totalDequeued = 0;
        int totalDropped = 0;
        double avgWaitTimeMs = 0.0;
        bool isThrottled = false;
    };
    Stats GetStats() const;
    
    // Check if throttled
    bool IsThrottled() const;
    
    // Clear queue
    void Clear();

private:
    Config config_;
    
    std::queue<InferenceRequest> queue_;
    mutable std::mutex mutex_;
    std::condition_variable notFull_;
    std::condition_variable notEmpty_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    std::atomic<bool> throttled_{false};
};

// Deployment manager
class DeploymentManager {
public:
    struct DeploymentConfig {
        std::string name;
        std::string version;
        std::string modelPath;
        int minInstances = 1;
        int maxInstances = 10;
        AutoScalingConfig scalingConfig;
    };
    
    DeploymentManager();
    ~DeploymentManager();
    
    // Initialize
    bool Initialize(const std::string& orchestratorEndpoint);
    
    // Deploy new version
    bool Deploy(const DeploymentConfig& config);
    
    // Update deployment
    bool Update(const std::string& deploymentName, const DeploymentConfig& config);
    
    // Rollback deployment
    bool Rollback(const std::string& deploymentName, const std::string& version);
    
    // Scale deployment
    bool Scale(const std::string& deploymentName, int instanceCount);
    
    // Get deployment status
    struct DeploymentStatus {
        std::string name;
        std::string currentVersion;
        int desiredInstances = 0;
        int runningInstances = 0;
        int healthyInstances = 0;
        std::string state; // "deploying", "running", "scaling", "error"
    };
    DeploymentStatus GetStatus(const std::string& deploymentName);
    
    // List deployments
    std::vector<DeploymentStatus> ListDeployments();
    
    // Delete deployment
    bool DeleteDeployment(const std::string& deploymentName);

private:
    std::string orchestratorEndpoint_;
    std::map<std::string, DeploymentConfig> deployments_;
    mutable std::mutex mutex_;
    
    // std::unique_ptr<KubernetesClient> k8sClient_;
    // std::unique_ptr<DockerClient> dockerClient_;
};

} // namespace deployment
} // namespace rawrxd
