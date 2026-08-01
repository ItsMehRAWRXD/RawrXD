// ============================================================================
// BackendHealthMonitor.hpp — Backend Health, Latency Tracking & Auto-Failover
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>
#include <thread>

namespace RawrXD {
namespace Security {

using json = nlohmann::json;

// ============================================================================
// Backend Types
// ============================================================================
enum class BackendType {
    LocalGGUF,
    Ollama,
    OpenAI,
    Anthropic,
    Azure,
    Custom
};

// ============================================================================
// Backend Status
// ============================================================================
enum class BackendStatus {
    Unknown,
    Online,
    Degraded,
    Offline,
    Error
};

// ============================================================================
// Backend Configuration
// ============================================================================
struct BackendConfig {
    std::string name;
    BackendType type = BackendType::LocalGGUF;
    std::string endpoint;
    std::string apiKey;
    int priority = 0;           // Lower = higher priority
    int maxRetries = 3;
    int timeoutMs = 30000;
    int healthCheckIntervalSec = 30;
    float degradationThresholdMs = 5000.0f;  // Latency above this = degraded
    float offlineThresholdMs = 30000.0f;       // Latency above this = offline
    bool enabled = true;
};

// ============================================================================
// Health Check Result
// ============================================================================
struct HealthResult {
    BackendStatus status = BackendStatus::Unknown;
    double latencyMs = 0.0;
    std::string error;
    std::chrono::system_clock::time_point checkedAt;
    bool modelLoaded = false;
    std::string modelName;
    int availableModels = 0;
};

// ============================================================================
// Latency Record
// ============================================================================
struct LatencyRecord {
    double latencyMs = 0.0;
    std::string operation;
    std::chrono::system_clock::time_point timestamp;
    bool success = false;
};

// ============================================================================
// Routing Decision
// ============================================================================
struct RoutingDecision {
    std::string backendName;
    BackendType backendType;
    double estimatedLatencyMs;
    float confidence;
    std::string reason;
};

// ============================================================================
// Backend Health Monitor
// ============================================================================
class BackendHealthMonitor {
public:
    BackendHealthMonitor();
    ~BackendHealthMonitor();

    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Backend Registration
    void RegisterBackend(const BackendConfig& config);
    void UnregisterBackend(const std::string& name);
    std::vector<BackendConfig> GetRegisteredBackends() const;
    BackendConfig GetBackend(const std::string& name) const;

    // Health Checks
    HealthResult CheckHealth(const std::string& backendName);
    HealthResult GetLastHealth(const std::string& backendName) const;
    BackendStatus GetStatus(const std::string& backendName) const;
    std::vector<std::string> GetOnlineBackends() const;
    std::vector<std::string> GetAvailableBackends() const;

    // Latency Tracking
    void RecordLatency(const std::string& backendName, double latencyMs, 
                       const std::string& operation, bool success);
    double GetAverageLatency(const std::string& backendName) const;
    double GetP95Latency(const std::string& backendName) const;
    json GetLatencyStats(const std::string& backendName) const;

    // Auto-Failover Routing
    RoutingDecision RouteRequest(const std::string& taskType, 
                                 int estimatedTokens = 0,
                                 const std::vector<std::string>& preferredBackends = {});
    RoutingDecision Failover(const std::string& failedBackend, 
                             const std::string& taskType);

    // Quality Scoring
    float GetQualityScore(const std::string& backendName) const;
    void RecordQuality(const std::string& backendName, float score);

    // Event Callbacks
    using StatusChangeCallback = std::function<void(const std::string& backend, 
                                                     BackendStatus oldStatus, 
                                                     BackendStatus newStatus)>;
    using FailoverCallback = std::function<void(const std::string& from, 
                                                const std::string& to)>;

    void SetStatusChangeCallback(StatusChangeCallback cb) { m_statusCb = cb; }
    void SetFailoverCallback(FailoverCallback cb) { m_failoverCb = cb; }

    // Statistics
    json GetStats() const;
    int GetTotalRequests() const { return m_totalRequests.load(); }
    int GetFailedRequests() const { return m_failedRequests.load(); }
    int GetFailovers() const { return m_failoverCount.load(); }

private:
    void HealthCheckLoop();
    HealthResult CheckLocalGGUF(const BackendConfig& config);
    HealthResult CheckOllama(const BackendConfig& config);
    HealthResult CheckOpenAI(const BackendConfig& config);
    void UpdateStatus(const std::string& name, BackendStatus newStatus);
    float CalculateScore(const BackendConfig& config, const std::string& taskType) const;

private:
    struct BackendState {
        BackendConfig config;
        BackendStatus status = BackendStatus::Unknown;
        HealthResult lastHealth;
        std::vector<LatencyRecord> latencies;
        std::vector<float> qualityScores;
        int consecutiveFailures = 0;
        std::chrono::system_clock::time_point lastUsed;
    };

    std::map<std::string, std::unique_ptr<BackendState>> m_backends;
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::thread m_healthThread;

    // Statistics
    std::atomic<int> m_totalRequests{0};
    std::atomic<int> m_failedRequests{0};
    std::atomic<int> m_failoverCount{0};

    // Callbacks
    StatusChangeCallback m_statusCb;
    FailoverCallback m_failoverCb;
};

} // namespace Security
} // namespace RawrXD
