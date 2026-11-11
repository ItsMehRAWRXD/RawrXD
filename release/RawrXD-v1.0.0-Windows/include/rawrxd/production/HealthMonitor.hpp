#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <functional>

namespace rawrxd {
namespace production {

// Health check status
enum class HealthStatus {
    HEALTHY,        // All systems operational
    DEGRADED,       // Reduced performance but functional
    UNHEALTHY,      // Critical issues, may fail
    UNKNOWN         // Status not determined
};

// Component health information
struct ComponentHealth {
    std::string name;
    HealthStatus status = HealthStatus::UNKNOWN;
    std::string message;
    float latencyMs = 0.0f;
    float throughput = 0.0f;
    float errorRate = 0.0f;
    size_t memoryUsageMB = 0;
    std::chrono::system_clock::time_point lastCheck;
    std::unordered_map<std::string, std::string> metrics;
};

// System health summary
struct SystemHealth {
    HealthStatus overallStatus = HealthStatus::UNKNOWN;
    std::string statusMessage;
    std::vector<ComponentHealth> components;
    std::chrono::system_clock::time_point timestamp;
    float uptimeSeconds = 0.0f;
    size_t totalMemoryMB = 0;
    size_t availableMemoryMB = 0;
    float cpuUsagePercent = 0.0f;

    // Get components by status
    std::vector<ComponentHealth> GetUnhealthyComponents() const;
    std::vector<ComponentHealth> GetDegradedComponents() const;
    bool IsHealthy() const { return overallStatus == HealthStatus::HEALTHY; }
};

// Health check interface
class HealthCheck {
public:
    virtual ~HealthCheck() = default;
    virtual ComponentHealth Check() = 0;
    virtual std::string GetName() const = 0;
    virtual std::chrono::milliseconds GetInterval() const = 0;
};

// Health monitor
class HealthMonitor {
public:
    HealthMonitor();
    ~HealthMonitor();

    // Register health checks
    void RegisterCheck(std::shared_ptr<HealthCheck> check);
    void RegisterCheck(const std::string& name,
                       std::function<ComponentHealth()> checkFunc,
                       std::chrono::milliseconds interval);

    // Start/stop monitoring
    void Start();
    void Stop();
    bool IsRunning() const { return running_; }

    // Get current health
    SystemHealth GetHealth() const;
    ComponentHealth GetComponentHealth(const std::string& name) const;

    // Set alert callback
    using AlertCallback = std::function<void(const ComponentHealth&)>;
    void SetAlertCallback(AlertCallback callback) { alertCallback_ = callback; }

    // Set thresholds
    void SetLatencyThreshold(const std::string& component, float thresholdMs);
    void SetErrorRateThreshold(const std::string& component, float threshold);
    void SetMemoryThreshold(size_t thresholdMB);

    // Export health report
    std::string ExportToJSON() const;
    std::string ExportToMarkdown() const;

    // Global instance
    static HealthMonitor& GetInstance();

private:
    std::vector<std::shared_ptr<HealthCheck>> checks_;
    std::unordered_map<std::string, ComponentHealth> healthData_;
    std::unordered_map<std::string, float> latencyThresholds_;
    std::unordered_map<std::string, float> errorRateThresholds_;
    size_t memoryThresholdMB_ = 8192;  // 8GB default
    AlertCallback alertCallback_;
    bool running_ = false;
    std::chrono::system_clock::time_point startTime_;

    void MonitorLoop();
    void EvaluateThresholds(const ComponentHealth& health);
    HealthStatus AggregateStatus(const std::vector<ComponentHealth>& components) const;
};

// Built-in health checks
class MemoryHealthCheck : public HealthCheck {
public:
    ComponentHealth Check() override;
    std::string GetName() const override { return "memory"; }
    std::chrono::milliseconds GetInterval() const override {
        return std::chrono::milliseconds(5000);
    }
};

class InferenceHealthCheck : public HealthCheck {
public:
    ComponentHealth Check() override;
    std::string GetName() const override { return "inference"; }
    std::chrono::milliseconds GetInterval() const override {
        return std::chrono::milliseconds(1000);
    }
};

class ModelHealthCheck : public HealthCheck {
public:
    ComponentHealth Check() override;
    std::string GetName() const override { return "model"; }
    std::chrono::milliseconds GetInterval() const override {
        return std::chrono::milliseconds(30000);
    }
};

} // namespace production
} // namespace rawrxd
