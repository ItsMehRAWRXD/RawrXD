#include "rawrxd/production/HealthMonitor.hpp"
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>

namespace rawrxd {
namespace production {

// Global instance
HealthMonitor& HealthMonitor::GetInstance() {
    static HealthMonitor instance;
    return instance;
}

HealthMonitor::HealthMonitor() = default;

HealthMonitor::~HealthMonitor() {
    Stop();
}

void HealthMonitor::RegisterCheck(std::shared_ptr<HealthCheck> check) {
    checks_.push_back(check);
}

void HealthMonitor::RegisterCheck(const std::string& name,
                                  std::function<ComponentHealth()> checkFunc,
                                  std::chrono::milliseconds interval) {
    // Create a wrapper health check
    class LambdaHealthCheck : public HealthCheck {
    public:
        LambdaHealthCheck(const std::string& n,
                         std::function<ComponentHealth()> f,
                         std::chrono::milliseconds i)
            : name_(n), func_(f), interval_(i) {}

        ComponentHealth Check() override { return func_(); }
        std::string GetName() const override { return name_; }
        std::chrono::milliseconds GetInterval() const override { return interval_; }

    private:
        std::string name_;
        std::function<ComponentHealth()> func_;
        std::chrono::milliseconds interval_;
    };

    checks_.push_back(std::make_shared<LambdaHealthCheck>(name, checkFunc, interval));
}

void HealthMonitor::Start() {
    if (running_) return;
    running_ = true;
    startTime_ = std::chrono::system_clock::now();

    // Start monitoring thread
    std::thread monitorThread(&HealthMonitor::MonitorLoop, this);
    monitorThread.detach();
}

void HealthMonitor::Stop() {
    running_ = false;
}

SystemHealth HealthMonitor::GetHealth() const {
    SystemHealth health;
    health.timestamp = std::chrono::system_clock::now();

    // Calculate uptime
    auto uptime = health.timestamp - startTime_;
    health.uptimeSeconds = std::chrono::duration<float>(uptime).count();

    // Collect component health
    for (const auto& check : checks_) {
        auto it = healthData_.find(check->GetName());
        if (it != healthData_.end()) {
            health.components.push_back(it->second);
        }
    }

    // Aggregate status
    health.overallStatus = AggregateStatus(health.components);

    // Set status message
    switch (health.overallStatus) {
        case HealthStatus::HEALTHY:
            health.statusMessage = "All systems operational";
            break;
        case HealthStatus::DEGRADED:
            health.statusMessage = "Some components degraded";
            break;
        case HealthStatus::UNHEALTHY:
            health.statusMessage = "Critical issues detected";
            break;
        default:
            health.statusMessage = "Status unknown";
            break;
    }

    return health;
}

ComponentHealth HealthMonitor::GetComponentHealth(const std::string& name) const {
    auto it = healthData_.find(name);
    if (it != healthData_.end()) {
        return it->second;
    }
    return ComponentHealth();
}

void HealthMonitor::SetLatencyThreshold(const std::string& component, float thresholdMs) {
    latencyThresholds_[component] = thresholdMs;
}

void HealthMonitor::SetErrorRateThreshold(const std::string& component, float threshold) {
    errorRateThresholds_[component] = threshold;
}

void HealthMonitor::SetMemoryThreshold(size_t thresholdMB) {
    memoryThresholdMB_ = thresholdMB;
}

std::string HealthMonitor::ExportToJSON() const {
    auto health = GetHealth();
    std::stringstream json;

    json << "{\n";
    json << "  \"overall_status\": \"";
    switch (health.overallStatus) {
        case HealthStatus::HEALTHY: json << "healthy"; break;
        case HealthStatus::DEGRADED: json << "degraded"; break;
        case HealthStatus::UNHEALTHY: json << "unhealthy"; break;
        default: json << "unknown"; break;
    }
    json << "\",\n";
    json << "  \"message\": \"" << health.statusMessage << "\",\n";
    json << "  \"uptime_seconds\": " << health.uptimeSeconds << ",\n";
    json << "  \"components\": [\n";

    for (size_t i = 0; i < health.components.size(); ++i) {
        const auto& comp = health.components[i];
        json << "    {\n";
        json << "      \"name\": \"" << comp.name << "\",\n";
        json << "      \"status\": \"";
        switch (comp.status) {
            case HealthStatus::HEALTHY: json << "healthy"; break;
            case HealthStatus::DEGRADED: json << "degraded"; break;
            case HealthStatus::UNHEALTHY: json << "unhealthy"; break;
            default: json << "unknown"; break;
        }
        json << "\",\n";
        json << "      \"latency_ms\": " << comp.latencyMs << ",\n";
        json << "      \"error_rate\": " << comp.errorRate << ",\n";
        json << "      \"memory_mb\": " << comp.memoryUsageMB << "\n";
        json << "    }";
        if (i < health.components.size() - 1) json << ",";
        json << "\n";
    }

    json << "  ]\n";
    json << "}";

    return json.str();
}

std::string HealthMonitor::ExportToMarkdown() const {
    auto health = GetHealth();
    std::stringstream md;

    md << "# System Health Report\n\n";
    md << "**Overall Status:** ";
    switch (health.overallStatus) {
        case HealthStatus::HEALTHY: md << "✅ HEALTHY"; break;
        case HealthStatus::DEGRADED: md << "⚠️ DEGRADED"; break;
        case HealthStatus::UNHEALTHY: md << "❌ UNHEALTHY"; break;
        default: md << "❓ UNKNOWN"; break;
    }
    md << "\n\n";
    md << "**Message:** " << health.statusMessage << "\n\n";
    md << "**Uptime:** " << health.uptimeSeconds << " seconds\n\n";

    md << "## Components\n\n";
    md << "| Component | Status | Latency (ms) | Error Rate | Memory (MB) |\n";
    md << "|-----------|--------|--------------|------------|-------------|\n";

    for (const auto& comp : health.components) {
        md << "| " << comp.name << " | ";
        switch (comp.status) {
            case HealthStatus::HEALTHY: md << "✅"; break;
            case HealthStatus::DEGRADED: md << "⚠️"; break;
            case HealthStatus::UNHEALTHY: md << "❌"; break;
            default: md << "❓"; break;
        }
        md << " | " << std::fixed << std::setprecision(2) << comp.latencyMs;
        md << " | " << comp.errorRate;
        md << " | " << comp.memoryUsageMB << " |\n";
    }

    return md.str();
}

void HealthMonitor::MonitorLoop() {
    while (running_) {
        for (const auto& check : checks_) {
            auto health = check->Check();
            health.lastCheck = std::chrono::system_clock::now();
            healthData_[check->GetName()] = health;

            EvaluateThresholds(health);
        }

        // Sleep for a short interval
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void HealthMonitor::EvaluateThresholds(const ComponentHealth& health) {
    // Check latency threshold
    auto latencyIt = latencyThresholds_.find(health.name);
    if (latencyIt != latencyThresholds_.end()) {
        if (health.latencyMs > latencyIt->second) {
            if (alertCallback_) {
                alertCallback_(health);
            }
        }
    }

    // Check error rate threshold
    auto errorIt = errorRateThresholds_.find(health.name);
    if (errorIt != errorRateThresholds_.end()) {
        if (health.errorRate > errorIt->second) {
            if (alertCallback_) {
                alertCallback_(health);
            }
        }
    }

    // Check memory threshold
    if (health.memoryUsageMB > memoryThresholdMB_) {
        if (alertCallback_) {
            alertCallback_(health);
        }
    }
}

HealthStatus HealthMonitor::AggregateStatus(const std::vector<ComponentHealth>& components) const {
    bool hasUnhealthy = false;
    bool hasDegraded = false;

    for (const auto& comp : components) {
        if (comp.status == HealthStatus::UNHEALTHY) {
            hasUnhealthy = true;
        } else if (comp.status == HealthStatus::DEGRADED) {
            hasDegraded = true;
        }
    }

    if (hasUnhealthy) return HealthStatus::UNHEALTHY;
    if (hasDegraded) return HealthStatus::DEGRADED;
    if (components.empty()) return HealthStatus::UNKNOWN;
    return HealthStatus::HEALTHY;
}

// Component health check implementations
ComponentHealth MemoryHealthCheck::Check() {
    ComponentHealth health;
    health.name = GetName();
    health.status = HealthStatus::HEALTHY;

    // Would get actual memory usage
    health.memoryUsageMB = 1024;  // Placeholder
    health.message = "Memory usage normal";

    return health;
}

ComponentHealth InferenceHealthCheck::Check() {
    ComponentHealth health;
    health.name = GetName();
    health.status = HealthStatus::HEALTHY;

    // Would get actual inference metrics
    health.latencyMs = 50.0f;  // Placeholder
    health.throughput = 20.0f;  // Placeholder
    health.message = "Inference running normally";

    return health;
}

ComponentHealth ModelHealthCheck::Check() {
    ComponentHealth health;
    health.name = GetName();
    health.status = HealthStatus::HEALTHY;

    // Would check model status
    health.message = "Model loaded and operational";

    return health;
}

// SystemHealth helper methods
std::vector<ComponentHealth> SystemHealth::GetUnhealthyComponents() const {
    std::vector<ComponentHealth> result;
    for (const auto& comp : components) {
        if (comp.status == HealthStatus::UNHEALTHY) {
            result.push_back(comp);
        }
    }
    return result;
}

std::vector<ComponentHealth> SystemHealth::GetDegradedComponents() const {
    std::vector<ComponentHealth> result;
    for (const auto& comp : components) {
        if (comp.status == HealthStatus::DEGRADED) {
            result.push_back(comp);
        }
    }
    return result;
}

} // namespace production
} // namespace rawrxd
