/**
 * HealthMonitor.cpp
 *
 * Phase F Batch 3/5: Health Monitoring & Alerting
 *
 * Implementation of health checks and alerting system.
 */

#include "HealthMonitor.hpp"
#include "../core/Logger.hpp"
#include <fstream>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace Telemetry {

// ============================================================================
// String Helpers
// ============================================================================

std::string HealthStatusToString(HealthStatus status) {
    switch (status) {
        case HealthStatus::HEALTHY:   return "healthy";
        case HealthStatus::DEGRADED:  return "degraded";
        case HealthStatus::UNHEALTHY: return "unhealthy";
        default: return "unknown";
    }
}

// ============================================================================
// CheckResult Implementation
// ============================================================================

std::string CheckResult::ToJson() const {
    std::string json = "{";
    json += "\"checkId\":\"" + checkId + "\",";
    json += "\"name\":\"" + name + "\",";
    json += "\"severity\":" + std::to_string(static_cast<int>(severity)) + ",";
    json += "\"passed\":" + std::string(passed ? "true" : "false") + ",";
    json += "\"message\":\"" + message + "\",";
    json += "\"timestamp\":" + std::to_string(timestamp) + ",";
    json += "\"durationMs\":" + std::to_string(durationMs);
    json += "}";
    return json;
}

// ============================================================================
// HealthCheck Implementation
// ============================================================================

HealthCheck::HealthCheck(const Config& config) : config_(config) {}

CheckResult HealthCheck::Execute() {
    if (!config_.enabled) {
        CheckResult result;
        result.checkId = config_.id;
        result.name = config_.name;
        result.passed = true;
        result.message = "Check disabled";
        result.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    CheckResult result = DoCheck();
    
    auto end = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count();
    result.checkId = config_.id;
    result.name = config_.name;
    result.severity = config_.severity;
    result.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(mutex_);
    lastResult_ = result;
    lastExecutionTime_ = result.timestamp;
    
    return result;
}

std::optional<CheckResult> HealthCheck::GetLastResult() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastResult_;
}

// ============================================================================
// LivenessCheck Implementation
// ============================================================================

LivenessCheck::LivenessCheck(const Config& config) : HealthCheck(config) {}

CheckResult LivenessCheck::DoCheck() {
    CheckResult result;
    result.passed = true;
    result.message = "Service is alive";
    return result;
}

// ============================================================================
// ReadinessCheck Implementation
// ============================================================================

ReadinessCheck::ReadinessCheck(const Config& config) : HealthCheck(config) {}

void ReadinessCheck::AddDependency(std::function<bool()> check) {
    std::lock_guard<std::mutex> lock(mutex_);
    dependencies_.push_back(check);
}

CheckResult ReadinessCheck::DoCheck() {
    CheckResult result;
    result.passed = true;
    result.message = "Service is ready";
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < dependencies_.size(); ++i) {
        if (!dependencies_[i]()) {
            result.passed = false;
            result.message = "Dependency " + std::to_string(i) + " not ready";
            return result;
        }
    }
    
    return result;
}

// ============================================================================
// ResourceCheck Implementation
// ============================================================================

ResourceCheck::ResourceCheck(const Config& config, const Thresholds& thresholds)
    : HealthCheck(config), thresholds_(thresholds) {}

CheckResult ResourceCheck::DoCheck() {
    CheckResult result;
    result.passed = true;
    
    double cpu = GetCPUUsage();
    double memory = GetMemoryUsage();
    double disk = GetDiskUsage();
    
    // Check CPU
    if (cpu >= thresholds_.cpuCritical) {
        result.passed = false;
        result.severity = CheckSeverity::CRITICAL;
        result.message = "CPU usage critical: " + std::to_string(cpu) + "%";
    } else if (cpu >= thresholds_.cpuWarning) {
        result.passed = false;
        result.severity = CheckSeverity::WARNING;
        result.message = "CPU usage high: " + std::to_string(cpu) + "%";
    }
    
    // Check memory
    if (memory >= thresholds_.memoryCritical) {
        result.passed = false;
        result.severity = CheckSeverity::CRITICAL;
        result.message += " Memory usage critical: " + std::to_string(memory) + "%";
    } else if (memory >= thresholds_.memoryWarning) {
        result.passed = false;
        result.severity = CheckSeverity::WARNING;
        result.message += " Memory usage high: " + std::to_string(memory) + "%";
    }
    
    // Check disk
    if (disk >= thresholds_.diskCritical) {
        result.passed = false;
        result.severity = CheckSeverity::CRITICAL;
        result.message += " Disk usage critical: " + std::to_string(disk) + "%";
    } else if (disk >= thresholds_.diskWarning) {
        result.passed = false;
        result.severity = CheckSeverity::WARNING;
        result.message += " Disk usage high: " + std::to_string(disk) + "%";
    }
    
    if (result.passed) {
        result.message = "Resource usage normal";
    }
    
    return result;
}

double ResourceCheck::GetCPUUsage() {
    // Platform-specific implementation
#ifdef _WIN32
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        // Simplified calculation
        return 0.0;
    }
#endif
    return 0.0;
}

double ResourceCheck::GetMemoryUsage() {
#ifdef _WIN32
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        return 100.0 * (1.0 - (double)memStatus.ullAvailPhys / memStatus.ullTotalPhys);
    }
#endif
    return 0.0;
}

double ResourceCheck::GetDiskUsage() {
    // Simplified - would check actual disk usage
    return 0.0;
}

// ============================================================================
// DependencyCheck Implementation
// ============================================================================

DependencyCheck::DependencyCheck(const Config& config, CheckFunc check)
    : HealthCheck(config), checkFunc_(check) {}

CheckResult DependencyCheck::DoCheck() {
    CheckResult result;
    
    auto [passed, message] = checkFunc_();
    result.passed = passed;
    result.message = message;
    
    return result;
}

// ============================================================================
// MetricThresholdCheck Implementation
// ============================================================================

MetricThresholdCheck::MetricThresholdCheck(
    const Config& config,
    MetricsRegistry* registry,
    const std::string& metricName,
    Comparison comparison,
    double threshold
) : HealthCheck(config), registry_(registry), metricName_(metricName),
    comparison_(comparison), threshold_(threshold) {}

CheckResult MetricThresholdCheck::DoCheck() {
    CheckResult result;
    result.passed = true;
    result.message = "Metric " + metricName_ + " within threshold";
    
    // Get metric value from registry
    auto family = registry_->GetFamily(metricName_);
    if (!family) {
        result.passed = false;
        result.message = "Metric " + metricName_ + " not found";
        return result;
    }
    
    // Simplified - would get actual value
    double value = 0.0;
    
    bool thresholdExceeded = false;
    switch (comparison_) {
        case Comparison::GREATER_THAN:
            thresholdExceeded = value > threshold_;
            break;
        case Comparison::LESS_THAN:
            thresholdExceeded = value < threshold_;
            break;
        case Comparison::EQUAL_TO:
            thresholdExceeded = value == threshold_;
            break;
        case Comparison::NOT_EQUAL:
            thresholdExceeded = value != threshold_;
            break;
    }
    
    if (thresholdExceeded) {
        result.passed = false;
        result.message = "Metric " + metricName_ + " threshold exceeded: " +
                         std::to_string(value);
    }
    
    return result;
}

// ============================================================================
// HealthMonitor Implementation
// ============================================================================

HealthMonitor::HealthMonitor(const Config& config) : config_(config) {}

HealthMonitor::~HealthMonitor() {
    Shutdown();
}

bool HealthMonitor::Initialize() {
    running_ = true;
    monitorThread_ = std::thread(&HealthMonitor::MonitorLoop, this);
    
    LOG_INFO("HealthMonitor initialized");
    return true;
}

void HealthMonitor::Shutdown() {
    running_ = false;
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

void HealthMonitor::RegisterCheck(HealthCheck::Ptr check) {
    std::lock_guard<std::mutex> lock(checksMutex_);
    checks_[check->GetId()] = check;
}

void HealthMonitor::UnregisterCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(checksMutex_);
    checks_.erase(checkId);
}

std::vector<HealthCheck::Ptr> HealthMonitor::GetChecks() const {
    std::lock_guard<std::mutex> lock(checksMutex_);
    
    std::vector<HealthCheck::Ptr> result;
    for (const auto& [id, check] : checks_) {
        result.push_back(check);
    }
    return result;
}

std::optional<HealthCheck::Ptr> HealthMonitor::GetCheck(const std::string& checkId) {
    std::lock_guard<std::mutex> lock(checksMutex_);
    
    auto it = checks_.find(checkId);
    if (it != checks_.end()) {
        return it->second;
    }
    return std::nullopt;
}

HealthStatus HealthMonitor::GetHealthStatus() const {
    std::lock_guard<std::mutex> lock(statusMutex_);
    return currentStatus_;
}

bool HealthMonitor::IsReady() const {
    auto results = GetAllResults();
    for (const auto& result : results) {
        if (!result.passed && result.severity == CheckSeverity::CRITICAL) {
            return false;
        }
    }
    return true;
}

std::vector<CheckResult> HealthMonitor::GetAllResults() const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    
    std::vector<CheckResult> result;
    for (const auto& [id, res] : results_) {
        result.push_back(res);
    }
    return result;
}

std::vector<CheckResult> HealthMonitor::GetFailedResults() const {
    auto all = GetAllResults();
    std::vector<CheckResult> failed;
    
    for (const auto& result : all) {
        if (!result.passed) {
            failed.push_back(result);
        }
    }
    return failed;
}

std::optional<CheckResult> HealthMonitor::GetResult(const std::string& checkId) const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    
    auto it = results_.find(checkId);
    if (it != results_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void HealthMonitor::ForceCheck(const std::string& checkId) {
    auto check = GetCheck(checkId);
    if (check) {
        ExecuteCheck(*check);
    }
}

void HealthMonitor::ForceCheckAll() {
    auto checks = GetChecks();
    for (const auto& check : checks) {
        ExecuteCheck(check);
    }
}

std::string HealthMonitor::GetStatusJson() const {
    std::string json = "{";
    json += "\"status\":\"" + HealthStatusToString(GetHealthStatus()) + "\",";
    json += "\"healthy\":" + std::string(IsHealthy() ? "true" : "false") + ",";
    json += "\"ready\":" + std::string(IsReady() ? "true" : "false") + ",";
    json += "\"checks\":" + std::to_string(checks_.size()) + ",";
    json += "\"failed\":" + std::to_string(GetFailedResults().size());
    json += "}";
    return json;
}

void HealthMonitor::OnHealthChange(HealthChangeCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    healthChangeCallback_ = callback;
}

void HealthMonitor::OnCheckFailure(CheckFailureCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    checkFailureCallback_ = callback;
}

void HealthMonitor::MonitorLoop() {
    // Initial delay
    std::this_thread::sleep_for(std::chrono::milliseconds(config_.startupDelayMs));
    
    while (running_) {
        auto checks = GetChecks();
        for (const auto& check : checks) {
            if (!running_) break;
            ExecuteCheck(check);
        }
        
        UpdateHealthStatus();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.checkIntervalMs));
    }
}

void HealthMonitor::ExecuteCheck(HealthCheck::Ptr check) {
    auto result = check->Execute();
    
    {
        std::lock_guard<std::mutex> lock(resultsMutex_);
        results_[check->GetId()] = result;
    }
    
    if (!result.passed) {
        NotifyCheckFailure(result);
    }
}

void HealthMonitor::UpdateHealthStatus() {
    auto failed = GetFailedResults();
    
    HealthStatus newStatus = HealthStatus::HEALTHY;
    for (const auto& result : failed) {
        if (result.severity == CheckSeverity::CRITICAL) {
            newStatus = HealthStatus::UNHEALTHY;
            break;
        } else if (result.severity == CheckSeverity::WARNING) {
            newStatus = HealthStatus::DEGRADED;
        }
    }
    
    HealthStatus oldStatus;
    {
        std::lock_guard<std::mutex> lock(statusMutex_);
        oldStatus = currentStatus_;
        currentStatus_ = newStatus;
    }
    
    if (oldStatus != newStatus) {
        NotifyHealthChange(oldStatus, newStatus);
    }
}

void HealthMonitor::NotifyHealthChange(HealthStatus oldStatus, HealthStatus newStatus) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (healthChangeCallback_) {
        healthChangeCallback_(oldStatus, newStatus);
    }
}

void HealthMonitor::NotifyCheckFailure(const CheckResult& result) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (checkFailureCallback_) {
        checkFailureCallback_(result);
    }
}

// ============================================================================
// Alert Implementation
// ============================================================================

std::string Alert::ToJson() const {
    std::string json = "{";
    json += "\"alertId\":\"" + alertId + "\",";
    json += "\"name\":\"" + name + "\",";
    json += "\"description\":\"" + description + "\",";
    json += "\"severity\":" + std::to_string(static_cast<int>(severity)) + ",";
    json += "\"source\":\"" + source + "\",";
    json += "\"timestamp\":" + std::to_string(timestamp) + ",";
    json += "\"resolved\":" + std::string(resolved ? "true" : "false");
    json += "}";
    return json;
}

// ============================================================================
// AlertRule Implementation
// ============================================================================

AlertRule::AlertRule(const Config& config) : config_(config) {}

bool AlertRule::Evaluate(MetricsRegistry* registry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Simplified evaluation - would parse and evaluate condition
    bool conditionMet = false; // Placeholder
    
    if (conditionMet && !firing_) {
        firing_ = true;
        firingSince_ = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    } else if (!conditionMet && firing_) {
        firing_ = false;
    }
    
    return firing_;
}

// ============================================================================
// AlertManager Implementation
// ============================================================================

AlertManager::AlertManager(const Config& config) : config_(config) {}

AlertManager::~AlertManager() {
    Shutdown();
}

bool AlertManager::Initialize() {
    running_ = true;
    evaluationThread_ = std::thread(&AlertManager::EvaluationLoop, this);
    
    LOG_INFO("AlertManager initialized");
    return true;
}

void AlertManager::Shutdown() {
    running_ = false;
    
    if (evaluationThread_.joinable()) {
        evaluationThread_.join();
    }
}

void AlertManager::AddRule(std::shared_ptr<AlertRule> rule) {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    rules_.push_back(rule);
}

void AlertManager::RemoveRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
        [&ruleId](const std::shared_ptr<AlertRule>& rule) {
            return rule->GetConfig().id == ruleId;
        }), rules_.end());
}

std::vector<std::shared_ptr<AlertRule>> AlertManager::GetRules() const {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    return rules_;
}

std::vector<Alert> AlertManager::GetActiveAlerts() const {
    std::lock_guard<std::mutex> lock(alertsMutex_);
    
    std::vector<Alert> result;
    for (const auto& [id, alert] : activeAlerts_) {
        if (!alert.resolved) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<Alert> AlertManager::GetAlertHistory() const {
    std::lock_guard<std::mutex> lock(alertsMutex_);
    return alertHistory_;
}

void AlertManager::ResolveAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(alertsMutex_);
    
    auto it = activeAlerts_.find(alertId);
    if (it != activeAlerts_.end()) {
        it->second.resolved = true;
        it->second.resolvedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void AlertManager::AddSilence(const std::string& matcher, uint64_t durationMs) {
    std::lock_guard<std::mutex> lock(silencesMutex_);
    
    uint64_t expires = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() + durationMs;
    silences_.emplace_back(matcher, expires);
}

bool AlertManager::IsSilenced(const Alert& alert) const {
    std::lock_guard<std::mutex> lock(silencesMutex_);
    
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    for (const auto& [matcher, expires] : silences_) {
        if (now < expires) {
            // Simplified matching
            if (alert.name.find(matcher) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

void AlertManager::AddNotificationChannel(const std::string& name, NotificationHandler handler) {
    std::lock_guard<std::mutex> lock(channelsMutex_);
    channels_[name] = handler;
}

void AlertManager::RemoveNotificationChannel(const std::string& name) {
    std::lock_guard<std::mutex> lock(channelsMutex_);
    channels_.erase(name);
}

std::string AlertManager::GetStatusJson() const {
    std::string json = "{";
    json += "\"activeAlerts\":" + std::to_string(GetActiveAlerts().size()) + ",";
    json += "\"rules\":" + std::to_string(rules_.size()) + ",";
    json += "\"channels\":" + std::to_string(channels_.size());
    json += "}";
    return json;
}

void AlertManager::EvaluationLoop() {
    while (running_) {
        EvaluateRules();
        CleanupSilences();
        CleanupResolvedAlerts();
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.evaluationIntervalMs));
    }
}

void AlertManager::EvaluateRules() {
    auto rules = GetRules();
    
    for (const auto& rule : rules) {
        // Would need access to metrics registry
        // bool firing = rule->Evaluate(registry);
        
        // Create or update alert
        // Simplified implementation
    }
}

void AlertManager::SendNotifications(const Alert& alert) {
    if (IsSilenced(alert)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(channelsMutex_);
    for (const auto& [name, handler] : channels_) {
        handler(alert);
    }
}

bool AlertManager::ShouldNotify(const Alert& alert) {
    // Check if recently notified
    return true;
}

void AlertManager::CleanupSilences() {
    std::lock_guard<std::mutex> lock(silencesMutex_);
    
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    silences_.erase(std::remove_if(silences_.begin(), silences_.end(),
        [now](const auto& silence) { return silence.second < now; }), silences_.end());
}

void AlertManager::CleanupResolvedAlerts() {
    std::lock_guard<std::mutex> lock(alertsMutex_);
    
    // Move old resolved alerts to history
    // Simplified - would check age
}

// ============================================================================
// NotificationChannels Implementation
// ============================================================================

AlertManager::NotificationHandler NotificationChannels::FileChannel(const std::string& filepath) {
    return [filepath](const Alert& alert) {
        std::ofstream file(filepath, std::ios::app);
        if (file.is_open()) {
            file << alert.timestamp << " " << alert.name << ": " << alert.description << std::endl;
            file.close();
        }
    };
}

AlertManager::NotificationHandler NotificationChannels::WebhookChannel(const std::string& url) {
    return [url](const Alert& alert) {
        // TODO: Implement HTTP POST
        LOG_INFO("Would send alert to webhook: " + url);
    };
}

AlertManager::NotificationHandler NotificationChannels::EmailChannel(
    const std::string& smtpServer,
    const std::string& from,
    const std::vector<std::string>& to
) {
    return [=](const Alert& alert) {
        // TODO: Implement SMTP
        LOG_INFO("Would send email alert via " + smtpServer);
    };
}

AlertManager::NotificationHandler NotificationChannels::SlackChannel(const std::string& webhookUrl) {
    return [webhookUrl](const Alert& alert) {
        // TODO: Implement Slack webhook
        LOG_INFO("Would send alert to Slack");
    };
}

AlertManager::NotificationHandler NotificationChannels::PagerDutyChannel(const std::string& integrationKey) {
    return [integrationKey](const Alert& alert) {
        // TODO: Implement PagerDuty API
        LOG_INFO("Would trigger PagerDuty incident");
    };
}

AlertManager::NotificationHandler NotificationChannels::CompositeChannel(
    const std::vector<AlertManager::NotificationHandler>& channels
) {
    return [channels](const Alert& alert) {
        for (const auto& channel : channels) {
            channel(alert);
        }
    };
}

// ============================================================================
// Health API Implementation
// ============================================================================

std::unique_ptr<HealthMonitor> Health::monitor_;
std::unique_ptr<AlertManager> Health::alertManager_;
std::mutex Health::mutex_;

bool Health::Initialize() {
    HealthMonitor::Config monitorConfig;
    AlertManager::Config alertConfig;
    return Initialize(monitorConfig, alertConfig);
}

bool Health::Initialize(const HealthMonitor::Config& monitorConfig,
                        const AlertManager::Config& alertConfig) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    monitor_ = std::make_unique<HealthMonitor>(monitorConfig);
    alertManager_ = std::make_unique<AlertManager>(alertConfig);
    
    if (!monitor_->Initialize()) {
        return false;
    }
    
    if (!alertManager_->Initialize()) {
        return false;
    }
    
    return true;
}

void Health::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (monitor_) {
        monitor_->Shutdown();
        monitor_.reset();
    }
    
    if (alertManager_) {
        alertManager_->Shutdown();
        alertManager_.reset();
    }
}

HealthMonitor* Health::GetMonitor() {
    std::lock_guard<std::mutex> lock(mutex_);
    return monitor_.get();
}

AlertManager* Health::GetAlertManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    return alertManager_.get();
}

bool Health::IsHealthy() {
    return monitor_ ? monitor_->IsHealthy() : false;
}

bool Health::IsReady() {
    return monitor_ ? monitor_->IsReady() : false;
}

HealthStatus Health::GetStatus() {
    return monitor_ ? monitor_->GetHealthStatus() : HealthStatus::UNHEALTHY;
}

void Health::RegisterLivenessCheck() {
    if (!monitor_) return;
    
    LivenessCheck::Config config;
    config.id = "liveness";
    config.name = "Liveness Check";
    config.intervalMs = 10000;
    
    monitor_->RegisterCheck(std::make_shared<LivenessCheck>(config));
}

void Health::RegisterReadinessCheck() {
    if (!monitor_) return;
    
    ReadinessCheck::Config config;
    config.id = "readiness";
    config.name = "Readiness Check";
    config.intervalMs = 30000;
    
    monitor_->RegisterCheck(std::make_shared<ReadinessCheck>(config));
}

void Health::RegisterResourceCheck(const ResourceCheck::Thresholds& thresholds) {
    if (!monitor_) return;
    
    ResourceCheck::Config config;
    config.id = "resources";
    config.name = "Resource Check";
    config.intervalMs = 60000;
    
    monitor_->RegisterCheck(std::make_shared<ResourceCheck>(config, thresholds));
}

void Health::Alert(const std::string& name, const std::string& description,
                   CheckSeverity severity) {
    if (!alertManager_) return;
    
    Alert alert;
    alert.alertId = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    alert.name = name;
    alert.description = description;
    alert.severity = severity;
    alert.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    alert.resolved = false;
    
    // Would add to active alerts and notify
}

} // namespace Telemetry
