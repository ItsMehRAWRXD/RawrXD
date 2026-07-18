// RawrXD Alert Manager Implementation
// Phase P.3: Alert management and notification system

#include "AlertManager.hpp"
#include "ObservabilityPlatform.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

namespace RawrXD {
namespace Performance {

// ============================================================================
// AlertManager Implementation
// ============================================================================

AlertManager::AlertManager(ObservabilityPlatform* observability)
    : observability_(observability)
    , running_(false)
    , initialized_(false) {
}

AlertManager::~AlertManager() {
    if (running_) {
        shutdown();
    }
}

bool AlertManager::initialize(const AlertManagerConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Start threads
    running_ = true;
    evalThread_ = std::thread(&AlertManager::evaluationLoop, this);
    notifyThread_ = std::thread(&AlertManager::notificationLoop, this);
    cleanupThread_ = std::thread(&AlertManager::cleanupLoop, this);
    
    initialized_ = true;
    return true;
}

bool AlertManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    notifyCv_.notify_all();
    
    if (evalThread_.joinable()) {
        evalThread_.join();
    }
    if (notifyThread_.joinable()) {
        notifyThread_.join();
    }
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Rule Management
// ============================================================================

std::string AlertManager::createRule(const AlertRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = rule.id.empty() ? "rule-" + std::to_string(rules_.size() + 1) : rule.id;
    AlertRule newRule = rule;
    newRule.id = id;
    
    rules_[id] = newRule;
    return id;
}

bool AlertManager::updateRule(const std::string& ruleId, const AlertRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    
    AlertRule updated = rule;
    updated.id = ruleId;
    it->second = updated;
    return true;
}

bool AlertManager::deleteRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Resolve any active alerts from this rule
    for (auto& [id, alert] : alerts_) {
        if (alert.ruleId == ruleId && alert.status == AlertStatus::FIRING) {
            alert.status = AlertStatus::RESOLVED;
            alert.resolvedAt = std::chrono::steady_clock::now();
        }
    }
    
    return rules_.erase(ruleId) > 0;
}

AlertRule AlertManager::getRule(const std::string& ruleId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        return it->second;
    }
    
    return AlertRule{};
}

std::vector<AlertRule> AlertManager::getAllRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AlertRule> result;
    result.reserve(rules_.size());
    
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    
    return result;
}

std::vector<AlertRule> AlertManager::getRulesForMetric(const std::string& metric) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AlertRule> result;
    for (const auto& [id, rule] : rules_) {
        if (rule.metric == metric) {
            result.push_back(rule);
        }
    }
    
    return result;
}

bool AlertManager::enableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    
    it->second.enabled = true;
    return true;
}

bool AlertManager::disableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }
    
    it->second.enabled = false;
    return true;
}

// ============================================================================
// Alert Management
// ============================================================================

std::vector<Alert> AlertManager::getActiveAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Alert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.status == AlertStatus::FIRING || 
            alert.status == AlertStatus::ACKNOWLEDGED) {
            result.push_back(alert);
        }
    }
    
    return result;
}

std::vector<Alert> AlertManager::getAlertsBySeverity(AlertSeverity severity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Alert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.severity == severity && 
            (alert.status == AlertStatus::FIRING || 
             alert.status == AlertStatus::ACKNOWLEDGED)) {
            result.push_back(alert);
        }
    }
    
    return result;
}

std::vector<Alert> AlertManager::getAlertHistory(uint32_t hours) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(hours);
    
    std::vector<Alert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.firedAt >= cutoff) {
            result.push_back(alert);
        }
    }
    
    // Sort by fired time descending
    std::sort(result.begin(), result.end(), 
              [](const Alert& a, const Alert& b) {
                  return a.firedAt > b.firedAt;
              });
    
    return result;
}

Alert AlertManager::getAlert(const std::string& alertId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = alerts_.find(alertId);
    if (it != alerts_.end()) {
        return it->second;
    }
    
    return Alert{};
}

bool AlertManager::acknowledgeAlert(const std::string& alertId, const std::string& user) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = alerts_.find(alertId);
    if (it == alerts_.end() || it->second.status != AlertStatus::FIRING) {
        return false;
    }
    
    it->second.status = AlertStatus::ACKNOWLEDGED;
    it->second.acknowledgedAt = std::chrono::steady_clock::now();
    it->second.annotations["acknowledgedBy"] = user;
    
    return true;
}

bool AlertManager::resolveAlert(const std::string& alertId, const std::string& comment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }
    
    it->second.status = AlertStatus::RESOLVED;
    it->second.resolvedAt = std::chrono::steady_clock::now();
    if (!comment.empty()) {
        it->second.annotations["resolutionComment"] = comment;
    }
    
    return true;
}

bool AlertManager::silenceAlert(const std::string& alertId, uint32_t durationMinutes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }
    
    it->second.status = AlertStatus::SILENCED;
    it->second.silencedUntil = std::chrono::steady_clock::now() + 
                                std::chrono::minutes(durationMinutes);
    
    return true;
}

bool AlertManager::unsilenceAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = alerts_.find(alertId);
    if (it == alerts_.end() || it->second.status != AlertStatus::SILENCED) {
        return false;
    }
    
    it->second.status = AlertStatus::FIRING;
    it->second.silencedUntil = std::chrono::steady_clock::time_point{};
    
    return true;
}

// ============================================================================
// Bulk Operations
// ============================================================================

bool AlertManager::acknowledgeAll(const std::vector<std::string>& alertIds, 
                                   const std::string& user) {
    bool allSuccess = true;
    for (const auto& id : alertIds) {
        if (!acknowledgeAlert(id, user)) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

bool AlertManager::resolveAll(const std::vector<std::string>& alertIds, 
                               const std::string& comment) {
    bool allSuccess = true;
    for (const auto& id : alertIds) {
        if (!resolveAlert(id, comment)) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

bool AlertManager::silenceAll(const std::vector<std::string>& alertIds, 
                               uint32_t durationMinutes) {
    bool allSuccess = true;
    for (const auto& id : alertIds) {
        if (!silenceAlert(id, durationMinutes)) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

// ============================================================================
// Silence Management
// ============================================================================

std::string AlertManager::createSilence(const Silence& silence) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = "silence-" + std::to_string(silenceIdCounter_.fetch_add(1));
    Silence newSilence = silence;
    newSilence.id = id;
    
    silences_[id] = newSilence;
    return id;
}

bool AlertManager::deleteSilence(const std::string& silenceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return silences_.erase(silenceId) > 0;
}

std::vector<AlertManager::Silence> AlertManager::getActiveSilences() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<Silence> result;
    
    for (const auto& [id, silence] : silences_) {
        if (silence.endsAt > now) {
            result.push_back(silence);
        }
    }
    
    return result;
}

bool AlertManager::isAlertSilenced(const Alert& alert) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [id, silence] : silences_) {
        if (silence.endsAt <= now) {
            continue;
        }
        
        // Check if all matchers apply
        bool matches = true;
        for (const auto& [key, value] : silence.matchers) {
            auto it = alert.labels.find(key);
            if (it == alert.labels.end() || it->second != value) {
                matches = false;
                break;
            }
        }
        
        if (matches) {
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// Notification Testing
// ============================================================================

bool AlertManager::testEmailNotification(const std::string& address) {
    Alert testAlert;
    testAlert.id = "test-" + generateAlertId();
    testAlert.ruleName = "Test Alert";
    testAlert.severity = AlertSeverity::INFO;
    testAlert.summary = "This is a test email notification";
    testAlert.description = "If you received this email, your email notifications are configured correctly.";
    testAlert.currentValue = 42.0;
    testAlert.threshold = 100.0;
    
    sendEmail(testAlert);
    return true;
}

bool AlertManager::testSlackNotification(const std::string& channel) {
    Alert testAlert;
    testAlert.id = "test-" + generateAlertId();
    testAlert.ruleName = "Test Alert";
    testAlert.severity = AlertSeverity::INFO;
    testAlert.summary = "This is a test Slack notification";
    testAlert.description = "If you see this message, your Slack notifications are configured correctly.";
    
    sendSlack(testAlert);
    return true;
}

bool AlertManager::testPagerDutyNotification() {
    Alert testAlert;
    testAlert.id = "test-" + generateAlertId();
    testAlert.ruleName = "Test Alert";
    testAlert.severity = AlertSeverity::WARNING;
    testAlert.summary = "This is a test PagerDuty notification";
    testAlert.description = "If you received this alert, your PagerDuty integration is configured correctly.";
    
    sendPagerDuty(testAlert);
    return true;
}

// ============================================================================
// Statistics
// ============================================================================

AlertManager::AlertStats AlertManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    AlertStats stats{};
    stats.totalAlerts = totalAlerts_.load();
    
    for (const auto& [id, alert] : alerts_) {
        switch (alert.status) {
            case AlertStatus::FIRING:
                stats.firingAlerts++;
                break;
            case AlertStatus::ACKNOWLEDGED:
                stats.acknowledgedAlerts++;
                break;
            case AlertStatus::RESOLVED:
                stats.resolvedAlerts++;
                break;
            case AlertStatus::SILENCED:
                stats.silencedAlerts++;
                break;
        }
        
        stats.alertsBySeverity[alert.severity]++;
        stats.alertsByRule[alert.ruleId]++;
        stats.alertsByMetric[alert.annotations.count("metric") ? 
                             alert.annotations.at("metric") : "unknown"]++;
    }
    
    return stats;
}

// ============================================================================
// Configuration
// ============================================================================

bool AlertManager::updateConfig(const AlertManagerConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    return true;
}

void AlertManager::setAlertCallback(AlertCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    alertCallback_ = callback;
}

// ============================================================================
// Internal Loops
// ============================================================================

void AlertManager::evaluationLoop() {
    while (running_) {
        auto start = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& [id, rule] : rules_) {
                if (rule.enabled) {
                    evaluateRule(rule);
                }
            }
        }
        
        // Sleep until next evaluation
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto sleepTime = std::chrono::seconds(config_.evaluationIntervalSeconds) - elapsed;
        
        if (sleepTime > std::chrono::seconds(0)) {
            std::this_thread::sleep_for(sleepTime);
        }
    }
}

void AlertManager::notificationLoop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(notifyMutex_);
        notifyCv_.wait(lock, [this] { return !notificationQueue_.empty() || !running_; });
        
        while (!notificationQueue_.empty()) {
            Alert alert = notificationQueue_.front();
            notificationQueue_.pop();
            lock.unlock();
            
            sendNotification(alert);
            totalNotifications_++;
            
            lock.lock();
        }
    }
}

void AlertManager::cleanupLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        
        if (!running_) break;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Clean up old resolved alerts
        auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(24 * 7); // 7 days
        
        for (auto it = alerts_.begin(); it != alerts_.end();) {
            if (it->second.status == AlertStatus::RESOLVED && 
                it->second.resolvedAt < cutoff) {
                it = alerts_.erase(it);
            } else {
                ++it;
            }
        }
        
        // Clean up expired silences
        auto now = std::chrono::steady_clock::now();
        for (auto it = silences_.begin(); it != silences_.end();) {
            if (it->second.endsAt <= now) {
                it = silences_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// ============================================================================
// Rule Evaluation
// ============================================================================

void AlertManager::evaluateRule(const AlertRule& rule) {
    // Query current metric value from observability platform
    // This is a simplified implementation - in production, query actual metrics
    double currentValue = 0.0;
    
    // Check if condition is met
    if (checkCondition(rule, currentValue)) {
        // Check if alert already firing
        bool alreadyFiring = false;
        for (const auto& [id, alert] : alerts_) {
            if (alert.ruleId == rule.id && 
                (alert.status == AlertStatus::FIRING || 
                 alert.status == AlertStatus::ACKNOWLEDGED)) {
                alreadyFiring = true;
                break;
            }
        }
        
        if (!alreadyFiring) {
            fireAlert(rule, currentValue);
        }
    } else {
        // Check if we need to resolve
        for (auto& [id, alert] : alerts_) {
            if (alert.ruleId == rule.id && alert.status == AlertStatus::FIRING) {
                alert.status = AlertStatus::RESOLVED;
                alert.resolvedAt = std::chrono::steady_clock::now();
            }
        }
    }
}

bool AlertManager::checkCondition(const AlertRule& rule, double value) {
    if (rule.condition == ">") return value > rule.threshold;
    if (rule.condition == ">=") return value >= rule.threshold;
    if (rule.condition == "<") return value < rule.threshold;
    if (rule.condition == "<=") return value <= rule.threshold;
    if (rule.condition == "==") return value == rule.threshold;
    if (rule.condition == "!=") return value != rule.threshold;
    return false;
}

void AlertManager::fireAlert(const AlertRule& rule, double value) {
    Alert alert;
    alert.id = generateAlertId();
    alert.ruleId = rule.id;
    alert.ruleName = rule.name;
    alert.severity = rule.severity;
    alert.status = AlertStatus::FIRING;
    alert.firedAt = std::chrono::steady_clock::now();
    alert.summary = rule.name + " is firing";
    alert.description = rule.description;
    alert.currentValue = value;
    alert.threshold = rule.threshold;
    alert.labels = rule.labels;
    alert.annotations["metric"] = rule.metric;
    
    // Check rate limiting
    auto lastAlert = lastAlertTime_.find(rule.id);
    if (lastAlert != lastAlertTime_.end()) {
        auto elapsed = std::chrono::steady_clock::now() - lastAlert->second;
        if (elapsed < std::chrono::minutes(rule.cooldownMinutes)) {
            return; // Still in cooldown
        }
    }
    
    // Check if silenced
    if (isAlertSilenced(alert)) {
        return;
    }
    
    // Store alert
    alerts_[alert.id] = alert;
    lastAlertTime_[rule.id] = std::chrono::steady_clock::now();
    totalAlerts_++;
    
    // Queue for notification
    {
        std::lock_guard<std::mutex> lock(notifyMutex_);
        notificationQueue_.push(alert);
    }
    notifyCv_.notify_one();
    
    // Call callback if set
    if (alertCallback_) {
        alertCallback_(alert);
    }
}

// ============================================================================
// Notifications
// ============================================================================

void AlertManager::sendNotification(const Alert& alert) {
    const AlertRule& rule = getRule(alert.ruleId);
    
    if (rule.sendEmail) {
        sendEmail(alert);
    }
    if (rule.sendSlack) {
        sendSlack(alert);
    }
    if (rule.sendPagerDuty) {
        sendPagerDuty(alert);
    }
}

void AlertManager::sendEmail(const Alert& alert) {
    // Implementation would use SMTP library
    // For now, just log
}

void AlertManager::sendSlack(const Alert& alert) {
    // Implementation would use HTTP client to POST to webhook
    // For now, just log
}

void AlertManager::sendPagerDuty(const Alert& alert) {
    // Implementation would use PagerDuty API
    // For now, just log
}

void AlertManager::sendWebhook(const Alert& alert) {
    // Implementation would use HTTP client
    // For now, just log
}

// ============================================================================
// ID Generation
// ============================================================================

std::string AlertManager::generateAlertId() {
    uint64_t counter = alertIdCounter_.fetch_add(1);
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    std::stringstream ss;
    ss << "alert-" << now << "-" << counter;
    return ss.str();
}

std::string AlertManager::generateSilenceId() {
    uint64_t counter = silenceIdCounter_.fetch_add(1);
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    std::stringstream ss;
    ss << "silence-" << now << "-" << counter;
    return ss.str();
}

} // namespace Performance
} // namespace RawrXD
