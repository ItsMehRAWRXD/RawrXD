// RawrXD Production Monitor Implementation
// Phase V.1: Real-time production monitoring and alerting

#include "ProductionMonitor.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

namespace RawrXD {
namespace Monitoring {

// ============================================================================
// TimeSeries Implementation
// ============================================================================

void TimeSeries::addValue(const MetricValue& value) {
    std::lock_guard<std::mutex> lock(mutex);
    values.push_back(value);
}

std::vector<MetricValue> TimeSeries::getRange(
    std::chrono::system_clock::time_point start,
    std::chrono::system_clock::time_point end) const {
    std::lock_guard<std::mutex> lock(mutex);
    
    std::vector<MetricValue> result;
    for (const auto& val : values) {
        if (val.timestamp >= start && val.timestamp <= end) {
            result.push_back(val);
        }
    }
    return result;
}

double TimeSeries::getLatest() const {
    std::lock_guard<std::mutex> lock(mutex);
    if (values.empty()) return 0.0;
    return values.back().value;
}

double TimeSeries::getAverage(std::chrono::seconds window) const {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto cutoff = std::chrono::system_clock::now() - window;
    double sum = 0.0;
    int count = 0;
    
    for (const auto& val : values) {
        if (val.timestamp >= cutoff) {
            sum += val.value;
            count++;
        }
    }
    
    return count > 0 ? sum / count : 0.0;
}

double TimeSeries::getPercentile(double percentile, std::chrono::seconds window) const {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto cutoff = std::chrono::system_clock::now() - window;
    std::vector<double> recentValues;
    
    for (const auto& val : values) {
        if (val.timestamp >= cutoff) {
            recentValues.push_back(val.value);
        }
    }
    
    if (recentValues.empty()) return 0.0;
    
    std::sort(recentValues.begin(), recentValues.end());
    size_t index = static_cast<size_t>(percentile * recentValues.size());
    return recentValues[std::min(index, recentValues.size() - 1)];
}

// ============================================================================
// ProductionMonitor Implementation
// ============================================================================

ProductionMonitor::ProductionMonitor() = default;

ProductionMonitor::~ProductionMonitor() {
    if (running_) {
        shutdown();
    }
}

bool ProductionMonitor::initialize(const std::string& configPath) {
    if (running_) {
        return true;
    }
    
    startTime_ = std::chrono::steady_clock::now();
    running_ = true;
    
    // Start evaluation thread
    evaluationThread_ = std::thread([this]() {
        while (running_) {
            evaluateAlertRules();
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });
    
    // Start cleanup thread
    cleanupThread_ = std::thread([this]() {
        while (running_) {
            cleanupOldData();
            std::this_thread::sleep_for(std::chrono::minutes(5));
        }
    });
    
    return true;
}

bool ProductionMonitor::shutdown() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    if (evaluationThread_.joinable()) {
        evaluationThread_.join();
    }
    
    if (cleanupThread_.joinable()) {
        cleanupThread_.join();
    }
    
    return true;
}

// ============================================================================
// Metric Registration
// ============================================================================

void ProductionMonitor::registerMetric(const MetricDefinition& definition) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto series = std::make_unique<TimeSeries>();
    series->definition = definition;
    metrics_[definition.name] = std::move(series);
}

void ProductionMonitor::unregisterMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.erase(name);
}

bool ProductionMonitor::hasMetric(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_.find(name) != metrics_.end();
}

std::vector<MetricDefinition> ProductionMonitor::getRegisteredMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<MetricDefinition> result;
    for (const auto& [name, series] : metrics_) {
        result.push_back(series->definition);
    }
    return result;
}

// ============================================================================
// Metric Recording
// ============================================================================

void ProductionMonitor::recordCounter(const std::string& name, double increment,
                                       const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        // Auto-register if not exists
        MetricDefinition def;
        def.name = name;
        def.type = MetricType::COUNTER;
        def.description = "Auto-registered counter";
        
        auto series = std::make_unique<TimeSeries>();
        series->definition = def;
        it = metrics_.insert({name, std::move(series)}).first;
    }
    
    MetricValue value(increment);
    value.labels = labels;
    it->second->addValue(value);
    
    metricsRecorded_++;
    notifyMetricSubscribers(name, value);
}

void ProductionMonitor::recordGauge(const std::string& name, double value,
                                   const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        MetricDefinition def;
        def.name = name;
        def.type = MetricType::GAUGE;
        def.description = "Auto-registered gauge";
        
        auto series = std::make_unique<TimeSeries>();
        series->definition = def;
        it = metrics_.insert({name, std::move(series)}).first;
    }
    
    MetricValue mv(value);
    mv.labels = labels;
    it->second->addValue(mv);
    
    metricsRecorded_++;
    notifyMetricSubscribers(name, mv);
}

void ProductionMonitor::recordHistogram(const std::string& name, double value,
                                       const std::map<std::string, std::string>& labels) {
    recordGauge(name, value, labels);  // Simplified - would use histogram buckets
}

void ProductionMonitor::recordSummary(const std::string& name, double value,
                                     const std::map<std::string, std::string>& labels) {
    recordGauge(name, value, labels);
}

// ============================================================================
// Metric Queries
// ============================================================================

double ProductionMonitor::getMetricValue(const std::string& name,
                                         const std::map<std::string, std::string>& labels) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        return it->second->getLatest();
    }
    return 0.0;
}

std::vector<MetricValue> ProductionMonitor::getMetricHistory(
    const std::string& name,
    std::chrono::seconds duration,
    const std::map<std::string, std::string>& labels) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        auto end = std::chrono::system_clock::now();
        auto start = end - duration;
        return it->second->getRange(start, end);
    }
    return {};
}

std::map<std::string, double> ProductionMonitor::getMetricAggregates(
    const std::string& name,
    std::chrono::seconds duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, double> result;
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        result["latest"] = it->second->getLatest();
        result["average"] = it->second->getAverage(duration);
        result["p50"] = it->second->getPercentile(0.50, duration);
        result["p95"] = it->second->getPercentile(0.95, duration);
        result["p99"] = it->second->getPercentile(0.99, duration);
    }
    
    return result;
}

// ============================================================================
// Alert Management
// ============================================================================

void ProductionMonitor::addAlertRule(const AlertRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    alertRules_[rule.name] = rule;
}

void ProductionMonitor::removeAlertRule(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    alertRules_.erase(name);
}

std::vector<AlertRule> ProductionMonitor::getAlertRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<AlertRule> result;
    for (const auto& [name, rule] : alertRules_) {
        result.push_back(rule);
    }
    return result;
}

std::vector<Alert> ProductionMonitor::getActiveAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Alert> result;
    for (const auto& [id, alert] : activeAlerts_) {
        if (!alert.isResolved) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<Alert> ProductionMonitor::getAlertHistory(std::chrono::hours duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    std::vector<Alert> result;
    
    for (const auto& alert : alertHistory_) {
        if (alert.firedAt >= cutoff) {
            result.push_back(alert);
        }
    }
    return result;
}

bool ProductionMonitor::acknowledgeAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = activeAlerts_.find(alertId);
    if (it != activeAlerts_.end()) {
        it->second.notificationCount++;
        return true;
    }
    return false;
}

bool ProductionMonitor::resolveAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = activeAlerts_.find(alertId);
    if (it != activeAlerts_.end()) {
        it->second.isResolved = true;
        it->second.resolvedAt = std::chrono::system_clock::now();
        alertHistory_.push_back(it->second);
        activeAlerts_.erase(it);
        alertsResolved_++;
        return true;
    }
    return false;
}

// ============================================================================
// Dashboard Management
// ============================================================================

void ProductionMonitor::createDashboard(const Dashboard& dashboard) {
    std::lock_guard<std::mutex> lock(mutex_);
    dashboards_[dashboard.name] = dashboard;
}

void ProductionMonitor::updateDashboard(const std::string& name, const Dashboard& dashboard) {
    std::lock_guard<std::mutex> lock(mutex_);
    dashboards_[name] = dashboard;
}

void ProductionMonitor::deleteDashboard(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    dashboards_.erase(name);
}

Dashboard ProductionMonitor::getDashboard(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dashboards_.find(name);
    if (it != dashboards_.end()) {
        return it->second;
    }
    return Dashboard{};
}

std::vector<std::string> ProductionMonitor::listDashboards() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, dashboard] : dashboards_) {
        result.push_back(name);
    }
    return result;
}

std::string ProductionMonitor::renderDashboard(const std::string& name) const {
    auto dashboard = getDashboard(name);
    
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"name\": \"" << dashboard.name << "\",\n";
    oss << "  \"title\": \"" << dashboard.title << "\",\n";
    oss << "  \"panels\": [\n";
    
    for (size_t i = 0; i < dashboard.panels.size(); ++i) {
        const auto& panel = dashboard.panels[i];
        oss << "    {\n";
        oss << "      \"title\": \"" << panel.title << "\",\n";
        oss << "      \"type\": \"" << panel.type << "\"\n";
        oss << "    }";
        if (i < dashboard.panels.size() - 1) {
            oss << ",";
        }
        oss << "\n";
    }
    
    oss << "  ]\n";
    oss << "}\n";
    
    return oss.str();
}

// ============================================================================
// SLO Management
// ============================================================================

void ProductionMonitor::defineSLO(const SLODefinition& slo) {
    std::lock_guard<std::mutex> lock(mutex_);
    slos_[slo.name] = slo;
}

void ProductionMonitor::removeSLO(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    slos_.erase(name);
}

SLOStatus ProductionMonitor::evaluateSLO(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SLOStatus status;
    status.sloName = name;
    status.lastEvaluated = std::chrono::system_clock::now();
    
    auto it = slos_.find(name);
    if (it != slos_.end()) {
        status.targetValue = it->second.target;
        // Would evaluate actual metric query
        status.currentValue = 0.99;  // Placeholder
        status.errorBudgetRemaining = 100.0 * (status.currentValue - status.targetValue) / (1.0 - status.targetValue);
        status.isBreaching = status.currentValue < status.targetValue;
    }
    
    return status;
}

std::vector<SLOStatus> ProductionMonitor::getAllSLOStatuses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<SLOStatus> result;
    for (const auto& [name, slo] : slos_) {
        result.push_back(evaluateSLO(name));
    }
    return result;
}

// ============================================================================
// Export
// ============================================================================

bool ProductionMonitor::exportToPrometheus(const std::string& outputPath) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, series] : metrics_) {
        file << "# HELP " << name << " " << series->definition.description << "\n";
        file << "# TYPE " << name << " ";
        switch (series->definition.type) {
            case MetricType::COUNTER: file << "counter"; break;
            case MetricType::GAUGE: file << "gauge"; break;
            case MetricType::HISTOGRAM: file << "histogram"; break;
            case MetricType::SUMMARY: file << "summary"; break;
        }
        file << "\n";
        
        if (!series->values.empty()) {
            file << name << " " << series->values.back().value << "\n";
        }
    }
    
    return true;
}

bool ProductionMonitor::exportToJSON(const std::string& outputPath, std::chrono::seconds duration) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"metrics\": [\n";
    
    auto metrics = getRegisteredMetrics();
    for (size_t i = 0; i < metrics.size(); ++i) {
        file << "    {\n";
        file << "      \"name\": \"" << metrics[i].name << "\",\n";
        file << "      \"description\": \"" << metrics[i].description << "\"\n";
        file << "    }";
        if (i < metrics.size() - 1) {
            file << ",";
        }
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool ProductionMonitor::exportToCSV(const std::string& outputPath, std::chrono::seconds duration) const {
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "timestamp,metric_name,value\n";
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    for (const auto& [name, series] : metrics_) {
        for (const auto& val : series->values) {
            if (val.timestamp >= cutoff) {
                auto time = std::chrono::system_clock::to_time_t(val.timestamp);
                file << time << "," << name << "," << val.value << "\n";
            }
        }
    }
    
    return true;
}

// ============================================================================
// Subscriptions
// ============================================================================

void ProductionMonitor::subscribeToMetric(const std::string& name, MetricCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    metricSubscribers_[name].push_back(callback);
}

void ProductionMonitor::subscribeToAlerts(AlertCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    alertSubscribers_.push_back(callback);
}

void ProductionMonitor::unsubscribeAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    metricSubscribers_.clear();
    alertSubscribers_.clear();
}

void ProductionMonitor::notifyMetricSubscribers(const std::string& name, const MetricValue& value) {
    auto it = metricSubscribers_.find(name);
    if (it != metricSubscribers_.end()) {
        for (auto& callback : it->second) {
            callback(name, value);
        }
    }
}

void ProductionMonitor::notifyAlertSubscribers(const Alert& alert) {
    for (auto& callback : alertSubscribers_) {
        callback(alert);
    }
}

// ============================================================================
// Health Status
// ============================================================================

ProductionMonitor::HealthStatus ProductionMonitor::getHealthStatus() const {
    HealthStatus status;
    status.checkedAt = std::chrono::system_clock::now();
    
    auto activeAlerts = getActiveAlerts();
    bool hasCritical = false;
    bool hasWarning = false;
    
    for (const auto& alert : activeAlerts) {
        if (alert.severity == AlertSeverity::CRITICAL || alert.severity == AlertSeverity::EMERGENCY) {
            hasCritical = true;
            status.issues.push_back(alert.message);
        } else if (alert.severity == AlertSeverity::WARNING) {
            hasWarning = true;
        }
    }
    
    if (hasCritical) {
        status.isHealthy = false;
        status.status = "unhealthy";
    } else if (hasWarning) {
        status.isHealthy = true;
        status.status = "degraded";
    } else {
        status.isHealthy = true;
        status.status = "healthy";
    }
    
    return status;
}

// ============================================================================
// Statistics
// ============================================================================

ProductionMonitor::MonitorStats ProductionMonitor::getStats() const {
    MonitorStats stats{};
    stats.metricsRecorded = metricsRecorded_.load();
    stats.alertsFired = alertsFired_.load();
    stats.alertsResolved = alertsResolved_.load();
    stats.activeAlertCount = static_cast<uint32_t>(getActiveAlerts().size());
    stats.registeredMetricCount = static_cast<uint32_t>(getRegisteredMetrics().size());
    stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime_);
    return stats;
}

// ============================================================================
// Internal Methods
// ============================================================================

void ProductionMonitor::evaluateAlertRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, rule] : alertRules_) {
        if (!rule.enabled) continue;
        
        // Check if condition is met
        if (evaluateCondition(rule.metricQuery)) {
            // Check if alert already active
            bool alreadyActive = false;
            for (const auto& [id, alert] : activeAlerts_) {
                if (alert.ruleName == name && !alert.isResolved) {
                    alreadyActive = true;
                    break;
                }
            }
            
            if (!alreadyActive) {
                Alert alert;
                alert.id = generateAlertId();
                alert.ruleName = name;
                alert.severity = rule.severity;
                alert.message = rule.description;
                alert.firedAt = std::chrono::system_clock::now();
                
                activeAlerts_[alert.id] = alert;
                alertsFired_++;
                
                notifyAlertSubscribers(alert);
            }
        }
    }
}

void ProductionMonitor::cleanupOldData() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& [name, series] : metrics_) {
        auto retention = series->definition.retentionPeriod;
        auto cutoff = now - retention;
        
        series->values.erase(
            std::remove_if(series->values.begin(), series->values.end(),
                [cutoff](const MetricValue& v) { return v.timestamp < cutoff; }),
            series->values.end()
        );
    }
}

std::string ProductionMonitor::generateAlertId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "alert-";
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

bool ProductionMonitor::evaluateCondition(const std::string& query) const {
    // Simplified condition evaluation
    // Would parse and evaluate actual metric queries like "cpu_usage > 80"
    return false;
}

// ============================================================================
// MetricBuilder Implementation
// ============================================================================

MetricBuilder::MetricBuilder(ProductionMonitor* monitor, const std::string& name)
    : monitor_(monitor), name_(name) {
}

MetricBuilder& MetricBuilder::withLabel(const std::string& key, const std::string& value) {
    labels_[key] = value;
    return *this;
}

MetricBuilder& MetricBuilder::increment(double amount) {
    monitor_->recordCounter(name_, amount, labels_);
    return *this;
}

MetricBuilder& MetricBuilder::set(double value) {
    monitor_->recordGauge(name_, value, labels_);
    return *this;
}

MetricBuilder& MetricBuilder::observe(double value) {
    monitor_->recordHistogram(name_, value, labels_);
    return *this;
}

// ============================================================================
// AlertBuilder Implementation
// ============================================================================

AlertBuilder::AlertBuilder(ProductionMonitor* monitor)
    : monitor_(monitor) {
}

AlertBuilder& AlertBuilder::withName(const std::string& name) {
    rule_.name = name;
    return *this;
}

AlertBuilder& AlertBuilder::withDescription(const std::string& description) {
    rule_.description = description;
    return *this;
}

AlertBuilder& AlertBuilder::withQuery(const std::string& query) {
    rule_.metricQuery = query;
    return *this;
}

AlertBuilder& AlertBuilder::withSeverity(AlertSeverity severity) {
    rule_.severity = severity;
    return *this;
}

AlertBuilder& AlertBuilder::withDuration(std::chrono::seconds duration) {
    rule_.duration = duration;
    return *this;
}

AlertBuilder& AlertBuilder::withCooldown(std::chrono::seconds cooldown) {
    rule_.cooldown = cooldown;
    return *this;
}

AlertBuilder& AlertBuilder::notifyOn(const std::vector<std::string>& channels) {
    rule_.notificationChannels = channels;
    return *this;
}

bool AlertBuilder::create() {
    monitor_->addAlertRule(rule_);
    return true;
}

} // namespace Monitoring
} // namespace RawrXD
