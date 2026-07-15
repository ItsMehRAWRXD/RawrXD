// SovereignObservability.cpp
// Phase D.4 Batch 4/5 — Observability & Operations Implementation

#include "SovereignObservability.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace Sovereign {

// ============================================================================
// Metric Collector Implementation
// ============================================================================

MetricCollector::MetricCollector()
    : retention_(std::chrono::hours(24))
{}

MetricCollector::~MetricCollector() {}

void MetricCollector::RegisterMetric(const MetricDefinition& definition) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    definitions_[definition.name] = definition;
}

void MetricCollector::UnregisterMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    definitions_.erase(name);
    data_.erase(name);
}

void MetricCollector::RecordCounter(const std::string& name, double increment) {
    RecordCounter(name, increment, {});
}

void MetricCollector::RecordCounter(const std::string& name, double increment,
                                     const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    MetricValue value;
    value.value = increment;
    value.labels = labels;
    
    // For counters, we accumulate
    auto& series = data_[name];
    if (!series.empty()) {
        value.value += series.back().value;
    }
    
    series.push_back(value);
}

void MetricCollector::RecordGauge(const std::string& name, double value) {
    RecordGauge(name, value, {});
}

void MetricCollector::RecordGauge(const std::string& name, double value,
                                   const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    MetricValue mv;
    mv.value = value;
    mv.labels = labels;
    
    data_[name].push_back(mv);
}

void MetricCollector::RecordHistogram(const std::string& name, double value) {
    RecordHistogram(name, value, {});
}

void MetricCollector::RecordHistogram(const std::string& name, double value,
                                       const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    MetricValue mv;
    mv.value = value;
    mv.labels = labels;
    
    data_[name].push_back(mv);
}

std::optional<double> MetricCollector::GetValue(const std::string& name) {
    return GetValue(name, {});
}

std::optional<double> MetricCollector::GetValue(const std::string& name,
                                                 const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    auto it = data_.find(name);
    if (it == data_.end() || it->second.empty()) {
        return std::nullopt;
    }
    
    // Find matching labels
    for (const auto& value : it->second) {
        if (value.labels == labels) {
            return value.value;
        }
    }
    
    // Return latest if no labels specified
    if (labels.empty()) {
        return it->second.back().value;
    }
    
    return std::nullopt;
}

std::vector<MetricValue> MetricCollector::GetTimeSeries(const std::string& name,
                                                         std::chrono::seconds duration) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    auto it = data_.find(name);
    if (it == data_.end()) {
        return {};
    }
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    std::vector<MetricValue> result;
    for (const auto& value : it->second) {
        if (value.timestamp >= cutoff) {
            result.push_back(value);
        }
    }
    
    return result;
}

std::optional<MetricCollector::MetricStats> MetricCollector::GetStatistics(
    const std::string& name, std::chrono::seconds duration) {
    
    auto series = GetTimeSeries(name, duration);
    if (series.empty()) {
        return std::nullopt;
    }
    
    std::vector<double> values;
    for (const auto& v : series) {
        values.push_back(v.value);
    }
    
    MetricStats stats{};
    stats.count = values.size();
    stats.min = *std::min_element(values.begin(), values.end());
    stats.max = *std::max_element(values.begin(), values.end());
    stats.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    
    // Calculate standard deviation
    double variance = 0.0;
    for (double v : values) {
        variance += (v - stats.mean) * (v - stats.mean);
    }
    stats.stddev = std::sqrt(variance / values.size());
    
    // Calculate percentiles
    std::sort(values.begin(), values.end());
    stats.p50 = values[values.size() * 0.5];
    stats.p90 = values[values.size() * 0.9];
    stats.p95 = values[values.size() * 0.95];
    stats.p99 = values[values.size() * 0.99];
    
    return stats;
}

std::string MetricCollector::ExportPrometheus() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::stringstream output;
    
    for (const auto& [name, definition] : definitions_) {
        output << "# HELP " << name << " " << definition.description << "\n";
        output << "# TYPE " << name << " ";
        
        switch (definition.type) {
            case MetricType::COUNTER:
                output << "counter";
                break;
            case MetricType::GAUGE:
                output << "gauge";
                break;
            case MetricType::HISTOGRAM:
                output << "histogram";
                break;
            case MetricType::SUMMARY:
                output << "summary";
                break;
        }
        output << "\n";
        
        auto it = data_.find(name);
        if (it != data_.end()) {
            for (const auto& value : it->second) {
                output << name;
                
                // Add labels
                if (!value.labels.empty()) {
                    output << "{";
                    bool first = true;
                    for (const auto& [k, v] : value.labels) {
                        if (!first) output << ",";
                        output << k << "=\"" << v << "\"";
                        first = false;
                    }
                    output << "}";
                }
                
                output << " " << value.value << "\n";
            }
        }
        
        output << "\n";
    }
    
    return output.str();
}

std::string MetricCollector::ExportJSON() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::stringstream output;
    output << "{\n";
    
    bool first_metric = true;
    for (const auto& [name, series] : data_) {
        if (!first_metric) output << ",\n";
        first_metric = false;
        
        output << "  \"" << name << "\": [\n";
        
        bool first_value = true;
        for (const auto& value : series) {
            if (!first_value) output << ",\n";
            first_value = false;
            
            output << "    {\n";
            output << "      \"value\": " << value.value << ",\n";
            output << "      \"timestamp\": \"" << 
                std::chrono::system_clock::to_time_t(value.timestamp) << "\"";
            
            if (!value.labels.empty()) {
                output << ",\n      \"labels\": {\n";
                bool first_label = true;
                for (const auto& [k, v] : value.labels) {
                    if (!first_label) output << ",\n";
                    first_label = false;
                    output << "        \"" << k << "\": \"" << v << "\"";
                }
                output << "\n      }";
            }
            
            output << "\n    }";
        }
        
        output << "\n  ]";
    }
    
    output << "\n}\n";
    return output.str();
}

std::string MetricCollector::ExportCSV() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::stringstream output;
    output << "metric_name,timestamp,value,labels\n";
    
    for (const auto& [name, series] : data_) {
        for (const auto& value : series) {
            output << name << ",";
            output << std::chrono::system_clock::to_time_t(value.timestamp) << ",";
            output << value.value << ",\"";
            
            for (const auto& [k, v] : value.labels) {
                output << k << "=" << v << ";";
            }
            
            output << "\"\n";
        }
    }
    
    return output.str();
}

void MetricCollector::SetRetention(std::chrono::hours hours) {
    retention_ = hours;
}

size_t MetricCollector::CleanupOldData() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - retention_;
    size_t removed = 0;
    
    for (auto& [name, series] : data_) {
        auto it = std::remove_if(series.begin(), series.end(),
            [cutoff](const MetricValue& v) { return v.timestamp < cutoff; });
        removed += std::distance(it, series.end());
        series.erase(it, series.end());
    }
    
    return removed;
}

void MetricCollector::ClearAll() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    data_.clear();
}

// ============================================================================
// Health Monitor Implementation
// ============================================================================

HealthMonitor::HealthMonitor()
    : monitoring_(false)
{}

HealthMonitor::~HealthMonitor() {
    StopMonitoring();
}

void HealthMonitor::RegisterCheck(const std::string& name, HealthCheckFunction check) {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    checks_[name] = check;
}

void HealthMonitor::UnregisterCheck(const std::string& name) {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    checks_.erase(name);
    last_results_.erase(name);
}

HealthCheckResult HealthMonitor::RunCheck(const std::string& name) {
    HealthCheckFunction check;
    {
        std::lock_guard<std::mutex> lock(checks_mutex_);
        auto it = checks_.find(name);
        if (it == checks_.end()) {
            HealthCheckResult result;
            result.component = name;
            result.status = HealthStatus::UNKNOWN;
            result.message = "Check not registered";
            return result;
        }
        check = it->second;
    }
    
    auto start = std::chrono::steady_clock::now();
    auto result = check();
    auto end = std::chrono::steady_clock::now();
    
    result.response_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.checked_at = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(checks_mutex_);
        last_results_[name] = result;
    }
    
    return result;
}

std::vector<HealthCheckResult> HealthMonitor::RunAllChecks() {
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(checks_mutex_);
        for (const auto& [name, _] : checks_) {
            names.push_back(name);
        }
    }
    
    std::vector<HealthCheckResult> results;
    for (const auto& name : names) {
        results.push_back(RunCheck(name));
    }
    
    return results;
}

HealthStatus HealthMonitor::GetOverallHealth() const {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    
    bool has_unhealthy = false;
    bool has_degraded = false;
    
    for (const auto& [_, result] : last_results_) {
        if (result.status == HealthStatus::UNHEALTHY) {
            has_unhealthy = true;
        } else if (result.status == HealthStatus::DEGRADED) {
            has_degraded = true;
        }
    }
    
    if (has_unhealthy) return HealthStatus::UNHEALTHY;
    if (has_degraded) return HealthStatus::DEGRADED;
    if (last_results_.empty()) return HealthStatus::UNKNOWN;
    return HealthStatus::HEALTHY;
}

std::vector<std::string> HealthMonitor::GetUnhealthyComponents() const {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    
    std::vector<std::string> unhealthy;
    for (const auto& [name, result] : last_results_) {
        if (result.status != HealthStatus::HEALTHY) {
            unhealthy.push_back(name);
        }
    }
    
    return unhealthy;
}

void HealthMonitor::StartMonitoring(std::chrono::seconds interval) {
    if (monitoring_.exchange(true)) {
        return; // Already monitoring
    }
    
    monitor_interval_ = interval;
    monitor_thread_ = std::thread(&HealthMonitor::MonitorLoop, this);
}

void HealthMonitor::StopMonitoring() {
    monitoring_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

bool HealthMonitor::IsMonitoring() const {
    return monitoring_;
}

std::optional<HealthCheckResult> HealthMonitor::GetLastResult(const std::string& name) {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    
    auto it = last_results_.find(name);
    if (it != last_results_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

std::vector<HealthCheckResult> HealthMonitor::GetAllResults() {
    std::lock_guard<std::mutex> lock(checks_mutex_);
    
    std::vector<HealthCheckResult> results;
    for (const auto& [_, result] : last_results_) {
        results.push_back(result);
    }
    
    return results;
}

std::string HealthMonitor::GetHealthEndpointResponse() {
    auto results = RunAllChecks();
    auto overall = GetOverallHealth();
    
    std::stringstream output;
    output << "{\n";
    output << "  \"status\": \"" << StatusToString(overall) << "\",\n";
    output << "  \"checks\": [\n";
    
    bool first = true;
    for (const auto& result : results) {
        if (!first) output << ",\n";
        first = false;
        
        output << "    {\n";
        output << "      \"component\": \"" << result.component << "\",\n";
        output << "      \"status\": \"" << StatusToString(result.status) << "\",\n";
        output << "      \"message\": \"" << result.message << "\",\n";
        output << "      \"response_time_ms\": " << result.response_time.count() << "\n";
        output << "    }";
    }
    
    output << "\n  ]\n";
    output << "}\n";
    
    return output.str();
}

void HealthMonitor::MonitorLoop() {
    while (monitoring_) {
        RunAllChecks();
        
        // Sleep with interrupt check
        for (int i = 0; i < monitor_interval_.count() && monitoring_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

std::string HealthMonitor::StatusToString(HealthStatus status) {
    switch (status) {
        case HealthStatus::HEALTHY: return "healthy";
        case HealthStatus::DEGRADED: return "degraded";
        case HealthStatus::UNHEALTHY: return "unhealthy";
        case HealthStatus::UNKNOWN: return "unknown";
        default: return "unknown";
    }
}

// ============================================================================
// Performance Profiler Implementation
// ============================================================================

PerformanceProfiler::PerformanceProfiler()
    : enabled_(false)
{}

PerformanceProfiler::~PerformanceProfiler() {}

void PerformanceProfiler::StartOperation(const std::string& operation) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(operations_mutex_);
    active_operations_[operation] = std::chrono::steady_clock::now();
}

void PerformanceProfiler::EndOperation(const std::string& operation) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(operations_mutex_);
    
    auto it = active_operations_.find(operation);
    if (it == active_operations_.end()) return;
    
    auto duration = std::chrono::steady_clock::now() - it->second;
    active_operations_.erase(it);
    
    ProfileSample sample;
    sample.operation = operation;
    sample.duration = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    
    std::lock_guard<std::mutex> samples_lock(samples_mutex_);
    samples_.push_back(sample);
}

void PerformanceProfiler::RecordSample(const ProfileSample& sample) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(samples_mutex_);
    samples_.push_back(sample);
}

std::vector<PerformanceProfiler::OperationStats> PerformanceProfiler::GetOperationStats(
    std::chrono::seconds duration) {
    
    std::lock_guard<std::mutex> lock(samples_mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    // Group by operation
    std::map<std::string, std::vector<ProfileSample>> grouped;
    for (const auto& sample : samples_) {
        if (sample.timestamp >= cutoff) {
            grouped[sample.operation].push_back(sample);
        }
    }
    
    std::vector<OperationStats> stats;
    for (const auto& [op, samples] : grouped) {
        OperationStats op_stats{};
        op_stats.operation = op;
        op_stats.count = samples.size();
        
        std::vector<std::chrono::nanoseconds> durations;
        for (const auto& s : samples) {
            durations.push_back(s.duration);
            op_stats.total_time += s.duration;
        }
        
        std::sort(durations.begin(), durations.end());
        
        op_stats.min_time = durations.front();
        op_stats.max_time = durations.back();
        op_stats.avg_time = op_stats.total_time / op_stats.count;
        op_stats.p95_time = durations[static_cast<size_t>(durations.size() * 0.95)];
        op_stats.p99_time = durations[static_cast<size_t>(durations.size() * 0.99)];
        
        stats.push_back(op_stats);
    }
    
    return stats;
}

std::string PerformanceProfiler::ExportTrace() {
    std::lock_guard<std::mutex> lock(samples_mutex_);
    
    std::stringstream output;
    output << "[\n";
    
    bool first = true;
    for (const auto& sample : samples_) {
        if (!first) output << ",\n";
        first = false;
        
        output << "  {\n";
        output << "    \"operation\": \"" << sample.operation << "\",\n";
        output << "    \"duration_ns\": " << sample.duration.count() << ",\n";
        output << "    \"timestamp\": " << 
            std::chrono::system_clock::to_time_t(sample.timestamp) << "\n";
        output << "  }";
    }
    
    output << "\n]\n";
    return output.str();
}

std::string PerformanceProfiler::ExportFlameGraph() {
    // Simplified flame graph format
    std::lock_guard<std::mutex> lock(samples_mutex_);
    
    std::stringstream output;
    
    // Group by operation and count
    std::map<std::string, size_t> counts;
    for (const auto& sample : samples_) {
        counts[sample.operation]++;
    }
    
    for (const auto& [op, count] : counts) {
        output << op << " " << count << "\n";
    }
    
    return output.str();
}

void PerformanceProfiler::Enable() {
    enabled_ = true;
}

void PerformanceProfiler::Disable() {
    enabled_ = false;
}

bool PerformanceProfiler::IsEnabled() const {
    return enabled_;
}

void PerformanceProfiler::Clear() {
    std::lock_guard<std::mutex> lock(samples_mutex_);
    samples_.clear();
}

// ProfileScope implementation
PerformanceProfiler::ProfileScope::ProfileScope(PerformanceProfiler* profiler,
                                                 const std::string& operation)
    : profiler_(profiler)
    , operation_(operation)
    , start_(std::chrono::steady_clock::now())
{}

PerformanceProfiler::ProfileScope::~ProfileScope() {
    if (profiler_ && profiler_->IsEnabled()) {
        auto duration = std::chrono::steady_clock::now() - start_;
        
        ProfileSample sample;
        sample.operation = operation_;
        sample.duration = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
        sample.attributes = attributes_;
        
        profiler_->RecordSample(sample);
    }
}

void PerformanceProfiler::ProfileScope::AddAttribute(const std::string& key,
                                                      const std::string& value) {
    attributes_[key] = value;
}

// ============================================================================
// Log Aggregator Implementation
// ============================================================================

LogAggregator::LogAggregator()
    : min_level_(LogLevel::INFO)
    , buffer_size_(10000)
{}

LogAggregator::~LogAggregator() {}

void LogAggregator::SetMinLevel(LogLevel level) {
    min_level_ = level;
}

void LogAggregator::SetBufferSize(size_t size) {
    buffer_size_ = size;
}

void LogAggregator::SetOutputPath(const std::string& path) {
    output_path_ = path;
}

void LogAggregator::Log(const LogEntry& entry) {
    if (entry.level < min_level_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(entries_mutex_);
    
    LogEntry mutable_entry = entry;
    mutable_entry.id = "log_" + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());
    mutable_entry.timestamp = std::chrono::system_clock::now();
    
    entries_.push_back(mutable_entry);
    
    // Trim if buffer too large
    while (entries_.size() > buffer_size_) {
        entries_.pop_front();
    }
    
    // Write to file if configured
    if (!output_path_.empty()) {
        std::ofstream file(output_path_, std::ios::app);
        if (file.is_open()) {
            file << FormatEntry(mutable_entry) << "\n";
        }
    }
}

void LogAggregator::Log(LogLevel level, const std::string& component,
                          const std::string& message) {
    Log(level, component, message, {});
}

void LogAggregator::Log(LogLevel level, const std::string& component,
                          const std::string& message,
                          const std::map<std::string, std::string>& fields) {
    LogEntry entry;
    entry.level = level;
    entry.component = component;
    entry.message = message;
    entry.fields = fields;
    Log(entry);
}

void LogAggregator::Trace(const std::string& component, const std::string& message) {
    Log(LogLevel::TRACE, component, message);
}

void LogAggregator::Debug(const std::string& component, const std::string& message) {
    Log(LogLevel::DEBUG, component, message);
}

void LogAggregator::Info(const std::string& component, const std::string& message) {
    Log(LogLevel::INFO, component, message);
}

void LogAggregator::Warn(const std::string& component, const std::string& message) {
    Log(LogLevel::WARN, component, message);
}

void LogAggregator::Error(const std::string& component, const std::string& message) {
    Log(LogLevel::ERROR, component, message);
}

void LogAggregator::Fatal(const std::string& component, const std::string& message) {
    Log(LogLevel::FATAL, component, message);
}

std::vector<LogEntry> LogAggregator::Query(LogLevel min_level,
                                             std::optional<std::string> component,
                                             std::optional<std::chrono::system_clock::time_point> start,
                                             std::optional<std::chrono::system_clock::time_point> end,
                                             size_t limit) {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    
    std::vector<LogEntry> result;
    
    for (const auto& entry : entries_) {
        if (entry.level < min_level) continue;
        if (component && entry.component != *component) continue;
        if (start && entry.timestamp < *start) continue;
        if (end && entry.timestamp > *end) continue;
        
        result.push_back(entry);
        
        if (result.size() >= limit) {
            break;
        }
    }
    
    return result;
}

std::vector<LogEntry> LogAggregator::Search(const std::string& query, size_t limit) {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    
    std::vector<LogEntry> result;
    
    for (const auto& entry : entries_) {
        if (entry.message.find(query) != std::string::npos ||
            entry.component.find(query) != std::string::npos) {
            result.push_back(entry);
            
            if (result.size() >= limit) {
                break;
            }
        }
    }
    
    return result;
}

bool LogAggregator::ExportToFile(const std::string& path,
                                  std::optional<LogLevel> min_level) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    auto entries = Query(min_level.value_or(LogLevel::TRACE));
    
    for (const auto& entry : entries) {
        file << FormatEntry(entry) << "\n";
    }
    
    return true;
}

LogAggregator::LogStats LogAggregator::GetStatistics() const {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    
    LogStats stats{};
    stats.total_entries = entries_.size();
    
    for (const auto& entry : entries_) {
        switch (entry.level) {
            case LogLevel::TRACE: stats.trace_count++; break;
            case LogLevel::DEBUG: stats.debug_count++; break;
            case LogLevel::INFO: stats.info_count++; break;
            case LogLevel::WARN: stats.warn_count++; break;
            case LogLevel::ERROR: stats.error_count++; break;
            case LogLevel::FATAL: stats.fatal_count++; break;
        }
    }
    
    if (!entries_.empty()) {
        stats.oldest_entry = entries_.front().timestamp;
        stats.newest_entry = entries_.back().timestamp;
    }
    
    return stats;
}

void LogAggregator::Clear() {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    entries_.clear();
}

size_t LogAggregator::CleanupOldEntries(std::chrono::hours retention) {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - retention;
    
    size_t before = entries_.size();
    while (!entries_.empty() && entries_.front().timestamp < cutoff) {
        entries_.pop_front();
    }
    
    return before - entries_.size();
}

std::string LogAggregator::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string LogAggregator::FormatEntry(const LogEntry& entry) {
    std::stringstream ss;
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << " [" << LevelToString(entry.level) << "]";
    ss << " [" << entry.component << "]";
    ss << " " << entry.message;
    
    if (!entry.fields.empty()) {
        ss << " {";
        bool first = true;
        for (const auto& [k, v] : entry.fields) {
            if (!first) ss << ", ";
            ss << k << "=" << v;
            first = false;
        }
        ss << "}";
    }
    
    return ss.str();
}

// ============================================================================
// Telemetry Exporter Implementation
// ============================================================================

TelemetryExporter::TelemetryExporter()
    : batch_size_(100)
    , flush_interval_(std::chrono::seconds(60))
    , running_(false)
{}

TelemetryExporter::~TelemetryExporter() {
    Stop();
}

void TelemetryExporter::SetEndpoint(const std::string& url) {
    endpoint_ = url;
}

void TelemetryExporter::SetAPIKey(const std::string& key) {
    api_key_ = key;
}

void TelemetryExporter::SetBatchSize(size_t size) {
    batch_size_ = size;
}

void TelemetryExporter::SetFlushInterval(std::chrono::seconds interval) {
    flush_interval_ = interval;
}

void TelemetryExporter::ExportMetrics(const MetricCollector& collector) {
    std::lock_guard<std::mutex> lock(batches_mutex_);
    
    ExportBatch batch;
    batch.type = "metrics";
    batch.data = collector.ExportJSON();
    batch.timestamp = std::chrono::system_clock::now();
    
    pending_batches_.push(batch);
}

void TelemetryExporter::ExportLogs(const LogAggregator& aggregator) {
    (void)aggregator;
    // Would export logs in production
}

void TelemetryExporter::ExportTraces(const PerformanceProfiler& profiler) {
    std::lock_guard<std::mutex> lock(batches_mutex_);
    
    ExportBatch batch;
    batch.type = "traces";
    batch.data = profiler.ExportTrace();
    batch.timestamp = std::chrono::system_clock::now();
    
    pending_batches_.push(batch);
}

void TelemetryExporter::Flush() {
    while (!pending_batches_.empty()) {
        ExportBatch batch;
        {
            std::lock_guard<std::mutex> lock(batches_mutex_);
            if (pending_batches_.empty()) break;
            batch = pending_batches_.front();
            pending_batches_.pop();
        }
        
        SendBatch(batch);
    }
}

void TelemetryExporter::Start() {
    if (running_.exchange(true)) {
        return;
    }
    
    export_thread_ = std::thread(&TelemetryExporter::ExportLoop, this);
}

void TelemetryExporter::Stop() {
    running_ = false;
    if (export_thread_.joinable()) {
        export_thread_.join();
    }
    Flush();
}

bool TelemetryExporter::IsRunning() const {
    return running_;
}

void TelemetryExporter::ExportLoop() {
    while (running_) {
        Flush();
        
        // Sleep with interrupt check
        for (int i = 0; i < flush_interval_.count() && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

bool TelemetryExporter::SendBatch(const ExportBatch& batch) {
    (void)batch;
    // Would send HTTP request in production
    // For now, just log
    std::cout << "Exporting " << batch.type << " batch ("
              << batch.data.size() << " bytes)" << std::endl;
    return true;
}

// ============================================================================
// Operational Commands Implementation
// ============================================================================

OperationalCommands::OperationalCommands() {}

OperationalCommands::~OperationalCommands() {}

void OperationalCommands::RegisterCommand(const std::string& name,
                                         const std::string& description,
                                         CommandFunction func) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    commands_[name] = {description, func};
}

void OperationalCommands::UnregisterCommand(const std::string& name) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    commands_.erase(name);
}

std::string OperationalCommands::Execute(const std::string& command,
                                            const std::vector<std::string>& args) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    
    auto it = commands_.find(command);
    if (it == commands_.end()) {
        return "Error: Unknown command '" + command + "'";
    }
    
    try {
        return it->second.second(args);
    } catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

std::vector<std::pair<std::string, std::string>> OperationalCommands::ListCommands() {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& [name, info] : commands_) {
        result.push_back({name, info.first});
    }
    
    return result;
}

std::optional<std::string> OperationalCommands::GetCommandDescription(
    const std::string& name) {
    
    std::lock_guard<std::mutex> lock(commands_mutex_);
    
    auto it = commands_.find(name);
    if (it != commands_.end()) {
        return it->second.first;
    }
    
    return std::nullopt;
}

void OperationalCommands::RegisterBuiltInCommands(MetricCollector* metrics,
                                                 HealthMonitor* health,
                                                 LogAggregator* logs,
                                                 PerformanceProfiler* profiler) {
    // Health command
    RegisterCommand("health", "Get system health status",
        [health](const std::vector<std::string>&) {
            return health ? health->GetHealthEndpointResponse() : "Health monitor not available";
        });
    
    // Metrics command
    RegisterCommand("metrics", "Export metrics in Prometheus format",
        [metrics](const std::vector<std::string>&) {
            return metrics ? metrics->ExportPrometheus() : "Metrics collector not available";
        });
    
    // Stats command
    RegisterCommand("stats", "Get system statistics",
        [metrics](const std::vector<std::string>&) {
            if (!metrics) return "Metrics collector not available";
            
            auto stats = metrics->GetStatistics("sovereign_cpu_usage_percent",
                                                   std::chrono::seconds(3600));
            if (!stats) return "No CPU metrics available";
            
            std::stringstream ss;
            ss << "CPU Usage: mean=" << stats->mean << "%, max=" << stats->max << "%";
            return ss.str();
        });
    
    // Profile command
    RegisterCommand("profile", "Get performance profile",
        [profiler](const std::vector<std::string>&) {
            return profiler ? profiler->ExportTrace() : "Profiler not available";
        });
    
    // Logs command
    RegisterCommand("logs", "Get recent log entries",
        [logs](const std::vector<std::string>& args) {
            if (!logs) return "Log aggregator not available";
            
            size_t limit = 100;
            if (!args.empty()) {
                limit = std::stoul(args[0]);
            }
            
            auto entries = logs->Query(LogLevel::INFO, std::nullopt, std::nullopt, std::nullopt, limit);
            
            std::stringstream ss;
            for (const auto& entry : entries) {
                ss << entry.component << ": " << entry.message << "\n";
            }
            return ss.str();
        });
}

// ============================================================================
// Sovereign Observability Implementation
// ============================================================================

SovereignObservability& SovereignObservability::GetInstance() {
    static SovereignObservability instance;
    return instance;
}

SovereignObservability::SovereignObservability()
    : initialized_(false)
{
    metrics_ = std::make_unique<MetricCollector>();
    health_ = std::make_unique<HealthMonitor>();
    profiler_ = std::make_unique<PerformanceProfiler>();
    logs_ = std::make_unique<LogAggregator>();
    exporter_ = std::make_unique<TelemetryExporter>();
    commands_ = std::make_unique<OperationalCommands>();
}

SovereignObservability::~SovereignObservability() {
    Shutdown();
}

void SovereignObservability::Initialize(const std::string& config_path) {
    std::lock_guard<std::mutex> lock(init_mutex_);
    
    if (initialized_) {
        return;
    }
    
    // Register built-in metrics
    BuiltInMetrics::RegisterAll(*metrics_);
    
    // Register built-in commands
    commands_->RegisterBuiltInCommands(
        metrics_.get(), health_.get(), logs_.get(), profiler_.get());
    
    // Start health monitoring
    health_->StartMonitoring(std::chrono::seconds(30));
    
    // Start telemetry exporter
    exporter_->Start();
    
    initialized_ = true;
    
    logs_->Info("observability", "Observability layer initialized");
}

void SovereignObservability::Shutdown() {
    std::lock_guard<std::mutex> lock(init_mutex_);
    
    if (!initialized_) {
        return;
    }
    
    logs_->Info("observability", "Shutting down observability layer");
    
    health_->StopMonitoring();
    exporter_->Stop();
    
    initialized_ = false;
}

bool SovereignObservability::IsInitialized() const {
    std::lock_guard<std::mutex> lock(init_mutex_);
    return initialized_;
}

MetricCollector& SovereignObservability::GetMetrics() {
    return *metrics_;
}

HealthMonitor& SovereignObservability::GetHealth() {
    return *health_;
}

PerformanceProfiler& SovereignObservability::GetProfiler() {
    return *profiler_;
}

LogAggregator& SovereignObservability::GetLogs() {
    return *logs_;
}

TelemetryExporter& SovereignObservability::GetExporter() {
    return *exporter_;
}

OperationalCommands& SovereignObservability::GetCommands() {
    return *commands_;
}

void SovereignObservability::RecordMetric(const std::string& name, double value) {
    if (!initialized_) return;
    
    metrics_->RecordGauge(name, value);
}

void SovereignObservability::LogInfo(const std::string& component, 
                                       const std::string& message) {
    if (!initialized_) return;
    
    logs_->Info(component, message);
}

void SovereignObservability::LogError(const std::string& component,
                                        const std::string& message) {
    if (!initialized_) return;
    
    logs_->Error(component, message);
}

std::string SovereignObservability::GetHealthStatus() {
    if (!initialized_) {
        return "{\"status\": \"unknown\", \"message\": \"Not initialized\"}";
    }
    
    return health_->GetHealthEndpointResponse();
}

bool SovereignObservability::IsHealthy() const {
    if (!initialized_) return false;
    
    return health_->GetOverallHealth() == HealthStatus::HEALTHY;
}

SovereignObservability::ObservabilityStatus SovereignObservability::GetStatus() const {
    std::lock_guard<std::mutex> lock(init_mutex_);
    
    ObservabilityStatus status{};
    status.initialized = initialized_;
    
    if (initialized_) {
        // These are approximate - in production would be more accurate
        status.monitoring_active = health_->IsMonitoring();
        status.exporter_running = exporter_->IsRunning();
    }
    
    return status;
}

// ============================================================================
// Built-in Metrics Implementation
// ============================================================================

void BuiltInMetrics::RegisterAll(MetricCollector& collector) {
    // System metrics
    {
        MetricDefinition def;
        def.name = CPU_USAGE;
        def.description = "CPU usage percentage";
        def.type = MetricType::GAUGE;
        def.unit = MetricUnit::PERCENT;
        collector.RegisterMetric(def);
    }
    
    {
        MetricDefinition def;
        def.name = MEMORY_USAGE;
        def.description = "Memory usage in bytes";
        def.type = MetricType::GAUGE;
        def.unit = MetricUnit::BYTES;
        collector.RegisterMetric(def);
    }
    
    // Inference metrics
    {
        MetricDefinition def;
        def.name = INFERENCE_REQUESTS;
        def.description = "Total inference requests";
        def.type = MetricType::COUNTER;
        def.unit = MetricUnit::COUNT;
        def.label_names = {"model", "status"};
        collector.RegisterMetric(def);
    }
    
    {
        MetricDefinition def;
        def.name = INFERENCE_LATENCY;
        def.description = "Inference latency";
        def.type = MetricType::HISTOGRAM;
        def.unit = MetricUnit::SECONDS;
        def.buckets = {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0};
        collector.RegisterMetric(def);
    }
    
    // Agent metrics
    {
        MetricDefinition def;
        def.name = AGENTS_ACTIVE;
        def.description = "Number of active agents";
        def.type = MetricType::GAUGE;
        def.unit = MetricUnit::COUNT;
        collector.RegisterMetric(def);
    }
    
    {
        MetricDefinition def;
        def.name = AGENTS_CREATED;
        def.description = "Total agents created";
        def.type = MetricType::COUNTER;
        def.unit = MetricUnit::COUNT;
        collector.RegisterMetric(def);
    }
    
    // Swarm metrics
    {
        MetricDefinition def;
        def.name = SWARMS_ACTIVE;
        def.description = "Number of active swarms";
        def.type = MetricType::GAUGE;
        def.unit = MetricUnit::COUNT;
        collector.RegisterMetric(def);
    }
    
    // Runtime metrics
    {
        MetricDefinition def;
        def.name = UPTIME;
        def.description = "System uptime in seconds";
        def.type = MetricType::COUNTER;
        def.unit = MetricUnit::SECONDS;
        collector.RegisterMetric(def);
    }
}

} // namespace Sovereign
