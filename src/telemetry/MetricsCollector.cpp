/**
 * MetricsCollector.cpp
 *
 * Phase F Batch 1/5: Metrics & Telemetry Collection
 *
 * Implementation of high-performance metrics collection.
 */

#include "MetricsCollector.hpp"
#include "../core/Logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#else
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace Telemetry {

// ============================================================================
// String Helpers
// ============================================================================

std::string MetricTypeToString(MetricType type) {
    switch (type) {
        case MetricType::COUNTER:   return "counter";
        case MetricType::GAUGE:     return "gauge";
        case MetricType::HISTOGRAM: return "histogram";
        case MetricType::SUMMARY:   return "summary";
        default: return "unknown";
    }
}

// ============================================================================
// LabelSet Implementation
// ============================================================================

void LabelSet::Set(const std::string& name, const std::string& value) {
    labels[name] = value;
}

void LabelSet::Set(const std::string& name, int64_t value) {
    labels[name] = std::to_string(value);
}

std::string LabelSet::Get(const std::string& name) const {
    auto it = labels.find(name);
    return (it != labels.end()) ? it->second : "";
}

bool LabelSet::Has(const std::string& name) const {
    return labels.find(name) != labels.end();
}

void LabelSet::Remove(const std::string& name) {
    labels.erase(name);
}

void LabelSet::Clear() {
    labels.clear();
}

std::string LabelSet::ToString() const {
    std::string result;
    for (const auto& [key, value] : labels) {
        if (!result.empty()) result += ",";
        result += key + "=\"" + value + "\"";
    }
    return result;
}

bool LabelSet::operator<(const LabelSet& other) const {
    return labels < other.labels;
}

bool LabelSet::operator==(const LabelSet& other) const {
    return labels == other.labels;
}

// ============================================================================
// Counter Implementation
// ============================================================================

Counter::Counter() {
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

Counter::Counter(uint64_t initial) : count_(initial) {
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Counter::Increment() {
    count_.fetch_add(1, std::memory_order_relaxed);
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Counter::Increment(uint64_t delta) {
    count_.fetch_add(delta, std::memory_order_relaxed);
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Counter::IncrementBy(double delta) {
    double current = value_.load(std::memory_order_relaxed);
    double newValue;
    do {
        newValue = current + delta;
    } while (!value_.compare_exchange_weak(current, newValue, std::memory_order_relaxed));
    
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

uint64_t Counter::GetCount() const {
    return count_.load(std::memory_order_relaxed);
}

double Counter::GetValue() const {
    return value_.load(std::memory_order_relaxed);
}

std::string Counter::Serialize() const {
    return std::to_string(GetValue());
}

uint64_t Counter::GetTimestamp() const {
    return timestamp_;
}

// ============================================================================
// Gauge Implementation
// ============================================================================

Gauge::Gauge() {
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

Gauge::Gauge(double initial) : value_(initial) {
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Gauge::Set(double value) {
    value_.store(value, std::memory_order_relaxed);
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Gauge::Increment() {
    value_.fetch_add(1.0, std::memory_order_relaxed);
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Gauge::Increment(double delta) {
    double current = value_.load(std::memory_order_relaxed);
    double newValue;
    do {
        newValue = current + delta;
    } while (!value_.compare_exchange_weak(current, newValue, std::memory_order_relaxed));
    
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Gauge::Decrement() {
    value_.fetch_sub(1.0, std::memory_order_relaxed);
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Gauge::Decrement(double delta) {
    double current = value_.load(std::memory_order_relaxed);
    double newValue;
    do {
        newValue = current - delta;
    } while (!value_.compare_exchange_weak(current, newValue, std::memory_order_relaxed));
    
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

double Gauge::GetValue() const {
    return value_.load(std::memory_order_relaxed);
}

std::string Gauge::Serialize() const {
    return std::to_string(GetValue());
}

uint64_t Gauge::GetTimestamp() const {
    return timestamp_;
}

// ============================================================================
// Histogram Implementation
// ============================================================================

Histogram::Histogram(const std::vector<double>& buckets) : bucketBoundaries_(buckets) {
    bucketCounts_.resize(buckets.size() + 1); // +1 for +Inf bucket
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Histogram::Observe(double value) {
    Observe(value, 1);
}

void Histogram::Observe(double value, uint64_t count) {
    // Find bucket
    size_t bucketIndex = bucketBoundaries_.size();
    for (size_t i = 0; i < bucketBoundaries_.size(); ++i) {
        if (value <= bucketBoundaries_[i]) {
            bucketIndex = i;
            break;
        }
    }
    
    bucketCounts_[bucketIndex].fetch_add(count, std::memory_order_relaxed);
    count_.fetch_add(count, std::memory_order_relaxed);
    
    double currentSum = sum_.load(std::memory_order_relaxed);
    double newSum;
    do {
        newSum = currentSum + (value * count);
    } while (!sum_.compare_exchange_weak(currentSum, newSum, std::memory_order_relaxed));
    
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

uint64_t Histogram::GetCount() const {
    return count_.load(std::memory_order_relaxed);
}

double Histogram::GetSum() const {
    return sum_.load(std::memory_order_relaxed);
}

std::map<double, uint64_t> Histogram::GetBuckets() const {
    std::map<double, uint64_t> result;
    for (size_t i = 0; i < bucketBoundaries_.size(); ++i) {
        result[bucketBoundaries_[i]] = bucketCounts_[i].load(std::memory_order_relaxed);
    }
    result[std::numeric_limits<double>::infinity()] = 
        bucketCounts_.back().load(std::memory_order_relaxed);
    return result;
}

std::string Histogram::Serialize() const {
    std::string json = "{";
    json += "\"count\":" + std::to_string(GetCount()) + ",";
    json += "\"sum\":" + std::to_string(GetSum()) + ",";
    json += "\"buckets\":{";
    
    auto buckets = GetBuckets();
    bool first = true;
    for (const auto& [boundary, count] : buckets) {
        if (!first) json += ",";
        first = false;
        if (std::isinf(boundary)) {
            json += "\"+Inf\":" + std::to_string(count);
        } else {
            json += "\"" + std::to_string(boundary) + "\":" + std::to_string(count);
        }
    }
    
    json += "}}";
    return json;
}

uint64_t Histogram::GetTimestamp() const {
    return timestamp_;
}

// ============================================================================
// Summary Implementation
// ============================================================================

Summary::Summary(const std::vector<double>& quantiles) : quantiles_(quantiles) {
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void Summary::Observe(double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    values_.push_back(value);
    
    // Keep only recent values (sliding window)
    if (values_.size() > 10000) {
        values_.erase(values_.begin(), values_.begin() + (values_.size() - 10000));
    }
    
    count_.fetch_add(1, std::memory_order_relaxed);
    
    double currentSum = sum_.load(std::memory_order_relaxed);
    double newSum;
    do {
        newSum = currentSum + value;
    } while (!sum_.compare_exchange_weak(currentSum, newSum, std::memory_order_relaxed));
    
    timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::vector<Summary::Quantile> Summary::GetQuantiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Quantile> result;
    if (values_.empty()) {
        for (double q : quantiles_) {
            result.push_back({q, 0.0});
        }
        return result;
    }
    
    std::vector<double> sorted = values_;
    std::sort(sorted.begin(), sorted.end());
    
    for (double q : quantiles_) {
        size_t index = static_cast<size_t>(q * sorted.size());
        if (index >= sorted.size()) index = sorted.size() - 1;
        result.push_back({q, sorted[index]});
    }
    
    return result;
}

uint64_t Summary::GetCount() const {
    return count_.load(std::memory_order_relaxed);
}

double Summary::GetSum() const {
    return sum_.load(std::memory_order_relaxed);
}

std::string Summary::Serialize() const {
    auto quantiles = GetQuantiles();
    
    std::string json = "{";
    json += "\"count\":" + std::to_string(GetCount()) + ",";
    json += "\"sum\":" + std::to_string(GetSum()) + ",";
    json += "\"quantiles\":{";
    
    bool first = true;
    for (const auto& q : quantiles) {
        if (!first) json += ",";
        first = false;
        json += "\"" + std::to_string(q.quantile) + "\":" + std::to_string(q.value);
    }
    
    json += "}}";
    return json;
}

uint64_t Summary::GetTimestamp() const {
    return timestamp_;
}

// ============================================================================
// MetricFamily Implementation
// ============================================================================

MetricFamily::MetricFamily(const std::string& name, const std::string& help, MetricType type)
    : name_(name), help_(help), type_(type) {}

Counter* MetricFamily::GetCounter(const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(labels);
    if (it != metrics_.end()) {
        return static_cast<Counter*>(it->second.get());
    }
    
    auto counter = std::make_unique<Counter>();
    Counter* ptr = counter.get();
    metrics_[labels] = std::move(counter);
    return ptr;
}

Gauge* MetricFamily::GetGauge(const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(labels);
    if (it != metrics_.end()) {
        return static_cast<Gauge*>(it->second.get());
    }
    
    auto gauge = std::make_unique<Gauge>();
    Gauge* ptr = gauge.get();
    metrics_[labels] = std::move(gauge);
    return ptr;
}

Histogram* MetricFamily::GetHistogram(const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(labels);
    if (it != metrics_.end()) {
        return static_cast<Histogram*>(it->second.get());
    }
    
    // Default buckets
    std::vector<double> buckets = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10};
    auto histogram = std::make_unique<Histogram>(buckets);
    Histogram* ptr = histogram.get();
    metrics_[labels] = std::move(histogram);
    return ptr;
}

Summary* MetricFamily::GetSummary(const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = metrics_.find(labels);
    if (it != metrics_.end()) {
        return static_cast<Summary*>(it->second.get());
    }
    
    // Default quantiles
    std::vector<double> quantiles = {0.5, 0.9, 0.95, 0.99};
    auto summary = std::make_unique<Summary>(quantiles);
    Summary* ptr = summary.get();
    metrics_[labels] = std::move(summary);
    return ptr;
}

bool MetricFamily::Remove(const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_.erase(labels) > 0;
}

std::vector<LabelSet> MetricFamily::GetLabelSets() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LabelSet> result;
    for (const auto& [labels, _] : metrics_) {
        result.push_back(labels);
    }
    return result;
}

std::string MetricFamily::Serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string output;
    
    // HELP line
    output += "# HELP " + name_ + " " + help_ + "\n";
    
    // TYPE line
    output += "# TYPE " + name_ + " " + MetricTypeToString(type_) + "\n";
    
    // Metric lines
    for (const auto& [labels, metric] : metrics_) {
        output += name_;
        
        std::string labelStr = labels.ToString();
        if (!labelStr.empty()) {
            output += "{" + labelStr + "}";
        }
        
        output += " " + metric->Serialize() + "\n";
    }
    
    return output;
}

// ============================================================================
// MetricsRegistry Implementation
// ============================================================================

MetricsRegistry::MetricsRegistry() = default;
MetricsRegistry::~MetricsRegistry() = default;

Counter* MetricsRegistry::RegisterCounter(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = families_.find(name);
    if (it != families_.end()) {
        LabelSet empty;
        return it->second->GetCounter(empty);
    }
    
    auto family = std::make_unique<MetricFamily>(name, help, MetricType::COUNTER);
    Counter* counter = family->GetCounter(LabelSet{});
    families_[name] = std::move(family);
    return counter;
}

Gauge* MetricsRegistry::RegisterGauge(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = families_.find(name);
    if (it != families_.end()) {
        LabelSet empty;
        return it->second->GetGauge(empty);
    }
    
    auto family = std::make_unique<MetricFamily>(name, help, MetricType::GAUGE);
    Gauge* gauge = family->GetGauge(LabelSet{});
    families_[name] = std::move(family);
    return gauge;
}

Histogram* MetricsRegistry::RegisterHistogram(const std::string& name, const std::string& help,
                                               const std::vector<double>& buckets) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = families_.find(name);
    if (it != families_.end()) {
        LabelSet empty;
        return it->second->GetHistogram(empty);
    }
    
    auto family = std::make_unique<MetricFamily>(name, help, MetricType::HISTOGRAM);
    Histogram* histogram = family->GetHistogram(LabelSet{});
    families_[name] = std::move(family);
    return histogram;
}

Summary* MetricsRegistry::RegisterSummary(const std::string& name, const std::string& help,
                                           const std::vector<double>& quantiles) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = families_.find(name);
    if (it != families_.end()) {
        LabelSet empty;
        return it->second->GetSummary(empty);
    }
    
    auto family = std::make_unique<MetricFamily>(name, help, MetricType::SUMMARY);
    Summary* summary = family->GetSummary(LabelSet{});
    families_[name] = std::move(family);
    return summary;
}

MetricFamily* MetricsRegistry::GetFamily(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = families_.find(name);
    if (it != families_.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<std::string> MetricsRegistry::GetFamilyNames() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, _] : families_) {
        result.push_back(name);
    }
    return result;
}

bool MetricsRegistry::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return families_.erase(name) > 0;
}

void MetricsRegistry::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    families_.clear();
}

std::string MetricsRegistry::ExportPrometheus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string output;
    for (const auto& [name, family] : families_) {
        output += family->Serialize();
        output += "\n";
    }
    return output;
}

std::string MetricsRegistry::ExportJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string json = "{";
    bool first = true;
    
    for (const auto& [name, family] : families_) {
        if (!first) json += ",";
        first = false;
        json += "\"" + name + "\":" + family->Serialize();
    }
    
    json += "}";
    return json;
}

std::string MetricsRegistry::ExportOpenMetrics() const {
    // OpenMetrics is similar to Prometheus with some differences
    return ExportPrometheus();
}

// ============================================================================
// MetricsCollector Implementation
// ============================================================================

MetricsCollector::MetricsCollector(const Config& config) : config_(config) {
    registry_ = std::make_unique<MetricsRegistry>();
}

MetricsCollector::~MetricsCollector() {
    Shutdown();
}

bool MetricsCollector::Initialize() {
    LOG_INFO("MetricsCollector initialized");
    return true;
}

void MetricsCollector::Shutdown() {
    StopCollection();
}

MetricsRegistry* MetricsCollector::GetRegistry() {
    return registry_.get();
}

Counter* MetricsCollector::Counter(const std::string& name, const std::string& help) {
    return registry_->RegisterCounter(name, help);
}

Gauge* MetricsCollector::Gauge(const std::string& name, const std::string& help) {
    return registry_->RegisterGauge(name, help);
}

Histogram* MetricsCollector::Histogram(const std::string& name, const std::string& help,
                                        const std::vector<double>& buckets) {
    return registry_->RegisterHistogram(name, help, buckets);
}

Summary* MetricsCollector::Summary(const std::string& name, const std::string& help,
                                    const std::vector<double>& quantiles) {
    return registry_->RegisterSummary(name, help, quantiles);
}

void MetricsCollector::StartCollection() {
    running_ = true;
    collectionThread_ = std::thread(&MetricsCollector::CollectionLoop, this);
}

void MetricsCollector::StopCollection() {
    running_ = false;
    
    if (collectionThread_.joinable()) {
        collectionThread_.join();
    }
}

void MetricsCollector::Flush() {
    ExportMetrics();
}

void MetricsCollector::AddExportHandler(ExportHandler handler) {
    std::lock_guard<std::mutex> lock(handlerMutex_);
    handlers_.push_back(handler);
}

void MetricsCollector::RemoveExportHandler(ExportHandler handler) {
    std::lock_guard<std::mutex> lock(handlerMutex_);
    handlers_.erase(std::remove(handlers_.begin(), handlers_.end(), handler), handlers_.end());
}

void MetricsCollector::EnablePrometheusEndpoint(uint16_t port) {
    // TODO: Implement HTTP server for Prometheus scraping
    LOG_INFO("Prometheus endpoint enabled on port " + std::to_string(port));
}

void MetricsCollector::EnableFileExport(const std::string& path) {
    AddExportHandler([path](const std::string& data) {
        std::ofstream file(path, std::ios::app);
        if (file.is_open()) {
            file << data << std::endl;
            file.close();
        }
    });
}

void MetricsCollector::EnableRemoteExport(const std::string& endpoint) {
    // TODO: Implement remote export via HTTP/gRPC
    LOG_INFO("Remote export enabled to " + endpoint);
}

std::string MetricsCollector::GetStatusJson() const {
    std::string json = "{";
    json += "\"running\":" + std::string(running_ ? "true" : "false") + ",";
    json += "\"families\":" + std::to_string(registry_->GetFamilyNames().size()) + ",";
    json += "\"flushIntervalMs\":" + std::to_string(config_.flushIntervalMs);
    json += "}";
    return json;
}

void MetricsCollector::CollectionLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.flushIntervalMs));
        
        if (!running_) break;
        
        ExportMetrics();
    }
}

void MetricsCollector::ExportMetrics() {
    std::string data = registry_->ExportPrometheus();
    
    std::lock_guard<std::mutex> lock(handlerMutex_);
    for (const auto& handler : handlers_) {
        handler(data);
    }
}

// ============================================================================
// System Metrics Implementation
// ============================================================================

void SystemMetrics::RegisterAll(MetricsRegistry* registry) {
    RegisterCPUMetrics(registry);
    RegisterMemoryMetrics(registry);
    RegisterDiskMetrics(registry);
    RegisterNetworkMetrics(registry);
    RegisterProcessMetrics(registry);
}

void SystemMetrics::RegisterCPUMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("system_cpu_usage_percent", "Current CPU usage percentage");
    registry->RegisterCounter("system_cpu_total_seconds", "Total CPU time in seconds");
    registry->RegisterGauge("system_cpu_load_average", "System load average");
}

void SystemMetrics::RegisterMemoryMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("system_memory_used_bytes", "Used memory in bytes");
    registry->RegisterGauge("system_memory_free_bytes", "Free memory in bytes");
    registry->RegisterGauge("system_memory_total_bytes", "Total memory in bytes");
    registry->RegisterGauge("system_memory_usage_percent", "Memory usage percentage");
}

void SystemMetrics::RegisterDiskMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("system_disk_used_bytes", "Used disk space in bytes");
    registry->RegisterGauge("system_disk_free_bytes", "Free disk space in bytes");
    registry->RegisterGauge("system_disk_total_bytes", "Total disk space in bytes");
    registry->RegisterCounter("system_disk_read_bytes", "Total disk bytes read");
    registry->RegisterCounter("system_disk_write_bytes", "Total disk bytes written");
}

void SystemMetrics::RegisterNetworkMetrics(MetricsRegistry* registry) {
    registry->RegisterCounter("system_network_receive_bytes", "Total network bytes received");
    registry->RegisterCounter("system_network_transmit_bytes", "Total network bytes transmitted");
    registry->RegisterGauge("system_network_connections", "Current network connections");
}

void SystemMetrics::RegisterProcessMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("process_memory_used_bytes", "Process memory usage in bytes");
    registry->RegisterGauge("process_threads", "Number of process threads");
    registry->RegisterCounter("process_cpu_seconds", "Process CPU time in seconds");
    registry->RegisterGauge("process_open_fds", "Number of open file descriptors");
}

void SystemMetrics::UpdateAll() {
    // TODO: Implement system metrics collection
    // This would read from /proc on Linux or use Windows APIs
}

// ============================================================================
// Application Metrics Implementation
// ============================================================================

void ApplicationMetrics::RegisterAll(MetricsRegistry* registry) {
    RegisterRequestMetrics(registry);
    RegisterQueueMetrics(registry);
    RegisterCacheMetrics(registry);
    RegisterDatabaseMetrics(registry);
}

void ApplicationMetrics::RegisterRequestMetrics(MetricsRegistry* registry) {
    registry->RegisterCounter("app_requests_total", "Total number of requests");
    registry->RegisterHistogram("app_request_duration_seconds", "Request duration in seconds",
                                 {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5});
    registry->RegisterCounter("app_request_errors_total", "Total number of request errors");
}

void ApplicationMetrics::RegisterQueueMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("app_queue_size", "Current queue size");
    registry->RegisterCounter("app_queue_enqueued_total", "Total items enqueued");
    registry->RegisterCounter("app_queue_dequeued_total", "Total items dequeued");
    registry->RegisterHistogram("app_queue_wait_seconds", "Time spent waiting in queue");
}

void ApplicationMetrics::RegisterCacheMetrics(MetricsRegistry* registry) {
    registry->RegisterCounter("app_cache_hits_total", "Total cache hits");
    registry->RegisterCounter("app_cache_misses_total", "Total cache misses");
    registry->RegisterGauge("app_cache_size", "Current cache size");
    registry->RegisterGauge("app_cache_hit_ratio", "Cache hit ratio");
}

void ApplicationMetrics::RegisterDatabaseMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("app_db_connections_active", "Active database connections");
    registry->RegisterGauge("app_db_connections_idle", "Idle database connections");
    registry->RegisterHistogram("app_db_query_duration_seconds", "Database query duration");
    registry->RegisterCounter("app_db_queries_total", "Total database queries");
}

void ApplicationMetrics::UpdateAll() {
    // Application-specific metrics are updated by the application code
}

// ============================================================================
// Distributed Metrics Implementation
// ============================================================================

void DistributedMetrics::RegisterAll(MetricsRegistry* registry) {
    RegisterNodeMetrics(registry);
    RegisterConsensusMetrics(registry);
    RegisterReplicationMetrics(registry);
}

void DistributedMetrics::RegisterNodeMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("distributed_nodes_total", "Total number of nodes");
    registry->RegisterGauge("distributed_nodes_healthy", "Number of healthy nodes");
    registry->RegisterGauge("distributed_nodes_unhealthy", "Number of unhealthy nodes");
    registry->RegisterCounter("distributed_node_joins_total", "Total node joins");
    registry->RegisterCounter("distributed_node_leaves_total", "Total node leaves");
}

void DistributedMetrics::RegisterConsensusMetrics(MetricsRegistry* registry) {
    registry->RegisterGauge("consensus_term", "Current consensus term");
    registry->RegisterGauge("consensus_is_leader", "Is this node the leader");
    registry->RegisterCounter("consensus_leader_changes_total", "Total leader changes");
    registry->RegisterHistogram("consensus_commit_latency_seconds", "Commit latency");
}

void DistributedMetrics::RegisterReplicationMetrics(MetricsRegistry* registry) {
    registry->RegisterCounter("replication_messages_total", "Total replication messages");
    registry->RegisterCounter("replication_bytes_total", "Total replication bytes");
    registry->RegisterGauge("replication_lag_bytes", "Replication lag in bytes");
    registry->RegisterHistogram("replication_sync_duration_seconds", "Sync duration");
}

void DistributedMetrics::UpdateAll() {
    // Distributed metrics are updated by the distributed systems code
}

} // namespace Telemetry
