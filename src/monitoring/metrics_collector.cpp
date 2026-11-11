// RawrXD Metrics Collector Implementation
// Phase AH: Monitoring & Observability

#include "metrics_collector.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <math>

// Platform-specific includes for system metrics
#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace rawrxd {
namespace monitoring {

// Global metrics collector instance
static std::unique_ptr<MetricsCollector> g_metrics_collector;

MetricsCollector* getMetricsCollector() {
    return g_metrics_collector.get();
}

void setMetricsCollector(std::unique_ptr<MetricsCollector> collector) {
    g_metrics_collector = std::move(collector);
}

// MetricsCollector implementation
MetricsCollector::MetricsCollector() 
    : collection_running_(false) {
}

MetricsCollector::~MetricsCollector() {
    stopCollection();
}

bool MetricsCollector::initialize(const std::string& config_path) {
    // Register default metrics
    registerMetric(Metric("rawrxd_requests_total", "Total number of requests", MetricType::COUNTER));
    registerMetric(Metric("rawrxd_requests_failed", "Number of failed requests", MetricType::COUNTER));
    registerMetric(Metric("rawrxd_request_latency_ms", "Request latency in milliseconds", MetricType::HISTOGRAM));
    registerMetric(Metric("rawrxd_tokens_generated", "Total tokens generated", MetricType::COUNTER));
    registerMetric(Metric("rawrxd_tokens_per_second", "Tokens per second", MetricType::GAUGE));
    registerMetric(Metric("rawrxd_memory_usage_bytes", "Memory usage in bytes", MetricType::GAUGE));
    registerMetric(Metric("rawrxd_cpu_usage_percent", "CPU usage percentage", MetricType::GAUGE));
    registerMetric(Metric("rawrxd_gpu_utilization_percent", "GPU utilization percentage", MetricType::GAUGE));
    registerMetric(Metric("rawrxd_gpu_memory_bytes", "GPU memory usage in bytes", MetricType::GAUGE));
    registerMetric(Metric("rawrxd_active_requests", "Number of active requests", MetricType::GAUGE));
    
    return true;
}

void MetricsCollector::registerMetric(const Metric& metric) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_[metric.name] = metric;
}

void MetricsCollector::unregisterMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_.erase(name);
}

void MetricsCollector::incrementCounter(const std::string& name, double value,
                                        const std::unordered_map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        // Auto-register counter if not exists
        metrics_[name] = Metric(name, "Auto-registered counter", MetricType::COUNTER);
        it = metrics_.find(name);
    }
    
    MetricValue mv(value);
    mv.labels = labels;
    it->second.values.push_back(mv);
    
    if (callback_) {
        callback_(it->second);
    }
}

void MetricsCollector::setGauge(const std::string& name, double value,
                                const std::unordered_map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        // Auto-register gauge if not exists
        metrics_[name] = Metric(name, "Auto-registered gauge", MetricType::GAUGE);
        it = metrics_.find(name);
    }
    
    // For gauges, we typically keep only the latest value per label set
    // Remove old values with same labels
    it->second.values.erase(
        std::remove_if(it->second.values.begin(), it->second.values.end(),
            [&labels](const MetricValue& mv) {
                return mv.labels == labels;
            }),
        it->second.values.end()
    );
    
    MetricValue mv(value);
    mv.labels = labels;
    it->second.values.push_back(mv);
    
    if (callback_) {
        callback_(it->second);
    }
}

void MetricsCollector::observeHistogram(const std::string& name, double value,
                                          const std::unordered_map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = metrics_.find(name);
    if (it == metrics_.end()) {
        // Auto-register histogram if not exists
        metrics_[name] = Metric(name, "Auto-registered histogram", MetricType::HISTOGRAM);
        it = metrics_.find(name);
    }
    
    MetricValue mv(value);
    mv.labels = labels;
    it->second.values.push_back(mv);
    
    if (callback_) {
        callback_(it->second);
    }
}

SystemMetrics MetricsCollector::collectSystemMetrics() {
    SystemMetrics metrics;
    
#ifdef _WIN32
    // Windows-specific implementation
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    
    metrics.memory_total_bytes = memInfo.ullTotalPhys;
    metrics.memory_free_bytes = memInfo.ullAvailPhys;
    metrics.memory_used_bytes = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
    metrics.memory_usage_percent = memInfo.dwMemoryLoad;
    
    // Get process memory info
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        metrics.process_memory_rss = pmc.WorkingSetSize;
        metrics.process_memory_vms = pmc.PagefileUsage;
    }
#else
    // Linux/Unix implementation
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        metrics.cpu_user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
        metrics.cpu_system_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
    }
    
    // Memory info from /proc
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal:") == 0) {
                sscanf(line.c_str(), "MemTotal: %lu", &metrics.memory_total_bytes);
                metrics.memory_total_bytes *= 1024; // Convert from KB
            } else if (line.find("MemAvailable:") == 0) {
                sscanf(line.c_str(), "MemAvailable: %lu", &metrics.memory_free_bytes);
                metrics.memory_free_bytes *= 1024;
            }
        }
        metrics.memory_used_bytes = metrics.memory_total_bytes - metrics.memory_free_bytes;
        metrics.memory_usage_percent = 100.0 * metrics.memory_used_bytes / metrics.memory_total_bytes;
    }
#endif
    
    return metrics;
}

void MetricsCollector::recordSystemMetrics() {
    auto sys = collectSystemMetrics();
    
    setGauge("rawrxd_memory_usage_bytes", static_cast<double>(sys.memory_used_bytes));
    setGauge("rawrxd_memory_usage_percent", sys.memory_usage_percent);
    setGauge("rawrxd_cpu_usage_percent", sys.cpu_usage_percent);
}

void MetricsCollector::recordInferenceStart(const std::string& model_name) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    inference_metrics_.requests_total++;
    inference_metrics_.requests_in_flight++;
    inference_metrics_.active_model = model_name;
}

void MetricsCollector::recordInferenceComplete(const std::string& model_name,
                                               std::chrono::milliseconds latency,
                                               uint64_t tokens_generated,
                                               uint64_t tokens_prompt,
                                               bool success) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    inference_metrics_.requests_in_flight--;
    
    if (success) {
        inference_metrics_.requests_successful++;
    } else {
        inference_metrics_.requests_failed++;
    }
    
    inference_metrics_.tokens_generated_total += tokens_generated;
    inference_metrics_.tokens_prompt_total += tokens_prompt;
    
    // Update latency statistics
    double latency_ms = latency.count();
    
    // Simple running average
    size_t n = inference_metrics_.requests_successful;
    inference_metrics_.latency_avg_ms = 
        (inference_metrics_.latency_avg_ms * (n - 1) + latency_ms) / n;
    
    // Record histogram
    observeHistogram("rawrxd_request_latency_ms", latency_ms, {{"model", model_name}});
    
    // Update throughput
    auto now = std::chrono::system_clock::now();
    static auto last_time = now;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_time).count();
    
    if (elapsed > 0) {
        inference_metrics_.tokens_per_second = 
            static_cast<double>(tokens_generated) / elapsed;
        inference_metrics_.requests_per_second = 
            static_cast<double>(inference_metrics_.requests_successful) / elapsed;
    }
    
    // Update gauges
    setGauge("rawrxd_tokens_per_second", inference_metrics_.tokens_per_second);
    setGauge("rawrxd_active_requests", static_cast<double>(inference_metrics_.requests_in_flight));
    
    // Increment counters
    incrementCounter("rawrxd_requests_total", 1, {{"model", model_name}, {"status", success ? "success" : "failure"}});
    incrementCounter("rawrxd_tokens_generated", static_cast<double>(tokens_generated), {{"model", model_name}});
}

InferenceMetrics MetricsCollector::getInferenceMetrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return inference_metrics_;
}

std::vector<GPUMetrics> MetricsCollector::collectGPUMetrics() {
    std::vector<GPUMetrics> gpu_metrics;
    
    // This would integrate with CUDA/NVML for NVIDIA GPUs
    // For now, return empty vector
    
    return gpu_metrics;
}

void MetricsCollector::recordGPUMetrics() {
    auto gpus = collectGPUMetrics();
    
    for (const auto& gpu : gpus) {
        std::unordered_map<std::string, std::string> labels = {
            {"device", std::to_string(gpu.device_id)},
            {"name", gpu.device_name}
        };
        
        setGauge("rawrxd_gpu_utilization_percent", gpu.gpu_utilization_percent, labels);
        setGauge("rawrxd_gpu_memory_bytes", static_cast<double>(gpu.memory_used_bytes), labels);
        setGauge("rawrxd_gpu_temperature_celsius", gpu.temperature_celsius, labels);
        setGauge("rawrxd_gpu_power_watts", gpu.power_draw_watts, labels);
    }
}

Metric MetricsCollector::getMetric(const std::string& name) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = metrics_.find(name);
    if (it != metrics_.end()) {
        return it->second;
    }
    
    return Metric();
}

std::vector<Metric> MetricsCollector::getAllMetrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::vector<Metric> result;
    for (const auto& [name, metric] : metrics_) {
        result.push_back(metric);
    }
    return result;
}

std::vector<Metric> MetricsCollector::getMetricsByType(MetricType type) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::vector<Metric> result;
    for (const auto& [name, metric] : metrics_) {
        if (metric.type == type) {
            result.push_back(metric);
        }
    }
    return result;
}

std::string MetricsCollector::exportPrometheus() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::stringstream ss;
    
    for (const auto& [name, metric] : metrics_) {
        // Write HELP and TYPE
        ss << "# HELP " << name << " " << metric.description << "\n";
        ss << "# TYPE " << name << " ";
        
        switch (metric.type) {
            case MetricType::COUNTER:
                ss << "counter";
                break;
            case MetricType::GAUGE:
                ss << "gauge";
                break;
            case MetricType::HISTOGRAM:
                ss << "histogram";
                break;
            case MetricType::SUMMARY:
                ss << "summary";
                break;
        }
        ss << "\n";
        
        // Write values
        for (const auto& value : metric.values) {
            ss << name;
            
            // Write labels
            if (!value.labels.empty()) {
                ss << "{";
                bool first = true;
                for (const auto& [k, v] : value.labels) {
                    if (!first) ss << ",";
                    ss << k << "=\"" << v << "\"";
                    first = false;
                }
                ss << "}";
            }
            
            ss << " " << value.value << "\n";
        }
        
        ss << "\n";
    }
    
    return ss.str();
}

std::string MetricsCollector::exportJSON() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"metrics\": [\n";
    
    bool first_metric = true;
    for (const auto& [name, metric] : metrics_) {
        if (!first_metric) ss << ",\n";
        first_metric = false;
        
        ss << "    {\n";
        ss << "      \"name\": \"" << name << "\",\n";
        ss << "      \"description\": \"" << metric.description << "\",\n";
        ss << "      \"type\": \"";
        switch (metric.type) {
            case MetricType::COUNTER: ss << "counter"; break;
            case MetricType::GAUGE: ss << "gauge"; break;
            case MetricType::HISTOGRAM: ss << "histogram"; break;
            case MetricType::SUMMARY: ss << "summary"; break;
        }
        ss << "\",\n";
        ss << "      \"values\": [\n";
        
        bool first_value = true;
        for (const auto& value : metric.values) {
            if (!first_value) ss << ",\n";
            first_value = false;
            
            ss << "        {\n";
            ss << "          \"value\": " << value.value << ",\n";
            ss << "          \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
                value.timestamp.time_since_epoch()).count() << ",\n";
            ss << "          \"labels\": {\n";
            
            bool first_label = true;
            for (const auto& [k, v] : value.labels) {
                if (!first_label) ss << ",\n";
                first_label = false;
                ss << "            \"" << k << "\": \"" << v << "\"";
            }
            ss << "\n          }\n";
            ss << "        }";
        }
        
        ss << "\n      ]\n";
        ss << "    }";
    }
    
    ss << "\n  ]\n";
    ss << "}\n";
    
    return ss.str();
}

std::string MetricsCollector::exportCSV() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::stringstream ss;
    ss << "name,description,type,value,timestamp,labels\n";
    
    for (const auto& [name, metric] : metrics_) {
        for (const auto& value : metric.values) {
            ss << name << ",";
            ss << "\"" << metric.description << "\",";
            
            switch (metric.type) {
                case MetricType::COUNTER: ss << "counter,"; break;
                case MetricType::GAUGE: ss << "gauge,"; break;
                case MetricType::HISTOGRAM: ss << "histogram,"; break;
                case MetricType::SUMMARY: ss << "summary,"; break;
            }
            
            ss << value.value << ",";
            ss << std::chrono::duration_cast<std::chrono::seconds>(
                value.timestamp.time_since_epoch()).count() << ",";
            
            // Labels as JSON string
            ss << "\"{";
            bool first = true;
            for (const auto& [k, v] : value.labels) {
                if (!first) ss << ";";
                ss << "\"" << k << "\":\"" << v << "\"";
                first = false;
            }
            ss << "}\"\n";
        }
    }
    
    return ss.str();
}

void MetricsCollector::addAlertConfig(const AlertConfig& config) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    alert_configs_[config.name] = config;
}

void MetricsCollector::removeAlertConfig(const std::string& name) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    alert_configs_.erase(name);
}

void MetricsCollector::checkAlerts() {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    
    for (const auto& [name, config] : alert_configs_) {
        if (!config.enabled) continue;
        
        // Get current metric value
        auto metric = getMetric(config.metric_name);
        if (metric.values.empty()) continue;
        
        double current_value = metric.values.back().value;
        bool triggered = false;
        
        if (config.condition == "gt" && current_value > config.threshold) {
            triggered = true;
        } else if (config.condition == "lt" && current_value < config.threshold) {
            triggered = true;
        } else if (config.condition == "eq" && current_value == config.threshold) {
            triggered = true;
        }
        
        // Check if alert already active
        auto it = std::find_if(active_alerts_.begin(), active_alerts_.end(),
            [&config](const Alert& a) { return a.config_name == config.name && !a.resolved; });
        
        if (triggered && it == active_alerts_.end()) {
            // Create new alert
            Alert alert;
            alert.id = generateAlertId();
            alert.config_name = config.name;
            alert.severity = config.severity;
            alert.description = config.description;
            alert.value = current_value;
            alert.threshold = config.threshold;
            alert.triggered_at = std::chrono::system_clock::now();
            
            active_alerts_.push_back(alert);
            
            // Notify
            if (alert_manager_) {
                alert_manager_->notify(alert);
            }
        } else if (!triggered && it != active_alerts_.end()) {
            // Resolve alert
            it->resolved = true;
            it->resolved_at = std::chrono::system_clock::now();
            alert_history_.push_back(*it);
        }
    }
}

std::vector<Alert> MetricsCollector::getActiveAlerts() const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    
    std::vector<Alert> result;
    for (const auto& alert : active_alerts_) {
        if (!alert.resolved) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<Alert> MetricsCollector::getAlertHistory() const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    return alert_history_;
}

void MetricsCollector::setMetricsCallback(MetricsCallback callback) {
    callback_ = callback;
}

void MetricsCollector::startCollection(std::chrono::seconds interval) {
    if (collection_running_) return;
    
    collection_running_ = true;
    collection_thread_ = std::thread(&MetricsCollector::collectionLoop, this, interval);
}

void MetricsCollector::stopCollection() {
    collection_running_ = false;
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

void MetricsCollector::collectionLoop(std::chrono::seconds interval) {
    while (collection_running_) {
        recordSystemMetrics();
        recordGPUMetrics();
        checkAlerts();
        
        std::this_thread::sleep_for(interval);
    }
}

std::string MetricsCollector::generateAlertId() {
    static uint64_t counter = 0;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "alert_" + std::to_string(now) + "_" + std::to_string(++counter);
}

// AlertManager implementation
AlertManager::AlertManager() = default;

void AlertManager::addNotificationChannel(const std::string& name,
                                          std::function<void(const Alert&)> callback) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    channels_[name] = callback;
}

void AlertManager::removeNotificationChannel(const std::string& name) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    channels_.erase(name);
}

void AlertManager::notify(const Alert& alert) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    
    for (const auto& [name, callback] : channels_) {
        try {
            callback(alert);
        } catch (...) {
            // Log error but don't stop other notifications
        }
    }
}

} // namespace monitoring
} // namespace rawrxd
