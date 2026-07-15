#include "observability/MetricsCollector.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct MetricData {
    std::string type;
    double value;
    double sum;
    double min;
    double max;
    size_t count;
    std::vector<double> samples;
    int64_t lastUpdated;
};

static std::map<std::string, MetricData> s_metrics;

void MetricsCollector::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_metrics.clear();
        s_initialized = true;
    }
}

void MetricsCollector::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic metric aggregation
    for (auto& [name, data] : s_metrics) {
        if (data.samples.size() > 1000) {
            // Keep only recent samples
            data.samples.erase(data.samples.begin(), data.samples.begin() + 500);
        }
    }
}

bool MetricsCollector::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void MetricsCollector::RecordCounter(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto& data = s_metrics[name];
    data.type = "counter";
    data.value += value;
    data.sum += value;
    data.count++;
    data.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
}

void MetricsCollector::RecordGauge(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto& data = s_metrics[name];
    data.type = "gauge";
    data.value = value;
    data.sum += value;
    data.count++;
    if (data.count == 1) {
        data.min = data.max = value;
    } else {
        if (value < data.min) data.min = value;
        if (value > data.max) data.max = value;
    }
    data.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
}

void MetricsCollector::RecordHistogram(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto& data = s_metrics[name];
    data.type = "histogram";
    data.samples.push_back(value);
    data.sum += value;
    data.count++;
    if (data.count == 1) {
        data.min = data.max = value;
    } else {
        if (value < data.min) data.min = value;
        if (value > data.max) data.max = value;
    }
    data.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
}

void MetricsCollector::RecordTimer(const std::string& name, double duration_ms) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto& data = s_metrics[name];
    data.type = "timer";
    data.samples.push_back(duration_ms);
    data.sum += duration_ms;
    data.count++;
    if (data.count == 1) {
        data.min = data.max = duration_ms;
    } else {
        if (duration_ms < data.min) data.min = duration_ms;
        if (duration_ms > data.max) data.max = duration_ms;
    }
    data.lastUpdated = std::chrono::system_clock::now().time_since_epoch().count();
}

nlohmann::json MetricsCollector::GetMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [name, data] : s_metrics) {
        result[name] = {
            {"type", data.type},
            {"value", data.value},
            {"sum", data.sum},
            {"count", data.count},
            {"min", data.min},
            {"max", data.max},
            {"last_updated", data.lastUpdated}
        };
    }
    return result;
}

nlohmann::json MetricsCollector::GetMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_metrics.find(name);
    if (it != s_metrics.end()) {
        return {
            {"name", name},
            {"type", it->second.type},
            {"value", it->second.value},
            {"sum", it->second.sum},
            {"count", it->second.count},
            {"min", it->second.min},
            {"max", it->second.max}
        };
    }
    return nlohmann::json{};
}

nlohmann::json MetricsCollector::GetMetricsByPrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::object();
    for (const auto& [name, data] : s_metrics) {
        if (name.find(prefix) == 0) {
            result[name] = {
                {"type", data.type},
                {"value", data.value},
                {"count", data.count}
            };
        }
    }
    return result;
}

void MetricsCollector::ResetMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_metrics.erase(name);
}

void MetricsCollector::ResetAllMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_metrics.clear();
}
