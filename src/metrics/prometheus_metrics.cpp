// RawrXD Prometheus Metrics
// Phase 9 - Task 17: Prometheus Metrics

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <iomanip>

// Metric types
enum MetricType {
    METRIC_COUNTER,
    METRIC_GAUGE,
    METRIC_HISTOGRAM,
    METRIC_SUMMARY
};

// Metric label
struct MetricLabel {
    std::string name;
    std::string value;
};

// Metric value
struct MetricValue {
    double value;
    uint64_t timestamp;
    std::vector<MetricLabel> labels;
};

// Metric definition
struct Metric {
    std::string name;
    std::string help;
    MetricType type;
    std::vector<MetricValue> values;
    std::mutex mutex;
};

// Histogram bucket
struct HistogramBucket {
    double upperBound;
    uint64_t count;
};

// Prometheus metrics exporter
class PrometheusExporter {
private:
    std::map<std::string, Metric> metrics;
    std::mutex metricsMutex;
    std::string namespace_;
    
public:
    PrometheusExporter() : namespace_("rawrxd") {}
    
    bool Initialize(const std::string& ns) {
        namespace_ = ns;
        
        // Register default metrics
        RegisterCounter("requests_total", "Total number of requests");
        RegisterCounter("tokens_generated_total", "Total number of tokens generated");
        RegisterGauge("active_requests", "Number of active requests");
        RegisterGauge("memory_usage_bytes", "Memory usage in bytes");
        RegisterHistogram("request_duration_seconds", "Request duration in seconds",
                         {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0});
        RegisterGauge("queue_depth", "Current queue depth");
        RegisterCounter("errors_total", "Total number of errors");
        
        printf("Prometheus metrics initialized\n");
        return true;
    }
    
    // Register counter metric
    void RegisterCounter(const std::string& name, const std::string& help) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        Metric metric;
        metric.name = namespace_ + "_" + name;
        metric.help = help;
        metric.type = METRIC_COUNTER;
        
        metrics[name] = metric;
    }
    
    // Register gauge metric
    void RegisterGauge(const std::string& name, const std::string& help) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        Metric metric;
        metric.name = namespace_ + "_" + name;
        metric.help = help;
        metric.type = METRIC_GAUGE;
        
        metrics[name] = metric;
    }
    
    // Register histogram metric
    void RegisterHistogram(const std::string& name, const std::string& help,
                          const std::vector<double>& buckets) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        Metric metric;
        metric.name = namespace_ + "_" + name;
        metric.help = help;
        metric.type = METRIC_HISTOGRAM;
        
        // Initialize buckets
        for (double bucket : buckets) {
            MetricValue value;
            value.value = 0;
            value.timestamp = GetTickCount64();
            value.labels.push_back({"le", std::to_string(bucket)});
            metric.values.push_back(value);
        }
        
        // Add +Inf bucket
        MetricValue infValue;
        infValue.value = 0;
        infValue.timestamp = GetTickCount64();
        infValue.labels.push_back({"le", "+Inf"});
        metric.values.push_back(infValue);
        
        metrics[name] = metric;
    }
    
    // Increment counter
    void IncrementCounter(const std::string& name, double value = 1.0,
                         const std::vector<MetricLabel>& labels = {}) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        auto it = metrics.find(name);
        if (it == metrics.end()) return;
        
        std::lock_guard<std::mutex> metricLock(it->second.mutex);
        
        // Find or create value with matching labels
        bool found = false;
        for (auto& val : it->second.values) {
            if (LabelsMatch(val.labels, labels)) {
                val.value += value;
                val.timestamp = GetTickCount64();
                found = true;
                break;
            }
        }
        
        if (!found) {
            MetricValue newValue;
            newValue.value = value;
            newValue.timestamp = GetTickCount64();
            newValue.labels = labels;
            it->second.values.push_back(newValue);
        }
    }
    
    // Set gauge value
    void SetGauge(const std::string& name, double value,
                 const std::vector<MetricLabel>& labels = {}) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        auto it = metrics.find(name);
        if (it == metrics.end()) return;
        
        std::lock_guard<std::mutex> metricLock(it->second.mutex);
        
        // Find or create value with matching labels
        bool found = false;
        for (auto& val : it->second.values) {
            if (LabelsMatch(val.labels, labels)) {
                val.value = value;
                val.timestamp = GetTickCount64();
                found = true;
                break;
            }
        }
        
        if (!found) {
            MetricValue newValue;
            newValue.value = value;
            newValue.timestamp = GetTickCount64();
            newValue.labels = labels;
            it->second.values.push_back(newValue);
        }
    }
    
    // Observe histogram value
    void ObserveHistogram(const std::string& name, double value,
                         const std::vector<MetricLabel>& labels = {}) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        auto it = metrics.find(name);
        if (it == metrics.end()) return;
        
        std::lock_guard<std::mutex> metricLock(it->second.mutex);
        
        // Increment all buckets where value <= upper bound
        for (auto& val : it->second.values) {
            for (const auto& label : val.labels) {
                if (label.name == "le") {
                    double upperBound = (label.value == "+Inf") ? 
                                       INFINITY : std::stod(label.value);
                    if (value <= upperBound) {
                        val.value++;
                    }
                    break;
                }
            }
        }
        
        // Update sum and count
        // (simplified - would track separately in production)
    }
    
    // Export metrics in Prometheus format
    std::string ExportMetrics() {
        std::lock_guard<std::mutex> lock(metricsMutex);
        
        std::stringstream output;
        
        for (auto& pair : metrics) {
            Metric& metric = pair.second;
            std::lock_guard<std::mutex> metricLock(metric.mutex);
            
            // Write help text
            output << "# HELP " << metric.name << " " << metric.help << "\n";
            
            // Write type
            output << "# TYPE " << metric.name << " ";
            switch (metric.type) {
                case METRIC_COUNTER: output << "counter"; break;
                case METRIC_GAUGE: output << "gauge"; break;
                case METRIC_HISTOGRAM: output << "histogram"; break;
                case METRIC_SUMMARY: output << "summary"; break;
            }
            output << "\n";
            
            // Write values
            for (const auto& value : metric.values) {
                output << metric.name;
                
                // Write labels
                if (!value.labels.empty()) {
                    output << "{";
                    bool first = true;
                    for (const auto& label : value.labels) {
                        if (!first) output << ",";
                        output << label.name << "=\"" << label.value << "\"";
                        first = false;
                    }
                    output << "}";
                }
                
                output << " " << std::fixed << std::setprecision(6) << value.value << "\n";
            }
            
            output << "\n";
        }
        
        return output.str();
    }
    
    // Record inference metrics
    void RecordInference(int tokensGenerated, double latencyMs, bool success) {
        IncrementCounter("requests_total", 1, {{"status", success ? "success" : "error"}});
        IncrementCounter("tokens_generated_total", tokensGenerated);
        ObserveHistogram("request_duration_seconds", latencyMs / 1000.0);
        
        if (!success) {
            IncrementCounter("errors_total", 1);
        }
    }
    
    // Record queue metrics
    void RecordQueueDepth(int depth) {
        SetGauge("queue_depth", depth);
    }
    
    // Record memory metrics
    void RecordMemoryUsage(size_t bytes) {
        SetGauge("memory_usage_bytes", bytes);
    }
    
private:
    bool LabelsMatch(const std::vector<MetricLabel>& a, const std::vector<MetricLabel>& b) {
        if (a.size() != b.size()) return false;
        
        for (size_t i = 0; i < a.size(); i++) {
            if (a[i].name != b[i].name || a[i].value != b[i].value) {
                return false;
            }
        }
        
        return true;
    }
};

// Global instance
static PrometheusExporter g_Prometheus;

// C API
extern "C" {

bool Prometheus_Init(const char* namespace_) {
    return g_Prometheus.Initialize(namespace_);
}

void Prometheus_IncrementCounter(const char* name, double value) {
    g_Prometheus.IncrementCounter(name, value);
}

void Prometheus_SetGauge(const char* name, double value) {
    g_Prometheus.SetGauge(name, value);
}

void Prometheus_ObserveHistogram(const char* name, double value) {
    g_Prometheus.ObserveHistogram(name, value);
}

const char* Prometheus_Export() {
    static std::string metrics;
    metrics = g_Prometheus.ExportMetrics();
    return metrics.c_str();
}

void Prometheus_RecordInference(int tokens, double latencyMs, int success) {
    g_Prometheus.RecordInference(tokens, latencyMs, success != 0);
}

void Prometheus_RecordQueueDepth(int depth) {
    g_Prometheus.RecordQueueDepth(depth);
}

void Prometheus_RecordMemory(size_t bytes) {
    g_Prometheus.RecordMemoryUsage(bytes);
}

} // extern "C"
