// RawrXD Metrics Collector
// Phase AH: Monitoring & Observability

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <memory>
#include <functional>

namespace rawrxd {
namespace monitoring {

// Metric types
enum class MetricType {
    COUNTER,      // Monotonically increasing value
    GAUGE,        // Value that can go up or down
    HISTOGRAM,    // Distribution of values
    SUMMARY       // Calculated summary statistics
};

// Metric value structure
struct MetricValue {
    double value;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> labels;
    
    MetricValue(double v = 0.0) 
        : value(v)
        , timestamp(std::chrono::system_clock::now()) {}
};

// Metric definition
struct Metric {
    std::string name;
    std::string description;
    MetricType type;
    std::string unit;
    std::vector<std::string> label_names;
    std::vector<MetricValue> values;
    
    Metric() = default;
    Metric(const std::string& n, const std::string& desc, MetricType t, const std::string& u = "")
        : name(n), description(desc), type(t), unit(u) {}
};

// System metrics snapshot
struct SystemMetrics {
    // CPU metrics
    double cpu_usage_percent;
    double cpu_user_time;
    double cpu_system_time;
    uint64_t cpu_context_switches;
    
    // Memory metrics
    uint64_t memory_used_bytes;
    uint64_t memory_free_bytes;
    uint64_t memory_total_bytes;
    double memory_usage_percent;
    
    // Disk metrics
    uint64_t disk_read_bytes;
    uint64_t disk_write_bytes;
    uint64_t disk_read_ops;
    uint64_t disk_write_ops;
    
    // Network metrics
    uint64_t network_rx_bytes;
    uint64_t network_tx_bytes;
    uint64_t network_rx_packets;
    uint64_t network_tx_packets;
    
    // Process metrics
    uint32_t process_threads;
    uint64_t process_memory_rss;
    uint64_t process_memory_vms;
    double process_cpu_percent;
    
    std::chrono::system_clock::time_point timestamp;
    
    SystemMetrics() : timestamp(std::chrono::system_clock::now()) {}
};

// Inference metrics
struct InferenceMetrics {
    // Request metrics
    uint64_t requests_total;
    uint64_t requests_successful;
    uint64_t requests_failed;
    uint64_t requests_in_flight;
    
    // Latency metrics (in milliseconds)
    double latency_avg_ms;
    double latency_p50_ms;
    double latency_p95_ms;
    double latency_p99_ms;
    double latency_max_ms;
    
    // Throughput metrics
    double tokens_per_second;
    double requests_per_second;
    
    // Token metrics
    uint64_t tokens_generated_total;
    uint64_t tokens_prompt_total;
    double tokens_avg_per_request;
    
    // Model metrics
    std::string active_model;
    uint64_t model_load_time_ms;
    uint64_t model_memory_bytes;
    
    std::chrono::system_clock::time_point timestamp;
    
    InferenceMetrics() 
        : requests_total(0)
        , requests_successful(0)
        , requests_failed(0)
        , requests_in_flight(0)
        , latency_avg_ms(0)
        , latency_p50_ms(0)
        , latency_p95_ms(0)
        , latency_p99_ms(0)
        , latency_max_ms(0)
        , tokens_per_second(0)
        , requests_per_second(0)
        , tokens_generated_total(0)
        , tokens_prompt_total(0)
        , tokens_avg_per_request(0)
        , model_load_time_ms(0)
        , model_memory_bytes(0)
        , timestamp(std::chrono::system_clock::now()) {}
};

// GPU metrics
struct GPUMetrics {
    int device_id;
    std::string device_name;
    
    // Utilization
    double gpu_utilization_percent;
    double memory_utilization_percent;
    
    // Memory
    uint64_t memory_total_bytes;
    uint64_t memory_used_bytes;
    uint64_t memory_free_bytes;
    
    // Temperature and power
    double temperature_celsius;
    double power_draw_watts;
    double power_limit_watts;
    
    // Clocks
    uint32_t graphics_clock_mhz;
    uint32_t memory_clock_mhz;
    
    // Processes
    std::vector<std::string> compute_processes;
    
    std::chrono::system_clock::time_point timestamp;
    
    GPUMetrics() 
        : device_id(-1)
        , gpu_utilization_percent(0)
        , memory_utilization_percent(0)
        , memory_total_bytes(0)
        , memory_used_bytes(0)
        , memory_free_bytes(0)
        , temperature_celsius(0)
        , power_draw_watts(0)
        , power_limit_watts(0)
        , graphics_clock_mhz(0)
        , memory_clock_mhz(0)
        , timestamp(std::chrono::system_clock::now()) {}
};

// Alert configuration
struct AlertConfig {
    std::string name;
    std::string metric_name;
    std::string condition;  // "gt", "lt", "eq"
    double threshold;
    std::chrono::seconds duration;
    std::string severity;   // "warning", "critical"
    std::string description;
    bool enabled;
    
    AlertConfig() : threshold(0), duration(std::chrono::seconds(60)), enabled(true) {}
};

// Alert instance
struct Alert {
    std::string id;
    std::string config_name;
    std::string severity;
    std::string description;
    double value;
    double threshold;
    std::chrono::system_clock::time_point triggered_at;
    std::chrono::system_clock::time_point resolved_at;
    bool resolved;
    
    Alert() : value(0), threshold(0), resolved(false) {}
};

// Forward declarations
class MetricsExporter;
class AlertManager;

/**
 * MetricsCollector - Central metrics collection and management
 */
class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector();
    
    // Initialize collector
    bool initialize(const std::string& config_path = "");
    
    // Metric registration
    void registerMetric(const Metric& metric);
    void unregisterMetric(const std::string& name);
    
    // Metric updates
    void incrementCounter(const std::string& name, double value = 1.0, 
                          const std::unordered_map<std::string, std::string>& labels = {});
    void setGauge(const std::string& name, double value,
                  const std::unordered_map<std::string, std::string>& labels = {});
    void observeHistogram(const std::string& name, double value,
                          const std::unordered_map<std::string, std::string>& labels = {});
    
    // System metrics
    SystemMetrics collectSystemMetrics();
    void recordSystemMetrics();
    
    // Inference metrics
    void recordInferenceStart(const std::string& model_name);
    void recordInferenceComplete(const std::string& model_name, 
                                   std::chrono::milliseconds latency,
                                   uint64_t tokens_generated,
                                   uint64_t tokens_prompt,
                                   bool success);
    InferenceMetrics getInferenceMetrics();
    
    // GPU metrics
    std::vector<GPUMetrics> collectGPUMetrics();
    void recordGPUMetrics();
    
    // Metric retrieval
    Metric getMetric(const std::string& name) const;
    std::vector<Metric> getAllMetrics() const;
    std::vector<Metric> getMetricsByType(MetricType type) const;
    
    // Export formats
    std::string exportPrometheus() const;
    std::string exportJSON() const;
    std::string exportCSV() const;
    
    // Alert management
    void addAlertConfig(const AlertConfig& config);
    void removeAlertConfig(const std::string& name);
    void checkAlerts();
    std::vector<Alert> getActiveAlerts() const;
    std::vector<Alert> getAlertHistory() const;
    
    // Callbacks
    using MetricsCallback = std::function<void(const Metric&)>;
    void setMetricsCallback(MetricsCallback callback);
    
    // Background collection
    void startCollection(std::chrono::seconds interval);
    void stopCollection();
    
private:
    std::unordered_map<std::string, Metric> metrics_;
    std::unordered_map<std::string, AlertConfig> alert_configs_;
    std::vector<Alert> active_alerts_;
    std::vector<Alert> alert_history_;
    
    InferenceMetrics inference_metrics_;
    mutable std::mutex metrics_mutex_;
    mutable std::mutex alerts_mutex_;
    
    std::unique_ptr<MetricsExporter> exporter_;
    std::unique_ptr<AlertManager> alert_manager_;
    
    MetricsCallback callback_;
    bool collection_running_;
    std::thread collection_thread_;
    
    // Internal helpers
    void collectionLoop(std::chrono::seconds interval);
    std::string generateAlertId();
};

/**
 * MetricsExporter - Export metrics to various backends
 */
class MetricsExporter {
public:
    virtual ~MetricsExporter() = default;
    virtual bool exportMetrics(const std::vector<Metric>& metrics) = 0;
    virtual std::string getName() const = 0;
};

/**
 * PrometheusExporter - Prometheus metrics export
 */
class PrometheusExporter : public MetricsExporter {
public:
    PrometheusExporter(const std::string& endpoint);
    bool exportMetrics(const std::vector<Metric>& metrics) override;
    std::string getName() const override { return "prometheus"; }
    
private:
    std::string endpoint_;
};

/**
 * InfluxDBExporter - InfluxDB metrics export
 */
class InfluxDBExporter : public MetricsExporter {
public:
    InfluxDBExporter(const std::string& url, const std::string& database);
    bool exportMetrics(const std::vector<Metric>& metrics) override;
    std::string getName() const override { return "influxdb"; }
    
private:
    std::string url_;
    std::string database_;
};

/**
 * AlertManager - Alert management and notification
 */
class AlertManager {
public:
    AlertManager();
    
    void addNotificationChannel(const std::string& name, 
                                std::function<void(const Alert&)> callback);
    void removeNotificationChannel(const std::string& name);
    void notify(const Alert& alert);
    
private:
    std::unordered_map<std::string, std::function<void(const Alert&)>> channels_;
    std::mutex channels_mutex_;
};

// Global metrics collector accessor
MetricsCollector* getMetricsCollector();
void setMetricsCollector(std::unique_ptr<MetricsCollector> collector);

// Convenience macros for metric recording
#define RAWRXD_COUNTER(name, value, ...) \
    do { \
        auto collector = rawrxd::monitoring::getMetricsCollector(); \
        if (collector) collector->incrementCounter(name, value, ##__VA_ARGS__); \
    } while(0)

#define RAWRXD_GAUGE(name, value, ...) \
    do { \
        auto collector = rawrxd::monitoring::getMetricsCollector(); \
        if (collector) collector->setGauge(name, value, ##__VA_ARGS__); \
    } while(0)

#define RAWRXD_HISTOGRAM(name, value, ...) \
    do { \
        auto collector = rawrxd::monitoring::getMetricsCollector(); \
        if (collector) collector->observeHistogram(name, value, ##__VA_ARGS__); \
    } while(0)

} // namespace monitoring
} // namespace rawrxd
