/**
 * MetricsCollector.hpp
 *
 * Phase F Batch 1/5: Metrics & Telemetry Collection
 *
 * High-performance metrics collection with multiple export formats.
 * Supports counters, gauges, histograms, and summaries.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <mutex>
#include <memory>
#include <functional>

namespace Telemetry {

// ============================================================================
// Metric Types
// ============================================================================

enum class MetricType {
    COUNTER,    // Monotonically increasing
    GAUGE,      // Can go up or down
    HISTOGRAM,  // Distribution of values
    SUMMARY     // Calculated percentiles
};

std::string MetricTypeToString(MetricType type);

// ============================================================================
// Label Set
// ============================================================================

/**
 * Labels for metric dimensions.
 */
struct LabelSet {
    std::map<std::string, std::string> labels;
    
    void Set(const std::string& name, const std::string& value);
    void Set(const std::string& name, int64_t value);
    std::string Get(const std::string& name) const;
    bool Has(const std::string& name) const;
    void Remove(const std::string& name);
    void Clear();
    
    std::string ToString() const;
    bool operator<(const LabelSet& other) const;
    bool operator==(const LabelSet& other) const;
};

// ============================================================================
// Metric Value
// ============================================================================

/**
 * Base class for metric values.
 */
class MetricValue {
public:
    virtual ~MetricValue() = default;
    virtual MetricType GetType() const = 0;
    virtual std::string Serialize() const = 0;
    virtual uint64_t GetTimestamp() const = 0;
};

// ============================================================================
// Counter
// ============================================================================

/**
 * Monotonically increasing counter.
 */
class Counter : public MetricValue {
public:
    Counter();
    explicit Counter(uint64_t initial);
    
    void Increment();
    void Increment(uint64_t delta);
    void IncrementBy(double delta);
    
    uint64_t GetCount() const;
    double GetValue() const;
    
    MetricType GetType() const override { return MetricType::COUNTER; }
    std::string Serialize() const override;
    uint64_t GetTimestamp() const override;
    
private:
    std::atomic<uint64_t> count_{0};
    std::atomic<double> value_{0.0};
    uint64_t timestamp_;
};

// ============================================================================
// Gauge
// ============================================================================

/**
 * Gauge that can go up or down.
 */
class Gauge : public MetricValue {
public:
    Gauge();
    explicit Gauge(double initial);
    
    void Set(double value);
    void Increment();
    void Increment(double delta);
    void Decrement();
    void Decrement(double delta);
    
    double GetValue() const;
    
    MetricType GetType() const override { return MetricType::GAUGE; }
    std::string Serialize() const override;
    uint64_t GetTimestamp() const override;
    
private:
    std::atomic<double> value_{0.0};
    uint64_t timestamp_;
};

// ============================================================================
// Histogram
// ============================================================================

/**
 * Histogram for value distributions.
 */
class Histogram : public MetricValue {
public:
    explicit Histogram(const std::vector<double>& buckets);
    
    void Observe(double value);
    void Observe(double value, uint64_t count);
    
    uint64_t GetCount() const;
    double GetSum() const;
    std::map<double, uint64_t> GetBuckets() const;
    
    MetricType GetType() const override { return MetricType::HISTOGRAM; }
    std::string Serialize() const override;
    uint64_t GetTimestamp() const override;
    
private:
    std::vector<double> bucketBoundaries_;
    std::vector<std::atomic<uint64_t>> bucketCounts_;
    std::atomic<uint64_t> count_{0};
    std::atomic<double> sum_{0.0};
    uint64_t timestamp_;
};

// ============================================================================
// Summary
// ============================================================================

/**
 * Summary with calculated percentiles.
 */
class Summary : public MetricValue {
public:
    struct Quantile {
        double quantile;
        double value;
    };
    
    explicit Summary(const std::vector<double>& quantiles);
    
    void Observe(double value);
    
    std::vector<Quantile> GetQuantiles() const;
    uint64_t GetCount() const;
    double GetSum() const;
    
    MetricType GetType() const override { return MetricType::SUMMARY; }
    std::string Serialize() const override;
    uint64_t GetTimestamp() const override;
    
private:
    std::vector<double> quantiles_;
    std::vector<double> values_;
    mutable std::mutex mutex_;
    std::atomic<uint64_t> count_{0};
    std::atomic<double> sum_{0.0};
    uint64_t timestamp_;
};

// ============================================================================
// Metric Family
// ============================================================================

/**
 * Family of metrics with the same name but different labels.
 */
class MetricFamily {
public:
    MetricFamily(const std::string& name, const std::string& help, MetricType type);
    
    // Access metrics
    Counter* GetCounter(const LabelSet& labels);
    Gauge* GetGauge(const LabelSet& labels);
    Histogram* GetHistogram(const LabelSet& labels);
    Summary* GetSummary(const LabelSet& labels);
    
    // Remove metric
    bool Remove(const LabelSet& labels);
    
    // Query
    std::string GetName() const { return name_; }
    std::string GetHelp() const { return help_; }
    MetricType GetType() const { return type_; }
    std::vector<LabelSet> GetLabelSets() const;
    
    // Serialization
    std::string Serialize() const;
    
private:
    std::string name_;
    std::string help_;
    MetricType type_;
    
    std::map<LabelSet, std::unique_ptr<MetricValue>> metrics_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Metrics Registry
// ============================================================================

/**
 * Central registry for all metrics.
 */
class MetricsRegistry {
public:
    MetricsRegistry();
    ~MetricsRegistry();
    
    // Registration
    Counter* RegisterCounter(const std::string& name, const std::string& help);
    Gauge* RegisterGauge(const std::string& name, const std::string& help);
    Histogram* RegisterHistogram(const std::string& name, const std::string& help,
                                  const std::vector<double>& buckets);
    Summary* RegisterSummary(const std::string& name, const std::string& help,
                               const std::vector<double>& quantiles);
    
    // Access
    MetricFamily* GetFamily(const std::string& name);
    std::vector<std::string> GetFamilyNames() const;
    
    // Unregister
    bool Unregister(const std::string& name);
    void Clear();
    
    // Export
    std::string ExportPrometheus() const;
    std::string ExportJson() const;
    std::string ExportOpenMetrics() const;
    
private:
    std::map<std::string, std::unique_ptr<MetricFamily>> families_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Metrics Collector
// ============================================================================

/**
 * High-performance metrics collector with batching.
 */
class MetricsCollector {
public:
    struct Config {
        uint64_t flushIntervalMs = 60000;      // Flush interval
        size_t maxBatchSize = 1000;            // Max metrics per batch
        bool enableCompression = true;         // Compress exports
        std::string defaultLabels;               // Default labels
    };
    
    explicit MetricsCollector(const Config& config = Config{});
    ~MetricsCollector();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Get registry
    MetricsRegistry* GetRegistry();
    
    // Quick access methods
    Counter* Counter(const std::string& name, const std::string& help);
    Gauge* Gauge(const std::string& name, const std::string& help);
    Histogram* Histogram(const std::string& name, const std::string& help,
                         const std::vector<double>& buckets);
    Summary* Summary(const std::string& name, const std::string& help,
                     const std::vector<double>& quantiles);
    
    // Collection control
    void StartCollection();
    void StopCollection();
    void Flush();
    
    // Export handlers
    using ExportHandler = std::function<void(const std::string& data)>;
    void AddExportHandler(ExportHandler handler);
    void RemoveExportHandler(ExportHandler handler);
    
    // Built-in exporters
    void EnablePrometheusEndpoint(uint16_t port);
    void EnableFileExport(const std::string& path);
    void EnableRemoteExport(const std::string& endpoint);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    std::unique_ptr<MetricsRegistry> registry_;
    
    std::vector<ExportHandler> handlers_;
    mutable std::mutex handlerMutex_;
    
    std::atomic<bool> running_{false};
    std::thread collectionThread_;
    
    // Collection loop
    void CollectionLoop();
    void ExportMetrics();
};

// ============================================================================
// System Metrics
// ============================================================================

/**
 * Pre-defined system metrics.
 */
class SystemMetrics {
public:
    static void RegisterAll(MetricsRegistry* registry);
    
    // CPU metrics
    static void RegisterCPUMetrics(MetricsRegistry* registry);
    
    // Memory metrics
    static void RegisterMemoryMetrics(MetricsRegistry* registry);
    
    // Disk metrics
    static void RegisterDiskMetrics(MetricsRegistry* registry);
    
    // Network metrics
    static void RegisterNetworkMetrics(MetricsRegistry* registry);
    
    // Process metrics
    static void RegisterProcessMetrics(MetricsRegistry* registry);
    
    // Update all
    static void UpdateAll();
};

// ============================================================================
// Application Metrics
// ============================================================================

/**
 * Pre-defined application metrics.
 */
class ApplicationMetrics {
public:
    static void RegisterAll(MetricsRegistry* registry);
    
    // Request metrics
    static void RegisterRequestMetrics(MetricsRegistry* registry);
    
    // Queue metrics
    static void RegisterQueueMetrics(MetricsRegistry* registry);
    
    // Cache metrics
    static void RegisterCacheMetrics(MetricsRegistry* registry);
    
    // Database metrics
    static void RegisterDatabaseMetrics(MetricsRegistry* registry);
    
    // Update all
    static void UpdateAll();
};

// ============================================================================
// Distributed Metrics
// ============================================================================

/**
 * Metrics for distributed systems.
 */
class DistributedMetrics {
public:
    static void RegisterAll(MetricsRegistry* registry);
    
    // Node metrics
    static void RegisterNodeMetrics(MetricsRegistry* registry);
    
    // Consensus metrics
    static void RegisterConsensusMetrics(MetricsRegistry* registry);
    
    // Replication metrics
    static void RegisterReplicationMetrics(MetricsRegistry* registry);
    
    // Update all
    static void UpdateAll();
};

} // namespace Telemetry
