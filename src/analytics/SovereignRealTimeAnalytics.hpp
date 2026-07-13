// Phase D.18 Batch 1/5: Real-Time Analytics
// Stream processing and real-time metrics
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Analytics {

// Forward declarations
struct DataStream;
struct MetricWindow;
struct AggregationRule;

// ============================================================================
// Real-Time Analytics Types
// ============================================================================

enum class StreamType {
    METRICS = 0,
    LOGS = 1,
    EVENTS = 2,
    TRACES = 3,
    CUSTOM = 4
};

enum class WindowType {
    TUMBLING = 0,
    SLIDING = 1,
    SESSION = 2,
    GLOBAL = 3
};

enum class AggregationFunction {
    SUM = 0,
    AVG = 1,
    MIN = 2,
    MAX = 3,
    COUNT = 4,
    COUNT_DISTINCT = 5,
    PERCENTILE = 6,
    STD_DEV = 7
};

struct DataPoint {
    std::string metric_name;
    double value;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> tags;
    std::map<std::string, std::any> metadata;
};

struct MetricWindow {
    std::string window_id;
    WindowType type;
    std::chrono::milliseconds duration;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::vector<DataPoint> data_points;
    std::map<std::string, double> aggregations;
    bool is_complete;
};

struct AggregationRule {
    std::string rule_id;
    std::string metric_pattern;
    AggregationFunction function;
    std::chrono::milliseconds window_size;
    std::vector<std::string> group_by_tags;
    std::map<std::string, std::any> parameters;
    bool emit_on_complete;
};

// ============================================================================
// Stream Processor
// ============================================================================

class StreamProcessor {
public:
    struct Config {
        int max_concurrent_streams = 100;
        size_t buffer_size = 10000;
        std::chrono::milliseconds processing_timeout{1000};
        bool enable_backpressure = true;
    };
    
    struct ProcessingResult {
        bool success;
        std::string stream_id;
        int processed_count;
        int dropped_count;
        std::chrono::milliseconds latency;
        std::string error_message;
    };
    
    explicit StreamProcessor(const Config& config);
    ~StreamProcessor();
    
    bool Initialize();
    void Shutdown();
    
    // Stream management
    std::string CreateStream(StreamType type, const std::string& name);
    bool DestroyStream(const std::string& stream_id);
    bool PauseStream(const std::string& stream_id);
    bool ResumeStream(const std::string& stream_id);
    
    // Data ingestion
    bool IngestDataPoint(const std::string& stream_id, const DataPoint& point);
    bool IngestBatch(const std::string& stream_id, const std::vector<DataPoint>& points);
    
    // Processing
    ProcessingResult ProcessStream(const std::string& stream_id);
    void SetProcessingFunction(const std::string& stream_id, 
                                  std::function<DataPoint(const DataPoint&)> func);
    
    // Queries
    std::vector<DataPoint> GetRecentData(const std::string& stream_id, 
                                          std::chrono::seconds window) const;
    std::vector<DataPoint> QueryStream(const std::string& stream_id,
                                        const std::map<std::string, std::string>& filters) const;
    
private:
    Config config_;
    std::map<std::string, std::unique_ptr<DataStream>> streams_;
    mutable std::mutex streams_mutex_;
    std::thread processing_thread_;
    std::atomic<bool> running_{false};
    
    void ProcessingLoop();
    bool ApplyBackpressure(const std::string& stream_id);
};

// ============================================================================
// Window Manager
// ============================================================================

class WindowManager {
public:
    struct Config {
        int max_windows = 1000;
        std::chrono::seconds window_retention{3600};
        bool enable_watermarks = true;
        std::chrono::milliseconds allowed_lateness{0};
    };
    
    explicit WindowManager(const Config& config);
    ~WindowManager();
    
    bool Initialize();
    void Shutdown();
    
    // Window creation
    std::string CreateTumblingWindow(const std::string& stream_id,
                                      std::chrono::milliseconds size);
    std::string CreateSlidingWindow(const std::string& stream_id,
                                     std::chrono::milliseconds size,
                                     std::chrono::milliseconds slide);
    std::string CreateSessionWindow(const std::string& stream_id,
                                     std::chrono::milliseconds gap);
    
    // Window operations
    bool AssignToWindow(const std::string& window_id, const DataPoint& point);
    bool CloseWindow(const std::string& window_id);
    std::optional<MetricWindow> GetWindow(const std::string& window_id) const;
    
    // Aggregation
    bool RegisterAggregationRule(const AggregationRule& rule);
    bool UnregisterAggregationRule(const std::string& rule_id);
    std::vector<MetricWindow> ComputeAggregations(const std::string& stream_id);
    
    // Triggers
    void SetWindowTrigger(const std::string& window_id,
                          std::function<void(const MetricWindow&)> callback);
    
private:
    Config config_;
    std::map<std::string, MetricWindow> windows_;
    std::map<std::string, AggregationRule> rules_;
    mutable std::mutex windows_mutex_;
    std::thread window_thread_;
    std::atomic<bool> running_{false};
    
    void WindowLoop();
    void EvaluateTriggers(const MetricWindow& window);
    std::string GenerateWindowId();
};

// ============================================================================
// Real-Time Metrics Collector
// ============================================================================

class RealTimeMetricsCollector {
public:
    struct Config {
        std::chrono::seconds collection_interval{10};
        size_t max_metrics_per_type = 10000;
        bool enable_histograms = true;
        bool enable_summaries = true;
    };
    
    struct MetricValue {
        std::string name;
        double value;
        std::map<std::string, std::string> labels;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    explicit RealTimeMetricsCollector(const Config& config);
    ~RealTimeMetricsCollector();
    
    bool Initialize();
    void Shutdown();
    
    // Metric registration
    void RegisterCounter(const std::string& name, const std::string& description);
    void RegisterGauge(const std::string& name, const std::string& description);
    void RegisterHistogram(const std::string& name, const std::string& description,
                           const std::vector<double>& buckets);
    void RegisterSummary(const std::string& name, const std::string& description,
                         const std::vector<double>& quantiles);
    
    // Metric updates
    void IncrementCounter(const std::string& name, double value = 1.0);
    void SetGauge(const std::string& name, double value);
    void ObserveHistogram(const std::string& name, double value);
    void ObserveSummary(const std::string& name, double value);
    
    // Queries
    std::vector<MetricValue> GetCurrentValues() const;
    std::vector<MetricValue> GetMetricHistory(const std::string& name,
                                               std::chrono::hours window) const;
    
    // Export
    std::string ExportToPrometheus() const;
    std::string ExportToJSON() const;
    
private:
    Config config_;
    std::map<std::string, std::vector<MetricValue>> metrics_history_;
    mutable std::mutex metrics_mutex_;
    std::thread collection_thread_;
    std::atomic<bool> running_{false};
    
    void CollectionLoop();
    void CleanupOldMetrics();
};

// ============================================================================
// Stream Join Engine
// ============================================================================

class StreamJoinEngine {
public:
    struct Config {
        std::chrono::milliseconds join_window{60000};
        size_t max_join_size = 10000;
        bool emit_inner_joins = true;
        bool emit_left_joins = false;
    };
    
    struct JoinResult {
        std::string join_id;
        DataPoint left;
        DataPoint right;
        std::chrono::steady_clock::time_point joined_at;
        std::chrono::milliseconds latency;
    };
    
    explicit StreamJoinEngine(const Config& config);
    ~StreamJoinEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Join setup
    std::string CreateJoin(const std::string& left_stream,
                           const std::string& right_stream,
                           const std::vector<std::string>& join_keys);
    bool DestroyJoin(const std::string& join_id);
    
    // Join execution
    std::vector<JoinResult> ExecuteJoin(const std::string& join_id);
    void SetJoinCallback(const std::string& join_id,
                         std::function<void(const JoinResult&)> callback);
    
    // Windowed joins
    std::vector<JoinResult> ExecuteWindowedJoin(const std::string& join_id,
                                                 std::chrono::milliseconds window);
    
private:
    Config config_;
    std::map<std::string, std::pair<std::string, std::string>> joins_;
    std::map<std::string, std::vector<std::string>> join_keys_;
    mutable std::mutex joins_mutex_;
};

// ============================================================================
// Real-Time Analytics Runtime
// ============================================================================

class RealTimeAnalyticsRuntime {
public:
    struct Config {
        StreamProcessor::Config processor;
        WindowManager::Config windows;
        RealTimeMetricsCollector::Config metrics;
        StreamJoinEngine::Config joins;
    };
    
    explicit RealTimeAnalyticsRuntime(const Config& config);
    ~RealTimeAnalyticsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    StreamProcessor* GetProcessor();
    WindowManager* GetWindowManager();
    RealTimeMetricsCollector* GetMetricsCollector();
    StreamJoinEngine* GetJoinEngine();
    
    // High-level API
    std::string CreateMetricStream(const std::string& name);
    bool IngestMetric(const std::string& stream_id, const std::string& metric_name,
                      double value, const std::map<std::string, std::string>& tags);
    
    std::vector<MetricWindow> GetAggregatedMetrics(const std::string& stream_id,
                                                    std::chrono::seconds window);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<StreamProcessor> processor_;
    std::unique_ptr<WindowManager> window_manager_;
    std::unique_ptr<RealTimeMetricsCollector> metrics_collector_;
    std::unique_ptr<StreamJoinEngine> join_engine_;
};

} // namespace Analytics
} // namespace Sovereign
