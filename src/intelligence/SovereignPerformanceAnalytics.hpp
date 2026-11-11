// Phase D.6 Batch 4/5: Performance Analytics
// Distributed Tracing and Latency Profiling
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignPredictiveAutoscaling.hpp"
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Intelligence {

// ============================================================================
// Distributed Tracing
// ============================================================================

struct Span {
    std::string trace_id;
    std::string span_id;
    std::string parent_span_id;
    std::string operation_name;
    std::string service_name;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    int64_t duration_us = 0;
    std::map<std::string, std::string> tags;
    std::map<std::string, std::string> logs;
    bool error = false;
    std::string error_message;
};

struct Trace {
    std::string trace_id;
    std::vector<Span> spans;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    int64_t total_duration_us = 0;
    bool has_errors = false;
    std::string root_service;
};

class DistributedTracer {
public:
    struct Config {
        double sampling_rate = 0.1;  // Sample 10% of traces
        int max_spans_per_trace = 1000;
        int max_tag_length = 256;
        bool enable_log_correlation = true;
        int buffer_size = 10000;
    };
    
    explicit DistributedTracer(const Config& config);
    ~DistributedTracer();
    
    bool Initialize();
    void Shutdown();
    
    // Span creation
    Span StartSpan(const std::string& operation_name,
                   const std::string& service_name,
                   const std::string& parent_span_id = "");
    void FinishSpan(Span& span);
    
    // Trace context propagation
    std::map<std::string, std::string> InjectContext(const Span& span);
    Span ExtractContext(const std::map<std::string, std::string>& headers);
    
    // Sampling
    bool ShouldSample(const std::string& operation_name);
    void SetSamplingRate(double rate);
    
    // Trace retrieval
    std::vector<Trace> GetTraces(const std::string& service_name,
                                    std::chrono::minutes lookback);
    Trace GetTrace(const std::string& trace_id);
    std::vector<Trace> GetTracesWithErrors(std::chrono::minutes lookback);
    
    // Analysis
    struct TraceAnalysis {
        double avg_duration_ms = 0.0;
        double p99_duration_ms = 0.0;
        std::map<std::string, double> service_breakdown;
        std::map<std::string, int> error_counts;
        std::vector<std::string> slowest_operations;
    };
    
    TraceAnalysis AnalyzeTraces(const std::vector<Trace>& traces);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread export_thread_;
    
    mutable std::mutex traces_mutex_;
    std::map<std::string, Trace> traces_;
    std::vector<Span> pending_spans_;
    
    std::string GenerateTraceId();
    std::string GenerateSpanId();
    void ExportLoop();
};

// ============================================================================
// Latency Profiler
// ============================================================================

class LatencyProfiler {
public:
    struct Config {
        int profiling_interval_ms = 1000;
        int max_stack_depth = 50;
        bool enable_cpu_profiling = true;
        bool enable_memory_profiling = true;
        bool enable_io_profiling = true;
    };
    
    struct ProfileSample {
        std::chrono::steady_clock::time_point timestamp;
        std::vector<std::string> stack_trace;
        double cpu_percent = 0.0;
        int64_t memory_bytes = 0;
        int64_t allocations = 0;
        std::string operation_name;
        int64_t duration_us = 0;
    };
    
    struct HotSpot {
        std::string function_name;
        std::string file_name;
        int line_number = 0;
        double total_time_percent = 0.0;
        double self_time_percent = 0.0;
        int64_t sample_count = 0;
    };
    
    struct LatencyBreakdown {
        std::string operation_name;
        double total_latency_ms = 0.0;
        std::map<std::string, double> component_latencies;
        std::map<std::string, double> percentage_breakdown;
        std::vector<HotSpot> hotspots;
    };
    
    explicit LatencyProfiler(const Config& config);
    ~LatencyProfiler();
    
    bool Initialize();
    void Shutdown();
    
    // Profiling
    void StartProfiling(const std::string& operation_name);
    void StopProfiling();
    
    // Analysis
    LatencyBreakdown AnalyzeOperation(const std::string& operation_name,
                                     std::chrono::minutes lookback);
    std::vector<HotSpot> FindHotSpots(std::chrono::minutes lookback);
    
    // Comparison
    struct LatencyComparison {
        std::string operation_name;
        double baseline_latency_ms = 0.0;
        double current_latency_ms = 0.0;
        double percent_change = 0.0;
        std::map<std::string, double> component_changes;
    };
    
    LatencyComparison CompareLatencies(const std::string& operation_name,
                                      std::chrono::minutes baseline_period,
                                      std::chrono::minutes current_period);
    
    // Flame graph generation
    std::string GenerateFlameGraph(std::chrono::minutes lookback);
    std::string GenerateFlameGraphDiff(std::chrono::minutes period1,
                                         std::chrono::minutes period2);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread profile_thread_;
    
    mutable std::mutex samples_mutex_;
    std::vector<ProfileSample> samples_;
    std::string current_operation_;
    
    void ProfileLoop();
    ProfileSample CaptureSample();
    std::vector<std::string> GetStackTrace();
};

// ============================================================================
// Bottleneck Detector
// ============================================================================

class BottleneckDetector {
public:
    struct Config {
        double cpu_threshold = 80.0;
        double memory_threshold = 85.0;
        double io_threshold = 90.0;
        double network_threshold = 80.0;
        int detection_window_minutes = 5;
        bool enable_saturation_detection = true;
    };
    
    enum class BottleneckType {
        CPU_BOUND = 0,
        MEMORY_BOUND = 1,
        IO_BOUND = 2,
        NETWORK_BOUND = 3,
        LOCK_CONTENTION = 4,
        DATABASE_SLOWDOWN = 5,
        EXTERNAL_DEPENDENCY = 6,
        UNKNOWN = 7
    };
    
    struct Bottleneck {
        std::string bottleneck_id;
        BottleneckType type;
        std::string resource_name;
        double severity = 0.0;  // 0.0 to 1.0
        std::chrono::steady_clock::time_point detected_at;
        std::chrono::steady_clock::time_point resolved_at;
        bool resolved = false;
        std::map<std::string, double> metrics;
        std::vector<std::string> affected_services;
        std::string recommended_action;
    };
    
    explicit BottleneckDetector(const Config& config);
    
    bool Initialize();
    
    // Detection
    std::vector<Bottleneck> DetectBottlenecks(
        const std::map<std::string, TimeSeries>& metrics);
    
    Bottleneck DetectCPUBottleneck(const TimeSeries& cpu_metrics);
    Bottleneck DetectMemoryBottleneck(const TimeSeries& memory_metrics);
    Bottleneck DetectIOBottleneck(const TimeSeries& io_metrics);
    Bottleneck DetectNetworkBottleneck(const TimeSeries& network_metrics);
    
    // Analysis
    std::vector<Bottleneck> GetActiveBottlenecks() const;
    std::vector<Bottleneck> GetBottleneckHistory(std::chrono::hours lookback) const;
    
    // Resolution tracking
    void MarkResolved(const std::string& bottleneck_id);
    double CalculateImpact(const Bottleneck& bottleneck);
    
private:
    Config config_;
    
    mutable std::mutex bottlenecks_mutex_;
    std::vector<Bottleneck> bottlenecks_;
    
    BottleneckType ClassifyBottleneck(const std::map<std::string, double>& metrics);
    double CalculateSeverity(BottleneckType type, 
                             const std::map<std::string, double>& metrics);
};

// ============================================================================
// SLO Manager
// ============================================================================

class SLOManager {
public:
    struct Config {
        int evaluation_window_minutes = 5;
        bool enable_burn_rate_alerts = true;
        double burn_rate_threshold = 14.4;  // 2% budget in 1 hour
    };
    
    struct ServiceLevelObjective {
        std::string slo_id;
        std::string name;
        std::string service_name;
        std::string metric_name;
        double target = 0.0;  // e.g., 0.99 for 99%
        std::string comparison;  // ">=", "<=", "<", ">"
        std::chrono::minutes evaluation_window{5};
        double error_budget_percent = 0.01;  // 1% error budget
    };
    
    struct SLOStatus {
        std::string slo_id;
        double current_value = 0.0;
        bool is_breached = false;
        double error_budget_remaining = 0.0;
        double burn_rate = 0.0;
        std::chrono::steady_clock::time_point last_evaluation;
        std::vector<std::string> alerts;
    };
    
    explicit SLOManager(const Config& config);
    
    bool Initialize();
    
    // SLO management
    bool DefineSLO(const ServiceLevelObjective& slo);
    bool UpdateSLO(const std::string& slo_id, const ServiceLevelObjective& slo);
    bool DeleteSLO(const std::string& slo_id);
    std::vector<ServiceLevelObjective> GetSLOs() const;
    
    // Evaluation
    SLOStatus EvaluateSLO(const std::string& slo_id,
                          const TimeSeries& metric_data);
    std::vector<SLOStatus> EvaluateAllSLOs(
        const std::map<std::string, TimeSeries>& metrics);
    
    // Error budget
    double CalculateErrorBudget(const std::string& slo_id,
                                std::chrono::days period);
    double CalculateBurnRate(const std::string& slo_id,
                            std::chrono::hours window);
    
    // Reporting
    struct SLOReport {
        std::string slo_id;
        double achievement_percent = 0.0;
        int breaches = 0;
        double avg_value = 0.0;
        double p99_value = 0.0;
        std::chrono::steady_clock::time_point report_period_start;
        std::chrono::steady_clock::time_point report_period_end;
    };
    
    SLOReport GenerateReport(const std::string& slo_id,
                            std::chrono::days period);
    
private:
    Config config_;
    
    mutable std::mutex slos_mutex_;
    std::map<std::string, ServiceLevelObjective> slos_;
    
    mutable std::mutex status_mutex_;
    std::map<std::string, SLOStatus> statuses_;
    
    bool EvaluateCondition(double value, double target, const std::string& comparison);
};

} // namespace Intelligence
} // namespace Sovereign
