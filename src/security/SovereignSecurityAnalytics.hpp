// Phase D.19 Batch 5/5: Security Analytics
// Security data analysis and visualization
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
namespace Security {

// Forward declarations
struct SecurityEvent;
struct SecurityMetric;
struct SecurityDashboard;

// ============================================================================
// Security Analytics Types
// ============================================================================

enum class EventType {
    AUTHENTICATION = 0,
    AUTHORIZATION = 1,
    DATA_ACCESS = 2,
    CONFIG_CHANGE = 3,
    THREAT_DETECTED = 4,
    INCIDENT = 5,
    COMPLIANCE = 6,
    SYSTEM = 7
};

enum class SeverityLevel {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class MetricType {
    COUNTER = 0,
    GAUGE = 1,
    HISTOGRAM = 2,
    RATE = 3
};

struct SecurityEvent {
    std::string event_id;
    EventType type;
    SeverityLevel severity;
    std::string source;
    std::string actor;
    std::string target;
    std::string action;
    bool success;
    std::map<std::string, std::any> details;
    std::chrono::steady_clock::time_point timestamp;
    std::vector<std::string> tags;
};

struct SecurityMetric {
    std::string metric_name;
    MetricType type;
    double value;
    std::map<std::string, std::string> labels;
    std::chrono::steady_clock::time_point timestamp;
};

struct SecurityDashboard {
    std::string dashboard_id;
    std::string name;
    std::vector<std::string> widget_ids;
    std::map<std::string, std::any> layout;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
};

// ============================================================================
// Security Event Collector
// ============================================================================

class SecurityEventCollector {
public:
    struct Config {
        size_t max_events = 1000000;
        std::chrono::seconds retention_period{86400};  // 24 hours
        bool enable_real_time = true;
    };
    
    explicit SecurityEventCollector(const Config& config);
    ~SecurityEventCollector();
    
    bool Initialize();
    void Shutdown();
    
    // Event collection
    bool CollectEvent(const SecurityEvent& event);
    bool CollectEvents(const std::vector<SecurityEvent>& events);
    
    // Queries
    std::vector<SecurityEvent> GetEventsByType(EventType type, std::chrono::hours window) const;
    std::vector<SecurityEvent> GetEventsBySeverity(SeverityLevel severity, std::chrono::hours window) const;
    std::vector<SecurityEvent> GetEventsByActor(const std::string& actor, std::chrono::hours window) const;
    std::vector<SecurityEvent> GetEventsByTarget(const std::string& target, std::chrono::hours window) const;
    std::vector<SecurityEvent> QueryEvents(const std::map<std::string, std::any>& filters) const;
    
    // Aggregation
    std::map<EventType, int> GetEventCounts(std::chrono::hours window) const;
    std::map<SeverityLevel, int> GetSeverityDistribution(std::chrono::hours window) const;
    
private:
    Config config_;
    std::vector<SecurityEvent> events_;
    mutable std::mutex events_mutex_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    
    void CleanupLoop();
    void CleanupOldEvents();
};

// ============================================================================
// Security Metrics Engine
// ============================================================================

class SecurityMetricsEngine {
public:
    struct Config {
        std::chrono::seconds collection_interval{60};
        size_t max_metrics = 10000;
    };
    
    struct MetricSeries {
        std::string metric_name;
        MetricType type;
        std::vector<SecurityMetric> data_points;
        std::chrono::steady_clock::time_point last_updated;
    };
    
    explicit SecurityMetricsEngine(const Config& config);
    ~SecurityMetricsEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Metric registration
    void RegisterMetric(const std::string& name, MetricType type);
    void UnregisterMetric(const std::string& name);
    
    // Metric updates
    void RecordMetric(const std::string& name, double value);
    void RecordMetric(const std::string& name, double value, const std::map<std::string, std::string>& labels);
    
    // Queries
    MetricSeries GetMetricSeries(const std::string& name, std::chrono::hours window) const;
    std::vector<MetricSeries> GetAllMetrics(std::chrono::hours window) const;
    
    // Calculations
    double CalculateAverage(const std::string& name, std::chrono::hours window) const;
    double CalculateRate(const std::string& name, std::chrono::hours window) const;
    std::pair<double, double> CalculatePercentiles(const std::string& name, std::chrono::hours window, double p50, double p95, double p99) const;
    
private:
    Config config_;
    std::map<std::string, MetricSeries> metrics_;
    mutable std::mutex metrics_mutex_;
    std::thread collection_thread_;
    std::atomic<bool> running_{false};
    
    void CollectionLoop();
};

// ============================================================================
// Security Correlator
// ============================================================================

class SecurityCorrelator {
public:
    struct Config {
        std::chrono::seconds correlation_window{300};  // 5 minutes
        int min_event_count = 3;
        double correlation_threshold = 0.8;
    };
    
    struct CorrelationResult {
        std::string correlation_id;
        std::vector<std::string> event_ids;
        std::string correlation_type;
        double confidence;
        std::string description;
        SeverityLevel severity;
        std::chrono::steady_clock::time_point detected_at;
    };
    
    explicit SecurityCorrelator(const Config& config);
    ~SecurityCorrelator();
    
    bool Initialize();
    void Shutdown();
    
    // Correlation rules
    std::string AddCorrelationRule(const std::string& name, const std::vector<std::string>& event_patterns);
    bool RemoveCorrelationRule(const std::string& rule_id);
    
    // Correlation
    std::vector<CorrelationResult> CorrelateEvents(const std::vector<SecurityEvent>& events);
    std::vector<CorrelationResult> FindAttackChains(const std::string& actor, std::chrono::hours window);
    std::vector<CorrelationResult> FindLateralMovement(const std::string& source_host, std::chrono::hours window);
    
    // Pattern detection
    std::vector<std::string> DetectBruteForce(std::chrono::hours window);
    std::vector<std::string> DetectDataExfiltration(std::chrono::hours window);
    std::vector<std::string> DetectPrivilegeEscalation(std::chrono::hours window);
    
private:
    Config config_;
    std::map<std::string, std::vector<std::string>> correlation_rules_;
    mutable std::mutex correlator_mutex_;
    
    double CalculateSimilarity(const SecurityEvent& a, const SecurityEvent& b);
    bool IsPartOfAttackChain(const SecurityEvent& event, const std::vector<SecurityEvent>& chain);
};

// ============================================================================
// Security Reporter
// ============================================================================

class SecurityReporter {
public:
    struct Config {
        std::string report_template_path;
        bool include_charts = true;
        bool include_recommendations = true;
    };
    
    struct SecurityReport {
        std::string report_id;
        std::string title;
        std::chrono::steady_clock::time_point generated_at;
        std::chrono::steady_clock::time_point period_start;
        std::chrono::steady_clock::time_point period_end;
        int total_events;
        std::map<SeverityLevel, int> severity_counts;
        std::map<EventType, int> event_type_counts;
        std::vector<std::string> top_threats;
        std::vector<std::string> recommendations;
        std::map<std::string, std::any> metrics;
    };
    
    explicit SecurityReporter(const Config& config);
    ~SecurityReporter();
    
    bool Initialize();
    void Shutdown();
    
    // Report generation
    SecurityReport GenerateReport(std::chrono::hours period);
    SecurityReport GenerateReportForActor(const std::string& actor, std::chrono::hours period);
    SecurityReport GenerateThreatReport(std::chrono::hours period);
    
    // Export
    bool ExportToPDF(const SecurityReport& report, const std::string& file_path);
    bool ExportToHTML(const SecurityReport& report, const std::string& file_path);
    bool ExportToJSON(const SecurityReport& report, const std::string& file_path);
    
    // Dashboard data
    std::map<std::string, double> GetSecurityScore() const;
    std::vector<std::pair<std::string, int>> GetTopRisks(int limit) const;
    std::map<std::string, std::vector<double>> GetTrendData(std::chrono::days period) const;
    
private:
    Config config_;
    
    std::vector<std::string> GenerateRecommendations(const SecurityReport& report);
    double CalculateSecurityScore(const SecurityReport& report);
};

// ============================================================================
// Security Analytics Runtime
// ============================================================================

class SecurityAnalyticsRuntime {
public:
    struct Config {
        SecurityEventCollector::Config collector;
        SecurityMetricsEngine::Config metrics;
        SecurityCorrelator::Config correlator;
        SecurityReporter::Config reporter;
    };
    
    explicit SecurityAnalyticsRuntime(const Config& config);
    ~SecurityAnalyticsRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    SecurityEventCollector* GetCollector();
    SecurityMetricsEngine* GetMetricsEngine();
    SecurityCorrelator* GetCorrelator();
    SecurityReporter* GetReporter();
    
    // High-level API
    bool LogSecurityEvent(EventType type, SeverityLevel severity, const std::string& actor,
                          const std::string& action, const std::string& target);
    SecurityReport GenerateSecurityReport(std::chrono::hours period);
    std::vector<SecurityCorrelator::CorrelationResult> CorrelateSecurityEvents();
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<SecurityEventCollector> collector_;
    std::unique_ptr<SecurityMetricsEngine> metrics_engine_;
    std::unique_ptr<SecurityCorrelator> correlator_;
    std::unique_ptr<SecurityReporter> reporter_;
};

} // namespace Security
} // namespace Sovereign
