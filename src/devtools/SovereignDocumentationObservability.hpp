// Phase D.8 Batch 5/5: Documentation & Observability
// Auto-generated docs, OpenAPI specs, developer portal
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Sovereign {
namespace DevTools {

// ============================================================================
// API Documentation
// ============================================================================

struct APIEndpoint {
    std::string path;
    std::string method;  // GET, POST, PUT, DELETE, PATCH
    std::string summary;
    std::string description;
    std::vector<std::string> tags;
    std::map<std::string, std::string> parameters;
    std::map<std::string, std::string> request_body;
    std::map<int, std::string> responses;
    std::vector<std::string> security;
    bool deprecated = false;
};

struct APISchema {
    std::string name;
    std::string type;  // object, array, string, integer, number, boolean
    std::map<std::string, APISchema> properties;
    std::vector<std::string> required;
    std::string description;
    std::string example;
};

class OpenAPIGenerator {
public:
    struct Config {
        std::string title = "Sovereign API";
        std::string version = "1.0.0";
        std::string description;
        std::string terms_of_service;
        std::string contact_name;
        std::string contact_email;
        std::string license_name;
        std::string license_url;
        std::vector<std::string> servers;
    };
    
    explicit OpenAPIGenerator(const Config& config);
    
    // Endpoint registration
    bool RegisterEndpoint(const APIEndpoint& endpoint);
    bool RegisterSchema(const std::string& name, const APISchema& schema);
    
    // Generation
    std::string GenerateOpenAPI3_0();
    std::string GenerateSwagger2_0();
    bool WriteToFile(const std::string& path, const std::string& format = "json");
    
    // Validation
    bool ValidateSpec(const std::string& spec);
    std::vector<std::string> GetValidationErrors();
    
    // Code generation
    bool GenerateClientSDK(const std::string& language, const std::string& output_path);
    bool GenerateServerStub(const std::string& language, const std::string& output_path);
    
private:
    Config config_;
    std::map<std::string, APIEndpoint> endpoints_;
    std::map<std::string, APISchema> schemas_;
};

// ============================================================================
// Code Documentation
// ============================================================================

struct DocComment {
    std::string brief;
    std::string detailed;
    std::vector<std::string> params;
    std::string returns;
    std::vector<std::string> throws;
    std::vector<std::string> see_also;
    std::string since;
    std::string deprecated;
    std::string example;
};

struct DocumentedSymbol {
    std::string name;
    std::string type;  // class, function, variable, enum, typedef
    std::string signature;
    DocComment documentation;
    std::string file_path;
    int line_number = 0;
    std::vector<std::string> modifiers;
    std::string access;  // public, private, protected
};

class DocumentationGenerator {
public:
    struct Config {
        std::string project_name;
        std::string version;
        std::string output_directory;
        std::vector<std::string> source_paths;
        std::vector<std::string> exclude_patterns;
        std::string theme = "default";
        bool generate_search = true;
        bool generate_source_links = true;
    };
    
    explicit DocumentationGenerator(const Config& config);
    
    // Parsing
    bool ParseSourceFile(const std::string& path);
    bool ParseDirectory(const std::string& path);
    
    // Generation
    bool GenerateHTML();
    bool GenerateMarkdown();
    bool GenerateXML();
    bool GenerateManPages();
    
    // Cross-references
    void AddCrossReference(const std::string& from, const std::string& to);
    std::vector<std::string> GetReferences(const std::string& symbol);
    
    // Search index
    void BuildSearchIndex();
    std::vector<DocumentedSymbol> Search(const std::string& query);
    
private:
    Config config_;
    std::map<std::string, DocumentedSymbol> symbols_;
    std::map<std::string, std::vector<std::string>> cross_references_;
    
    DocComment ParseComment(const std::string& comment_text);
    std::string GenerateHTMLForSymbol(const DocumentedSymbol& symbol);
};

// ============================================================================
// Developer Portal
// ============================================================================

class DeveloperPortal {
public:
    struct Config {
        std::string title = "Sovereign Developer Portal";
        std::string base_url;
        std::string logo_url;
        std::string favicon_url;
        std::map<std::string, std::string> theme_colors;
        bool enable_api_console = true;
        bool enable_code_samples = true;
        bool enable_changelog = true;
    };
    
    struct Guide {
        std::string id;
        std::string title;
        std::string description;
        std::string content;
        std::vector<std::string> tags;
        int order = 0;
        std::string category;
    };
    
    struct Tutorial {
        std::string id;
        std::string title;
        std::string description;
        std::vector<std::string> steps;
        std::string difficulty;  // beginner, intermediate, advanced
        std::chrono::minutes estimated_time{30};
        std::vector<std::string> prerequisites;
    };
    
    struct ChangelogEntry {
        std::string version;
        std::string date;
        std::vector<std::string> added;
        std::vector<std::string> changed;
        std::vector<std::string> deprecated;
        std::vector<std::string> removed;
        std::vector<std::string> fixed;
        std::vector<std::string> security;
    };
    
    explicit DeveloperPortal(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Content management
    bool AddGuide(const Guide& guide);
    bool AddTutorial(const Tutorial& tutorial);
    bool AddChangelogEntry(const ChangelogEntry& entry);
    bool AddCodeSample(const std::string& language, const std::string& title,
                       const std::string& code, const std::string& description);
    
    // API console
    bool EnableAPIConsole(const OpenAPIGenerator& api_spec);
    bool AddAPIEndpointToConsole(const APIEndpoint& endpoint);
    
    // Search
    void BuildSearchIndex();
    std::vector<std::string> Search(const std::string& query);
    
    // Generation
    bool GenerateStaticSite(const std::string& output_path);
    bool Serve(int port = 3000);
    
    // Analytics
    void TrackPageView(const std::string& path);
    void TrackSearch(const std::string& query, int results_count);
    void TrackCodeCopy(const std::string& sample_id);
    
private:
    Config config_;
    std::map<std::string, Guide> guides_;
    std::map<std::string, Tutorial> tutorials_;
    std::vector<ChangelogEntry> changelog_;
    std::map<std::string, std::vector<std::pair<std::string, std::string>>> code_samples_;
};

// ============================================================================
// Metrics & Observability
// ============================================================================

struct Metric {
    std::string name;
    std::string type;  // counter, gauge, histogram, summary
    std::string description;
    std::map<std::string, std::string> labels;
    double value = 0.0;
    std::chrono::steady_clock::time_point timestamp;
};

class MetricsCollector {
public:
    struct Config {
        std::string service_name;
        std::string instance_id;
        int flush_interval_seconds = 60;
        std::string output_format = "prometheus";
        std::string endpoint;
    };
    
    explicit MetricsCollector(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Counter
    void Counter(const std::string& name, double value = 1.0,
                 const std::map<std::string, std::string>& labels = {});
    void Increment(const std::string& name, 
                   const std::map<std::string, std::string>& labels = {});
    
    // Gauge
    void Gauge(const std::string& name, double value,
               const std::map<std::string, std::string>& labels = {});
    void Set(const std::string& name, double value,
             const std::map<std::string, std::string>& labels = {});
    
    // Histogram
    void Histogram(const std::string& name, double value,
                   const std::map<std::string, std::string>& labels = {});
    void Observe(const std::string& name, double value,
                 const std::map<std::string, std::string>& labels = {});
    
    // Timer
    class Timer {
    public:
        Timer(MetricsCollector* collector, const std::string& name,
              const std::map<std::string, std::string>& labels);
        ~Timer();
        void Stop();
    private:
        MetricsCollector* collector_;
        std::string name_;
        std::map<std::string, std::string> labels_;
        std::chrono::steady_clock::time_point start_;
        bool stopped_ = false;
    };
    
    std::unique_ptr<Timer> StartTimer(const std::string& name,
                                         const std::map<std::string, std::string>& labels = {});
    
    // Export
    std::string ExportPrometheus();
    std::string ExportJSON();
    std::string ExportOpenMetrics();
    bool PushToGateway(const std::string& gateway_url);
    
    // Query
    std::vector<Metric> GetMetrics(const std::string& pattern = "*");
    double GetMetricValue(const std::string& name,
                          const std::map<std::string, std::string>& labels = {});
    
private:
    Config config_;
    std::map<std::string, std::vector<Metric>> metrics_;
    std::mutex metrics_mutex_;
    std::thread flush_thread_;
    std::atomic<bool> running_{false};
    
    void FlushLoop();
};

// ============================================================================
// Distributed Tracing
// ============================================================================

struct Span {
    std::string trace_id;
    std::string span_id;
    std::string parent_span_id;
    std::string operation_name;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::map<std::string, std::string> tags;
    std::vector<std::pair<std::string, std::string>> logs;
    int status_code = 0;  // 0=OK, 1=Error
    std::string status_message;
};

struct Trace {
    std::string trace_id;
    std::vector<Span> spans;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
};

class Tracer {
public:
    struct Config {
        std::string service_name;
        std::string service_version;
        std::string exporter_endpoint;
        std::string exporter_type = "jaeger";  // jaeger, zipkin, otlp
        double sampling_rate = 1.0;
        int max_queue_size = 2048;
    };
    
    explicit Tracer(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Span creation
    Span* StartSpan(const std::string& operation_name,
                    const std::map<std::string, std::string>& tags = {});
    Span* StartSpanWithParent(const std::string& operation_name,
                              const std::string& parent_span_id,
                              const std::map<std::string, std::string>& tags = {});
    
    // Span operations
    void FinishSpan(Span* span);
    void SetTag(Span* span, const std::string& key, const std::string& value);
    void LogEvent(Span* span, const std::string& event, const std::string& message);
    void SetError(Span* span, const std::string& message);
    
    // Context propagation
    std::map<std::string, std::string> InjectContext(Span* span);
    Span* ExtractContext(const std::map<std::string, std::string>& context);
    
    // Export
    bool Flush();
    std::vector<Trace> GetPendingTraces();
    
private:
    Config config_;
    std::map<std::string, std::unique_ptr<Span>> active_spans_;
    std::vector<Trace> pending_traces_;
    std::mutex spans_mutex_;
    std::thread export_thread_;
    std::atomic<bool> running_{false};
    
    std::string GenerateTraceID();
    std::string GenerateSpanID();
    void ExportLoop();
};

// ============================================================================
// Logging
// ============================================================================

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

struct LogEntry {
    LogLevel level;
    std::string message;
    std::string logger_name;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> fields;
    std::string file;
    int line = 0;
    std::string function;
};

class StructuredLogger {
public:
    struct Config {
        std::string service_name;
        std::string service_version;
        LogLevel min_level = LogLevel::INFO;
        std::string format = "json";  // json, logfmt, pretty
        bool add_caller_info = true;
        bool add_timestamp = true;
        std::string output_path;
        bool console_output = true;
        int max_file_size_mb = 100;
        int max_files = 5;
    };
    
    explicit StructuredLogger(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Logging methods
    void Trace(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Debug(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Info(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Warn(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Error(const std::string& message, const std::map<std::string, std::string>& fields = {});
    void Fatal(const std::string& message, const std::map<std::string, std::string>& fields = {});
    
    void Log(LogLevel level, const std::string& message,
             const std::map<std::string, std::string>& fields = {});
    
    // Context
    void WithField(const std::string& key, const std::string& value);
    void WithFields(const std::map<std::string, std::string>& fields);
    void ClearFields();
    
    // Sampling
    void SetSamplingRate(double rate);
    bool ShouldSample();
    
    // Export
    std::vector<LogEntry> GetRecentLogs(int count = 100);
    bool ExportToFile(const std::string& path);
    bool ExportToElasticsearch(const std::string& endpoint);
    bool ExportToLoki(const std::string& endpoint);
    
private:
    Config config_;
    std::map<std::string, std::string> context_fields_;
    std::vector<LogEntry> recent_logs_;
    std::mutex logs_mutex_;
    std::ofstream file_stream_;
    double sampling_rate_ = 1.0;
    std::mt19937 random_gen_;
    
    void WriteLog(const LogEntry& entry);
    std::string FormatLogEntry(const LogEntry& entry);
};

// ============================================================================
// Alerting
// ============================================================================

struct AlertRule {
    std::string id;
    std::string name;
    std::string condition;  // PromQL expression
    std::chrono::seconds for_duration{0};
    std::vector<std::string> labels;
    std::vector<std::string> annotations;
    std::vector<std::string> receivers;
};

struct Alert {
    std::string id;
    std::string rule_id;
    std::string status;  // firing, resolved
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
    std::chrono::steady_clock::time_point starts_at;
    std::chrono::steady_clock::time_point ends_at;
};

class AlertManager {
public:
    struct Config {
        std::string alertmanager_url;
        std::string default_receiver = "default";
        int evaluation_interval_seconds = 15;
        int group_wait_seconds = 30;
        int group_interval_seconds = 5 * 60;
        int repeat_interval_seconds = 4 * 60 * 60;
    };
    
    explicit AlertManager(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    bool AddRule(const AlertRule& rule);
    bool RemoveRule(const std::string& rule_id);
    std::vector<AlertRule> GetRules();
    
    // Alert handling
    void SendAlert(const Alert& alert);
    void ResolveAlert(const std::string& alert_id);
    std::vector<Alert> GetActiveAlerts();
    
    // Receivers
    void AddEmailReceiver(const std::string& name, const std::vector<std::string>& to);
    void AddSlackReceiver(const std::string& name, const std::string& webhook_url);
    void AddPagerDutyReceiver(const std::string& name, const std::string& service_key);
    void AddWebhookReceiver(const std::string& name, const std::string& url);
    
    // Silences
    bool SilenceAlert(const std::string& matcher, std::chrono::hours duration);
    bool UnsilenceAlert(const std::string& silence_id);
    std::vector<std::string> GetSilences();
    
private:
    Config config_;
    std::map<std::string, AlertRule> rules_;
    std::map<std::string, Alert> active_alerts_;
    std::mutex alerts_mutex_;
    std::thread evaluation_thread_;
    std::atomic<bool> running_{false};
    
    void EvaluationLoop();
    bool EvaluateRule(const AlertRule& rule);
    void NotifyReceivers(const Alert& alert);
};

// ============================================================================
// Observability Runtime
// ============================================================================

class ObservabilityRuntime {
public:
    struct Config {
        MetricsCollector::Config metrics;
        Tracer::Config tracing;
        StructuredLogger::Config logging;
        AlertManager::Config alerting;
    };
    
    explicit ObservabilityRuntime(const Config& config);
    ~ObservabilityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Access subsystems
    MetricsCollector* GetMetricsCollector();
    Tracer* GetTracer();
    StructuredLogger* GetLogger();
    AlertManager* GetAlertManager();
    
    // Unified operations
    void RecordRequest(const std::string& operation, const std::string& status,
                       std::chrono::milliseconds duration);
    void RecordError(const std::string& operation, const std::string& error_type,
                     const std::string& message);
    
    // Health
    bool IsHealthy();
    std::map<std::string, bool> GetSubsystemHealth();
    
private:
    Config config_;
    std::unique_ptr<MetricsCollector> metrics_;
    std::unique_ptr<Tracer> tracer_;
    std::unique_ptr<StructuredLogger> logger_;
    std::unique_ptr<AlertManager> alert_manager_;
};

// ============================================================================
// Documentation & Observability Runtime
// ============================================================================

class DocumentationObservabilityRuntime {
public:
    struct Config {
        OpenAPIGenerator::Config openapi;
        DocumentationGenerator::Config docs;
        DeveloperPortal::Config portal;
        ObservabilityRuntime::Config observability;
    };
    
    explicit DocumentationObservabilityRuntime(const Config& config);
    ~DocumentationObservabilityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Documentation
    OpenAPIGenerator* GetOpenAPIGenerator();
    DocumentationGenerator* GetDocumentationGenerator();
    DeveloperPortal* GetDeveloperPortal();
    
    // Observability
    ObservabilityRuntime* GetObservabilityRuntime();
    
    // Unified workflow
    bool GenerateAllDocumentation(const std::string& output_path);
    bool StartDeveloperPortal(int port = 3000);
    bool StartObservabilityStack();
    
private:
    Config config_;
    std::unique_ptr<OpenAPIGenerator> openapi_;
    std::unique_ptr<DocumentationGenerator> docs_;
    std::unique_ptr<DeveloperPortal> portal_;
    std::unique_ptr<ObservabilityRuntime> observability_;
};

} // namespace DevTools
} // namespace Sovereign
