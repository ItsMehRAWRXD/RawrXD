/**
 * LogAggregator.hpp
 *
 * Phase F Batch 4/5: Log Aggregation & Analysis
 *
 * Structured logging with aggregation, filtering, and analysis capabilities.
 * Supports multiple output formats and destinations.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <memory>
#include <functional>
#include <sstream>

namespace Telemetry {

// ============================================================================
// Log Level
// ============================================================================

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

std::string LogLevelToString(LogLevel level);
LogLevel LogLevelFromString(const std::string& str);
bool IsLevelEnabled(LogLevel messageLevel, LogLevel configuredLevel);

// ============================================================================
// Log Entry
// ============================================================================

/**
 * Single structured log entry.
 */
struct LogEntry {
    uint64_t timestamp;
    LogLevel level;
    std::string message;
    std::string source;
    std::string threadId;
    std::map<std::string, std::string> fields;
    std::string traceId;
    std::string spanId;
    
    LogEntry();
    
    // Builder pattern
    LogEntry& WithField(const std::string& key, const std::string& value);
    LogEntry& WithField(const std::string& key, int64_t value);
    LogEntry& WithField(const std::string& key, double value);
    LogEntry& WithField(const std::string& key, bool value);
    LogEntry& WithTrace(const std::string& trace, const std::string& span);
    
    // Serialization
    std::string ToJson() const;
    std::string ToLogfmt() const;
    std::string ToText() const;
    
    static LogEntry FromJson(const std::string& json);
};

// ============================================================================
// Log Filter
// ============================================================================

/**
 * Filter for log entries.
 */
class LogFilter {
public:
    virtual ~LogFilter() = default;
    virtual bool Matches(const LogEntry& entry) const = 0;
};

/**
 * Filter by log level.
 */
class LevelFilter : public LogFilter {
public:
    explicit LevelFilter(LogLevel minLevel);
    bool Matches(const LogEntry& entry) const override;
    
private:
    LogLevel minLevel_;
};

/**
 * Filter by source.
 */
class SourceFilter : public LogFilter {
public:
    explicit SourceFilter(const std::string& source);
    bool Matches(const LogEntry& entry) const override;
    
private:
    std::string source_;
};

/**
 * Filter by field value.
 */
class FieldFilter : public LogFilter {
public:
    FieldFilter(const std::string& key, const std::string& value);
    bool Matches(const LogEntry& entry) const override;
    
private:
    std::string key_;
    std::string value_;
};

/**
 * Composite filter (AND logic).
 */
class CompositeFilter : public LogFilter {
public:
    void AddFilter(std::unique_ptr<LogFilter> filter);
    bool Matches(const LogEntry& entry) const override;
    
private:
    std::vector<std::unique_ptr<LogFilter>> filters_;
};

// ============================================================================
// Log Output
// ============================================================================

/**
 * Output destination for logs.
 */
class LogOutput {
public:
    using Ptr = std::shared_ptr<LogOutput>;
    
    virtual ~LogOutput() = default;
    virtual void Write(const LogEntry& entry) = 0;
    virtual void Flush() = 0;
    virtual void Close() = 0;
};

/**
 * Console output.
 */
class ConsoleOutput : public LogOutput {
public:
    struct Config {
        bool colored = true;
        bool timestamps = true;
        bool source = true;
    };
    
    explicit ConsoleOutput(const Config& config = Config{});
    
    void Write(const LogEntry& entry) override;
    void Flush() override;
    void Close() override;
    
private:
    Config config_;
    std::mutex mutex_;
    
    std::string Colorize(LogLevel level, const std::string& text);
};

/**
 * File output with rotation.
 */
class FileOutput : public LogOutput {
public:
    struct Config {
        std::string filepath;
        size_t maxSize = 100 * 1024 * 1024;  // 100MB
        size_t maxFiles = 5;
        bool compress = true;
    };
    
    explicit FileOutput(const Config& config);
    ~FileOutput();
    
    void Write(const LogEntry& entry) override;
    void Flush() override;
    void Close() override;
    
private:
    Config config_;
    std::ofstream file_;
    std::mutex mutex_;
    size_t currentSize_ = 0;
    
    void RotateIfNeeded();
    void Rotate();
};

/**
 * Network output (syslog, etc.).
 */
class NetworkOutput : public LogOutput {
public:
    struct Config {
        std::string protocol;  // tcp, udp
        std::string host;
        uint16_t port;
        std::string format;  // json, syslog
    };
    
    explicit NetworkOutput(const Config& config);
    ~NetworkOutput();
    
    void Write(const LogEntry& entry) override;
    void Flush() override;
    void Close() override;
    
private:
    Config config_;
    int socket_ = -1;
    std::mutex mutex_;
    
    bool Connect();
    void Disconnect();
};

/**
 * Async buffered output.
 */
class AsyncOutput : public LogOutput {
public:
    struct Config {
        size_t bufferSize = 10000;
        uint64_t flushIntervalMs = 1000;
        bool dropOnFull = false;
    };
    
    AsyncOutput(LogOutput::Ptr wrapped, const Config& config);
    ~AsyncOutput();
    
    void Write(const LogEntry& entry) override;
    void Flush() override;
    void Close() override;
    
private:
    LogOutput::Ptr wrapped_;
    Config config_;
    
    std::queue<LogEntry> buffer_;
    std::mutex bufferMutex_;
    std::condition_variable cv_;
    
    std::atomic<bool> running_{false};
    std::thread workerThread_;
    
    void WorkerLoop();
};

// ============================================================================
// Logger
// ============================================================================

/**
 * Main logger class.
 */
class Logger {
public:
    struct Config {
        LogLevel level = LogLevel::INFO;
        std::string source = "application";
        bool async = true;
        bool captureStackTrace = false;
    };
    
    explicit Logger(const Config& config);
    ~Logger();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Add outputs
    void AddOutput(LogOutput::Ptr output);
    void AddOutput(LogOutput::Ptr output, std::unique_ptr<LogFilter> filter);
    void RemoveOutput(LogOutput::Ptr output);
    void ClearOutputs();
    
    // Logging methods
    void Log(LogLevel level, const std::string& message);
    void Log(LogLevel level, const std::string& message, const std::map<std::string, std::string>& fields);
    
    // Convenience methods
    void Trace(const std::string& message);
    void Debug(const std::string& message);
    void Info(const std::string& message);
    void Warn(const std::string& message);
    void Error(const std::string& message);
    void Fatal(const std::string& message);
    
    // With fields
    void Trace(const std::string& message, const std::map<std::string, std::string>& fields);
    void Debug(const std::string& message, const std::map<std::string, std::string>& fields);
    void Info(const std::string& message, const std::map<std::string, std::string>& fields);
    void Warn(const std::string& message, const std::map<std::string, std::string>& fields);
    void Error(const std::string& message, const std::map<std::string, std::string>& fields);
    void Fatal(const std::string& message, const std::map<std::string, std::string>& fields);
    
    // Configuration
    void SetLevel(LogLevel level) { config_.level = level; }
    LogLevel GetLevel() const { return config_.level; }
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    struct FilteredOutput {
        LogOutput::Ptr output;
        std::unique_ptr<LogFilter> filter;
    };
    
    std::vector<FilteredOutput> outputs_;
    mutable std::mutex outputsMutex_;
    
    std::atomic<bool> running_{false};
    
    void WriteEntry(const LogEntry& entry);
    std::string GetCurrentThreadId() const;
};

// ============================================================================
// Log Aggregation
// ============================================================================

/**
 * Aggregates log entries for analysis.
 */
class LogAggregator {
public:
    struct Config {
        size_t maxEntries = 1000000;  // Max entries to keep
        uint64_t retentionMs = 86400000;  // 24 hours
        bool indexFields = true;
    };
    
    explicit LogAggregator(const Config& config = Config{});
    ~LogAggregator();
    
    // Add entry
    void AddEntry(const LogEntry& entry);
    void AddEntries(const std::vector<LogEntry>& entries);
    
    // Query
    std::vector<LogEntry> Query(const LogFilter& filter, size_t limit = 100) const;
    std::vector<LogEntry> QueryByLevel(LogLevel level, size_t limit = 100) const;
    std::vector<LogEntry> QueryByTimeRange(uint64_t start, uint64_t end, size_t limit = 100) const;
    std::vector<LogEntry> QueryBySource(const std::string& source, size_t limit = 100) const;
    
    // Aggregation
    std::map<LogLevel, uint64_t> CountByLevel() const;
    std::map<std::string, uint64_t> CountBySource() const;
    std::map<std::string, uint64_t> CountByHour() const;
    
    // Statistics
    uint64_t GetTotalCount() const;
    uint64_t GetErrorCount() const;
    double GetErrorRate() const;
    
    // Maintenance
    void Cleanup();
    void Clear();
    
private:
    Config config_;
    
    std::vector<LogEntry> entries_;
    mutable std::mutex entriesMutex_;
    
    // Indexes
    std::map<LogLevel, std::vector<size_t>> levelIndex_;
    std::map<std::string, std::vector<size_t>> sourceIndex_;
    std::map<uint64_t, std::vector<size_t>> timeIndex_;
    mutable std::mutex indexMutex_;
    
    void UpdateIndexes(const LogEntry& entry, size_t index);
};

// ============================================================================
// Log Analysis
// ============================================================================

/**
 * Analyzes log patterns and trends.
 */
class LogAnalyzer {
public:
    struct Pattern {
        std::string pattern;
        uint64_t count;
        double frequency;
        std::vector<LogEntry> examples;
    };
    
    struct Trend {
        std::string metric;
        double current;
        double previous;
        double change;
        std::string direction;  // up, down, stable
    };
    
    // Pattern detection
    std::vector<Pattern> DetectPatterns(const std::vector<LogEntry>& entries) const;
    std::vector<Pattern> DetectErrorPatterns(const std::vector<LogEntry>& entries) const;
    
    // Trend analysis
    std::vector<Trend> AnalyzeTrends(const std::vector<LogEntry>& current,
                                        const std::vector<LogEntry>& previous) const;
    
    // Anomaly detection
    std::vector<LogEntry> DetectAnomalies(const std::vector<LogEntry>& entries) const;
    
    // Root cause analysis
    std::vector<LogEntry> FindRootCause(const LogEntry& error,
                                         const std::vector<LogEntry>& context) const;
};

// ============================================================================
// Log Search
// ============================================================================

/**
 * Full-text search for logs.
 */
class LogSearch {
public:
    // Index entry
    void Index(const LogEntry& entry);
    void Index(const std::vector<LogEntry>& entries);
    
    // Search
    std::vector<LogEntry> Search(const std::string& query, size_t limit = 100) const;
    std::vector<LogEntry> Search(const std::string& query,
                                    const LogFilter& filter,
                                    size_t limit = 100) const;
    
    // Advanced search
    std::vector<LogEntry> FuzzySearch(const std::string& query, size_t limit = 100) const;
    std::vector<LogEntry> RegexSearch(const std::string& pattern, size_t limit = 100) const;
    
private:
    // Simple inverted index
    std::map<std::string, std::set<size_t>> index_;
    std::vector<LogEntry> entries_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Global Logger
// ============================================================================

/**
 * Global logger access.
 */
class Log {
public:
    // Initialize
    static bool Initialize(const Logger::Config& config = Logger::Config{});
    static void Shutdown();
    
    // Get logger
    static Logger* GetLogger();
    
    // Convenience methods
    static void Trace(const std::string& message);
    static void Debug(const std::string& message);
    static void Info(const std::string& message);
    static void Warn(const std::string& message);
    static void Error(const std::string& message);
    static void Fatal(const std::string& message);
    
    static void Trace(const std::string& message, const std::map<std::string, std::string>& fields);
    static void Debug(const std::string& message, const std::map<std::string, std::string>& fields);
    static void Info(const std::string& message, const std::map<std::string, std::string>& fields);
    static void Warn(const std::string& message, const std::map<std::string, std::string>& fields);
    static void Error(const std::string& message, const std::map<std::string, std::string>& fields);
    static void Fatal(const std::string& message, const std::map<std::string, std::string>& fields);
    
private:
    static std::unique_ptr<Logger> logger_;
    static std::mutex mutex_;
};

// ============================================================================
// Macros
// ============================================================================

#define LOG_TRACE(msg) Telemetry::Log::Trace(msg)
#define LOG_DEBUG(msg) Telemetry::Log::Debug(msg)
#define LOG_INFO(msg) Telemetry::Log::Info(msg)
#define LOG_WARN(msg) Telemetry::Log::Warn(msg)
#define LOG_ERROR(msg) Telemetry::Log::Error(msg)
#define LOG_FATAL(msg) Telemetry::Log::Fatal(msg)

#define LOG_TRACE_FIELDS(msg, fields) Telemetry::Log::Trace(msg, fields)
#define LOG_DEBUG_FIELDS(msg, fields) Telemetry::Log::Debug(msg, fields)
#define LOG_INFO_FIELDS(msg, fields) Telemetry::Log::Info(msg, fields)
#define LOG_WARN_FIELDS(msg, fields) Telemetry::Log::Warn(msg, fields)
#define LOG_ERROR_FIELDS(msg, fields) Telemetry::Log::Error(msg, fields)
#define LOG_FATAL_FIELDS(msg, fields) Telemetry::Log::Fatal(msg, fields)

} // namespace Telemetry
