#pragma once
#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>
#include <functional>
#include <stdint.h>

namespace rawrxd::diagnostics {

// ───────────────────────────────────────────────────────────────
// Diagnostic severity
// ───────────────────────────────────────────────────────────────
enum class Severity {
    Verbose,
    Info,
    Warning,
    Error,
    Fatal
};

// ───────────────────────────────────────────────────────────────
// Diagnostic category
// ───────────────────────────────────────────────────────────────
enum class Category {
    General,
    Initialization,
    ModelLoading,
    Inference,
    Quantization,
    GPU,
    Memory,
    Network,
    Configuration,
    Performance,
    Security,
    Validation
};

// ───────────────────────────────────────────────────────────────
// Diagnostic record
// ───────────────────────────────────────────────────────────────
struct DiagnosticRecord {
    uint64_t id = 0;
    Severity severity = Severity::Info;
    Category category = Category::General;
    std::string message;
    std::string source_location;
    uint64_t timestamp_us = 0;
    std::vector<std::pair<std::string, std::string>> context_kv;
    std::string stack_trace;
    bool is_user_visible = true;
};

// ───────────────────────────────────────────────────────────────
// Diagnostics filter / routing rule
// ───────────────────────────────────────────────────────────────
struct DiagnosticRule {
    std::optional<Severity> min_severity;
    std::optional<Category> category_filter;
    std::optional<std::string> message_regex;
    bool suppress = false;
    bool trigger_breakpoint = false;
    std::string route_target; // "console", "file", "telemetry", "callback"
};

// ───────────────────────────────────────────────────────────────
// DiagnosticsEngine — centralized structured logging & diagnostics
// ───────────────────────────────────────────────────────────────
class DiagnosticsEngine {
public:
    DiagnosticsEngine();
    ~DiagnosticsEngine();

    // Lifecycle
    bool Initialize(const std::string& config_json = "{}");
    void Shutdown();
    bool IsInitialized() const;

    // Logging
    void Log(Severity severity, Category category, const std::string& message,
              const std::string& source_loc = "");
    void LogVerbose(const std::string& msg, const std::string& src = "");
    void LogInfo(const std::string& msg, const std::string& src = "");
    void LogWarning(const std::string& msg, const std::string& src = "");
    void LogError(const std::string& msg, const std::string& src = "");
    void LogFatal(const std::string& msg, const std::string& src = "");

    // Filtering
    void AddRule(const DiagnosticRule& rule);
    void ClearRules();
    bool ShouldSuppress(Severity sev, Category cat, const std::string& msg) const;

    // Retrieval
    std::vector<DiagnosticRecord> GetRecords(Severity min_severity = Severity::Verbose,
                                                Category cat = Category::General) const;
    std::vector<DiagnosticRecord> GetRecentRecords(size_t count) const;
    size_t GetCount(Severity min_severity = Severity::Verbose) const;
    size_t GetErrorCount() const;
    size_t GetWarningCount() const;

    // Callbacks
    using RecordCallback = std::function<void(const DiagnosticRecord&)>;
    void SetRecordCallback(RecordCallback cb);
    void SetFatalHandler(std::function<void(const DiagnosticRecord&)> handler);

    // Serialization
    bool SaveToFile(const std::string& path) const;
    bool LoadFromFile(const std::string& path);
    std::string ExportJSON() const;

    // Static helpers
    static const char* SeverityToString(Severity s);
    static const char* CategoryToString(Category c);
    static Severity SeverityFromString(const std::string& s);
    static Category CategoryFromString(const std::string& s);

    // Performance counters
    void BeginTimer(const std::string& name);
    void EndTimer(const std::string& name);
    std::optional<float> GetElapsedMs(const std::string& name) const;
    void ResetTimers();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::diagnostics
