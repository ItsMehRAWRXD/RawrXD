#pragma once
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <optional>

namespace rawrxd::build {

// ───────────────────────────────────────────────────────────────
// Build intelligence source (CMake, compiler output, etc.)
// ───────────────────────────────────────────────────────────────
enum class IntelligenceSource {
    CMakeConfigure,
    CMakeBuild,
    CompilerOutput,
    LinkerOutput,
    TestOutput,
    StaticAnalysis,
    DynamicAnalysis,
    UserAnnotation
};

// ───────────────────────────────────────────────────────────────
// Build intelligence event — structured diagnostic
// ───────────────────────────────────────────────────────────────
struct BuildIntelligenceEvent {
    uint64_t event_id = 0;
    IntelligenceSource source = IntelligenceSource::CMakeBuild;
    std::string severity;             // "error", "warning", "info", "suggestion"
    std::string file_path;
    uint32_t line_number = 0;
    uint32_t column_number = 0;
    std::string message;
    std::string category;             // "type_mismatch", "unused_var", "deprecated_api", etc.
    std::string suggestion;           // AI-generated fix suggestion
    float confidence = 1.0f;          // 0.0–1.0
    uint64_t timestamp_ms = 0;
    bool is_auto_fixable = false;
    std::string proposed_patch;       // diff/patch text if auto-fixable
};

// ───────────────────────────────────────────────────────────────
// Build metrics snapshot
// ───────────────────────────────────────────────────────────────
struct BuildMetrics {
    uint64_t total_events = 0;
    uint64_t error_count = 0;
    uint64_t warning_count = 0;
    uint64_t suggestion_count = 0;
    uint64_t auto_fixable_count = 0;
    float avg_confidence = 0.0f;
    std::chrono::milliseconds total_build_time{0};
    std::vector<std::string> top_error_categories;
};

// ───────────────────────────────────────────────────────────────
// BuildIntelligence — AI-enhanced build analysis engine
// ───────────────────────────────────────────────────────────────
class BuildIntelligence {
public:
    BuildIntelligence();
    ~BuildIntelligence();

    // Event ingestion
    void IngestEvent(const BuildIntelligenceEvent& event);
    void IngestCompilerOutput(const std::string& raw_output, IntelligenceSource src);
    void IngestCMakeOutput(const std::string& raw_output);

    // Analysis
    BuildMetrics AnalyzeBuild() const;
    std::vector<BuildIntelligenceEvent> GetErrors() const;
    std::vector<BuildIntelligenceEvent> GetWarnings() const;
    std::vector<BuildIntelligenceEvent> GetSuggestions() const;
    std::vector<BuildIntelligenceEvent> GetByCategory(const std::string& category) const;
    std::vector<BuildIntelligenceEvent> GetByFile(const std::string& file_path) const;

    // AI-enhanced features
    std::vector<BuildIntelligenceEvent> GetAutoFixableEvents() const;
    bool GenerateFixPatch(const BuildIntelligenceEvent& event, std::string& out_patch) const;
    std::vector<std::string> SuggestBuildOptimizations() const;
    float PredictBuildSuccessRate() const;

    // Trend analysis
    void RecordBuildAttempt(bool success, const std::string& target);
    float GetSuccessRateForTarget(const std::string& target) const;
    std::vector<std::string> GetFlakyTargets() const;

    // Serialization
    bool SaveState(const std::string& path) const;
    bool LoadState(const std::string& path);
    void ClearState();

    // Callbacks
    using EventCallback = std::function<void(const BuildIntelligenceEvent&)>;
    void SetEventCallback(EventCallback cb) { event_cb_ = std::move(cb); }

    // Static parsers
    static std::vector<BuildIntelligenceEvent> ParseMSVCOutput(const std::string& output);
    static std::vector<BuildIntelligenceEvent> ParseGCCOutput(const std::string& output);
    static std::vector<BuildIntelligenceEvent> ParseCMakeErrorOutput(const std::string& output);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    EventCallback event_cb_;
};

} // namespace rawrxd::build
