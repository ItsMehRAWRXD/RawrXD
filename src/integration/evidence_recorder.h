#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <nlohmann/json.hpp>

namespace RawrXD {

// Event types for structured logging
enum class EvidenceEventType {
    ActionStarted,
    ActionCompleted,
    ArtifactProduced,
    FailureDetected,
    RecoveryAttempted,
    PlanGenerated,
    BuildTriggered,
    TestTriggered,
    MemoryUpdated
};

// Single evidence event
struct EvidenceEvent {
    EvidenceEventType type;
    std::string timestamp;
    std::string actionId;
    std::string tool;
    nlohmann::json inputs;
    nlohmann::json outputs;
    int64_t durationMs;
    bool success;
    std::string error;
    
    nlohmann::json toJson() const;
};

// Complete evidence trace for a goal execution
struct EvidenceTrace {
    std::string goal;
    std::string startTime;
    std::string endTime;
    std::vector<EvidenceEvent> events;
    nlohmann::json plan;
    std::string changesPatch;
    std::string buildLog;
    std::string testLog;
    bool completed;
    
    nlohmann::json toJson() const;
    bool save(const std::string& path) const;
};

// Evidence recorder for VAL-012
class EvidenceRecorder {
public:
    explicit EvidenceRecorder(const std::string& evidenceDir);
    
    // Start a new trace
    void beginTrace(const std::string& goal);
    
    // Record events
    void recordEvent(EvidenceEventType type, 
                     const std::string& tool,
                     const nlohmann::json& inputs,
                     const nlohmann::json& outputs,
                     int64_t durationMs,
                     bool success,
                     const std::string& error = "");
    
    void recordPlanGenerated(const nlohmann::json& plan);
    void recordArtifact(const std::string& artifactType, const std::string& path);
    void recordBuildTriggered();
    void recordBuildCompleted(bool success, const std::string& log);
    void recordTestTriggered();
    void recordTestCompleted(bool success, const std::string& log);
    void recordMemoryUpdated();
    
    // Finalize trace
    void endTrace(bool completed);
    bool saveTrace();
    
    // Generate completion.json
    bool generateCompletionJson(const std::string& path) const;
    
private:
    std::string evidenceDir_;
    EvidenceTrace currentTrace_;
    std::chrono::steady_clock::time_point traceStart_;
    bool hasActiveTrace_;
    
    std::string generateTimestamp() const;
    std::string eventTypeToString(EvidenceEventType type) const;
};

} // namespace RawrXD
