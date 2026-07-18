#include "evidence_recorder.h"
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace RawrXD {

nlohmann::json EvidenceEvent::toJson() const {
    return nlohmann::json{
        {"type", static_cast<int>(type)},
        {"timestamp", timestamp},
        {"action_id", actionId},
        {"tool", tool},
        {"inputs", inputs},
        {"outputs", outputs},
        {"duration_ms", durationMs},
        {"success", success},
        {"error", error}
    };
}

nlohmann::json EvidenceTrace::toJson() const {
    nlohmann::json eventsJson = nlohmann::json::array();
    for (const auto& event : events) {
        eventsJson.push_back(event.toJson());
    }
    
    return nlohmann::json{
        {"goal", goal},
        {"start_time", startTime},
        {"end_time", endTime},
        {"events", eventsJson},
        {"plan", plan},
        {"changes_patch", changesPatch},
        {"build_log", buildLog},
        {"test_log", testLog},
        {"completed", completed}
    };
}

bool EvidenceTrace::save(const std::string& path) const {
    try {
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        file << toJson().dump(2);
        return true;
    } catch (...) {
        return false;
    }
}

EvidenceRecorder::EvidenceRecorder(const std::string& evidenceDir)
    : evidenceDir_(evidenceDir), hasActiveTrace_(false) {
    std::filesystem::create_directories(evidenceDir);
}

void EvidenceRecorder::beginTrace(const std::string& goal) {
    currentTrace_ = EvidenceTrace{};
    currentTrace_.goal = goal;
    currentTrace_.startTime = generateTimestamp();
    currentTrace_.completed = false;
    traceStart_ = std::chrono::steady_clock::now();
    hasActiveTrace_ = true;
}

void EvidenceRecorder::recordEvent(EvidenceEventType type,
                                   const std::string& tool,
                                   const nlohmann::json& inputs,
                                   const nlohmann::json& outputs,
                                   int64_t durationMs,
                                   bool success,
                                   const std::string& error) {
    if (!hasActiveTrace_) return;
    
    EvidenceEvent event;
    event.type = type;
    event.timestamp = generateTimestamp();
    event.actionId = std::to_string(std::hash<std::string>{}(event.timestamp + tool));
    event.tool = tool;
    event.inputs = inputs;
    event.outputs = outputs;
    event.durationMs = durationMs;
    event.success = success;
    event.error = error;
    
    currentTrace_.events.push_back(event);
}

void EvidenceRecorder::recordPlanGenerated(const nlohmann::json& plan) {
    if (!hasActiveTrace_) return;
    currentTrace_.plan = plan;
    
    recordEvent(EvidenceEventType::PlanGenerated,
                "planner",
                {{"goal", currentTrace_.goal}},
                {{"steps", plan.size()}},
                0, true);
}

void EvidenceRecorder::recordArtifact(const std::string& artifactType, const std::string& path) {
    if (!hasActiveTrace_) return;
    
    recordEvent(EvidenceEventType::ArtifactProduced,
                "file_system",
                {{"type", artifactType}},
                {{"path", path}},
                0, true);
}

void EvidenceRecorder::recordBuildTriggered() {
    if (!hasActiveTrace_) return;
    
    recordEvent(EvidenceEventType::BuildTriggered,
                "build_system",
                {},
                {},
                0, true);
}

void EvidenceRecorder::recordBuildCompleted(bool success, const std::string& log) {
    if (!hasActiveTrace_) return;
    currentTrace_.buildLog = log;
    
    recordEvent(EvidenceEventType::BuildTriggered,
                "build_system",
                {},
                {{"success", success}, {"log_length", log.size()}},
                0, success);
}

void EvidenceRecorder::recordTestTriggered() {
    if (!hasActiveTrace_) return;
    
    recordEvent(EvidenceEventType::TestTriggered,
                "test_runner",
                {},
                {},
                0, true);
}

void EvidenceRecorder::recordTestCompleted(bool success, const std::string& log) {
    if (!hasActiveTrace_) return;
    currentTrace_.testLog = log;
    
    recordEvent(EvidenceEventType::TestTriggered,
                "test_runner",
                {},
                {{"success", success}, {"log_length", log.size()}},
                0, success);
}

void EvidenceRecorder::recordMemoryUpdated() {
    if (!hasActiveTrace_) return;
    
    recordEvent(EvidenceEventType::MemoryUpdated,
                "memory_system",
                {},
                {},
                0, true);
}

void EvidenceRecorder::endTrace(bool completed) {
    if (!hasActiveTrace_) return;
    
    currentTrace_.endTime = generateTimestamp();
    currentTrace_.completed = completed;
    hasActiveTrace_ = false;
}

bool EvidenceRecorder::saveTrace() {
    if (currentTrace_.goal.empty()) return false;
    
    std::string tracePath = evidenceDir_ + "/execution/trace.json";
    return currentTrace_.save(tracePath);
}

bool EvidenceRecorder::generateCompletionJson(const std::string& path) const {
    try {
        // Count files modified from events
        int filesModified = 0;
        for (const auto& event : currentTrace_.events) {
            if (event.type == EvidenceEventType::ArtifactProduced) {
                filesModified++;
            }
        }
        
        // Check build success from log
        bool buildSuccess = !currentTrace_.buildLog.empty() && 
                           currentTrace_.buildLog.find("error") == std::string::npos;
        
        // Check test success from log
        bool testsPassed = !currentTrace_.testLog.empty() &&
                          currentTrace_.testLog.find("FAIL") == std::string::npos;
        
        // Check if memory was updated
        bool memoryUpdated = false;
        for (const auto& event : currentTrace_.events) {
            if (event.type == EvidenceEventType::MemoryUpdated) {
                memoryUpdated = true;
                break;
            }
        }
        
        nlohmann::json completion = {
            {"validation_id", "VAL-012"},
            {"goal", currentTrace_.goal},
            {"planned", !currentTrace_.plan.is_null() && !currentTrace_.plan.empty()},
            {"files_modified", filesModified},
            {"build_success", buildSuccess},
            {"tests_passed", testsPassed},
            {"memory_updated", memoryUpdated},
            {"evidence_complete", currentTrace_.completed},
            {"status", currentTrace_.completed ? "COMPLETE" : "INCOMPLETE"},
            {"execution_time_ms", 
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - traceStart_).count()}
        };
        
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        file << completion.dump(2);
        return true;
    } catch (...) {
        return false;
    }
}

std::string EvidenceRecorder::generateTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string EvidenceRecorder::eventTypeToString(EvidenceEventType type) const {
    switch (type) {
        case EvidenceEventType::ActionStarted: return "ActionStarted";
        case EvidenceEventType::ActionCompleted: return "ActionCompleted";
        case EvidenceEventType::ArtifactProduced: return "ArtifactProduced";
        case EvidenceEventType::FailureDetected: return "FailureDetected";
        case EvidenceEventType::RecoveryAttempted: return "RecoveryAttempted";
        case EvidenceEventType::PlanGenerated: return "PlanGenerated";
        case EvidenceEventType::BuildTriggered: return "BuildTriggered";
        case EvidenceEventType::TestTriggered: return "TestTriggered";
        case EvidenceEventType::MemoryUpdated: return "MemoryUpdated";
        default: return "Unknown";
    }
}

} // namespace RawrXD
