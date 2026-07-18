#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace RawrXD {

// Minimal evidence recorder for VAL-012 validation
class EvidenceRecorder {
public:
    inline EvidenceRecorder(const std::string& basePath) : basePath_(basePath) {}
    
    inline void beginTrace(const std::string& goal) {
        trace_ = nlohmann::json::object();
        trace_["goal"] = goal;
        trace_["timestamp_start"] = getTimestamp();
        trace_["steps"] = nlohmann::json::array();
    }
    
    inline void recordPlanGenerated(const nlohmann::json& plan) {
        trace_["plan"] = plan;
        trace_["steps"].push_back({
            {"step", "plan"},
            {"status", "generated"},
            {"timestamp", getTimestamp()}
        });
    }
    
    inline void recordArtifact(const std::string& name, const std::string& path) {
        trace_["artifacts"] = trace_.value("artifacts", nlohmann::json::array());
        trace_["artifacts"].push_back({
            {"name", name},
            {"path", path},
            {"timestamp", getTimestamp()}
        });
    }
    
    inline void recordBuildCompleted(bool success, const std::string& message) {
        trace_["steps"].push_back({
            {"step", "build"},
            {"status", success ? "success" : "failure"},
            {"message", message},
            {"timestamp", getTimestamp()}
        });
    }
    
    inline void recordTestCompleted(bool success, const std::string& message) {
        trace_["steps"].push_back({
            {"step", "test"},
            {"status", success ? "success" : "failure"},
            {"message", message},
            {"timestamp", getTimestamp()}
        });
    }
    
    inline void recordMemoryUpdated() {
        trace_["steps"].push_back({
            {"step", "memory"},
            {"status", "updated"},
            {"timestamp", getTimestamp()}
        });
    }
    
    inline void endTrace(bool success) {
        trace_["timestamp_end"] = getTimestamp();
        trace_["success"] = success;
    }
    
    inline void saveTrace() {
        std::filesystem::create_directories(basePath_ + "/result");
        std::ofstream file(basePath_ + "/result/trace.json");
        file << trace_.dump(2);
    }
    
    inline void generateCompletionJson(const std::string& path) {
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        
        nlohmann::json completion = {
            {"validation_id", "VAL-012"},
            {"title", "Closed-Loop Autonomous Task Demonstration"},
            {"status", trace_.value("success", false) ? "PASS" : "FAIL"},
            {"timestamp", getTimestamp()},
            {"goal", trace_.value("goal", "")},
            {"steps_executed", trace_["steps"].size()},
            {"artifacts_produced", trace_.value("artifacts", nlohmann::json::array()).size()},
            {"evidence_path", basePath_},
            {"verification_level", "V"},
            {"notes", "First system-level proof of Planner → Executor → Build → Test → Evidence"}
        };
        
        std::ofstream file(path);
        file << completion.dump(2);
    }
    
private:
    std::string basePath_;
    nlohmann::json trace_;
    
    inline std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&time));
        return buf;
    }
};

} // namespace RawrXD