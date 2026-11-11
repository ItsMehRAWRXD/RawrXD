//============================================================================
// nevm_failure_artifacts.hpp
// RawrXD N-EVM - Failure Artifact Capture
// Captures state for reproducible intermittent bug debugging
//============================================================================

#pragma once

#include <string>
#include <fstream>
#include <filesystem>
#include <json/json.h>
#include <chrono>
#include <sstream>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Failure Context
//============================================================================

struct FailureContext {
    std::string model_hash;
    Json::Value plan_version;
    std::vector<uint8_t> kv_page_state;
    Json::Value residency_timeline;
    std::vector<int32_t> last_tokens;
    Json::Value benchmark_context;
    
    std::string timestamp;
    int failed_step;
    std::string failure_type;
    std::string failure_message;
};

//============================================================================
// Artifact Collector
//============================================================================

class FailureArtifactCollector {
public:
    FailureArtifactCollector(const std::string& output_dir = "failure_artifacts")
        : output_dir_(output_dir) {}
    
    void Capture(const FailureContext& context) {
        // Create timestamped directory
        std::string dir = CreateArtifactDirectory();
        
        // Write model hash
        WriteFile(dir + "/model_hash.txt", context.model_hash);
        
        // Write plan version
        WriteJSON(dir + "/plan_version.json", context.plan_version);
        
        // Write KV page state
        WriteBinary(dir + "/kv_page_state.bin", context.kv_page_state);
        
        // Write residency timeline
        WriteJSON(dir + "/residency_timeline.json", context.residency_timeline);
        
        // Write last tokens
        WriteTokens(dir + "/last_tokens.txt", context.last_tokens);
        
        // Write benchmark context
        WriteJSON(dir + "/benchmark_context.json", context.benchmark_context);
        
        // Write failure summary
        Json::Value summary;
        summary["timestamp"] = context.timestamp;
        summary["failed_step"] = context.failed_step;
        summary["failure_type"] = context.failure_type;
        summary["failure_message"] = context.failure_message;
        WriteJSON(dir + "/failure_summary.json", summary);
        
        std::cerr << "\nFailure artifacts captured to: " << dir << "\n";
    }
    
    std::string GetLastArtifactPath() const {
        return last_artifact_path_;
    }

private:
    std::string output_dir_;
    std::string last_artifact_path_;
    
    std::string CreateArtifactDirectory() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << output_dir_ << "/failure_";
        ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
        
        std::string dir = ss.str();
        std::filesystem::create_directories(dir);
        
        last_artifact_path_ = dir;
        return dir;
    }
    
    void WriteFile(const std::string& path, const std::string& content) {
        std::ofstream file(path);
        file << content;
    }
    
    void WriteJSON(const std::string& path, const Json::Value& json) {
        std::ofstream file(path);
        Json::StreamWriterBuilder builder;
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(json, &file);
    }
    
    void WriteBinary(const std::string& path, const std::vector<uint8_t>& data) {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    
    void WriteTokens(const std::string& path, const std::vector<int32_t>& tokens) {
        std::ofstream file(path);
        for (size_t i = 0; i < tokens.size(); ++i) {
            file << tokens[i];
            if (i < tokens.size() - 1) file << " ";
        }
    }
};

} // namespace NEVM
} // namespace RawrXD
