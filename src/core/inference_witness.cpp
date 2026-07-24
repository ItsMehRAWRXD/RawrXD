// ============================================================================
// inference_witness.cpp — VAL-051 Deterministic Generation Witness
// ============================================================================
// Implementation of execution manifest for inference pipeline evidence capture.
// ============================================================================

#include "inference_witness.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace RawrXD {
namespace Evidence {

// ============================================================================
// InferenceWitness Methods
// ============================================================================

void InferenceWitness::RecordStageStart(InferenceStage stage) {
    auto it = stages.find(stage);
    if (it == stages.end()) {
        stages[stage] = StageResult{};
    }
    stages[stage].completed = false;
}

void InferenceWitness::RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum) {
    auto it = stages.find(stage);
    if (it != stages.end()) {
        it->second.completed = true;
        it->second.success = success;
        it->second.checksum = checksum;
    }
}

void InferenceWitness::RecordStageError(InferenceStage stage, const std::string& error) {
    auto it = stages.find(stage);
    if (it != stages.end()) {
        it->second.completed = true;
        it->second.success = false;
        it->second.errorMessage = error;
    }
}

void InferenceWitness::Finalize(bool success) {
    executionSuccess = success;
    executionTimestamp = GetCurrentTimestampIso8601();
    
    // Calculate total duration from stage results
    totalDurationMicros = 0;
    for (const auto& [stage, result] : stages) {
        totalDurationMicros += result.durationMicros;
    }
}

std::string InferenceWitness::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    
    // Schema
    json << "  \"schema\": \"" << SCHEMA << "\",\n";
    json << "  \"version\": " << VERSION << ",\n";
    
    // Build provenance
    json << "  \"build\": {\n";
    json << "    \"gitCommit\": \"" << EscapeJsonString(gitCommit) << "\",\n";
    json << "    \"binarySha256\": \"" << binarySha256 << "\",\n";
    json << "    \"timestamp\": \"" << buildTimestamp << "\"\n";
    json << "  },\n";
    
    // Model provenance
    json << "  \"model\": {\n";
    json << "    \"path\": \"" << EscapeJsonString(modelPath) << "\",\n";
    json << "    \"sha256\": \"" << modelSha256 << "\",\n";
    json << "    \"sizeBytes\": " << modelSizeBytes << ",\n";
    json << "    \"format\": \"" << modelFormat << "\"\n";
    json << "  },\n";
    
    // Execution parameters
    json << "  \"parameters\": {\n";
    json << "    \"promptSha256\": \"" << promptSha256 << "\",\n";
    json << "    \"promptTokenCount\": " << promptTokenCount << ",\n";
    json << "    \"seed\": " << seed << ",\n";
    json << "    \"temperature\": " << temperature << ",\n";
    json << "    \"topP\": " << topP << ",\n";
    json << "    \"topK\": " << topK << ",\n";
    json << "    \"maxTokens\": " << maxTokens << "\n";
    json << "  },\n";
    
    // Stage results
    json << "  \"stages\": {\n";
    const char* stageNames[] = {
        "modelLoad", "tokenizer", "embedding", "forwardPass",
        "kvCache", "sampler", "tokenOutput"
    };
    bool first = true;
    for (size_t i = 0; i < static_cast<size_t>(InferenceStage::COUNT); ++i) {
        InferenceStage stage = static_cast<InferenceStage>(i);
        auto it = stages.find(stage);
        if (it != stages.end()) {
            if (!first) json << ",\n";
            first = false;
            json << "    \"" << stageNames[i] << "\": {\n";
            json << "      \"completed\": " << (it->second.completed ? "true" : "false") << ",\n";
            json << "      \"success\": " << (it->second.success ? "true" : "false") << ",\n";
            json << "      \"durationMicros\": " << it->second.durationMicros << ",\n";
            json << "      \"checksum\": \"" << it->second.checksum << "\"";
            if (!it->second.errorMessage.empty()) {
                json << ",\n      \"error\": \"" << EscapeJsonString(it->second.errorMessage) << "\"";
            }
            json << "\n    }";
        }
    }
    json << "\n  },\n";
    
    // Output
    json << "  \"output\": {\n";
    json << "    \"text\": \"" << EscapeJsonString(outputText) << "\",\n";
    json << "    \"tokenChecksum\": \"" << outputTokenChecksum << "\",\n";
    json << "    \"logitsChecksum\": \"" << logitsChecksum << "\",\n";
    json << "    \"tokenCount\": " << outputTokenCount << "\n";
    json << "  },\n";
    
    // Execution result
    json << "  \"execution\": {\n";
    json << "    \"success\": " << (executionSuccess ? "true" : "false") << ",\n";
    json << "    \"timestamp\": \"" << executionTimestamp << "\",\n";
    json << "    \"totalDurationMicros\": " << totalDurationMicros << "\n";
    json << "  }";
    
    // Failure context (if applicable)
    if (!executionSuccess && (!failureStage.empty() || !failureReason.empty())) {
        json << ",\n  \"failure\": {\n";
        json << "    \"stage\": \"" << failureStage << "\",\n";
        json << "    \"reason\": \"" << EscapeJsonString(failureReason) << "\"\n";
        json << "  }";
    }
    
    json << "\n}\n";
    return json.str();
}

bool InferenceWitness::SaveToFile(const std::string& path) const {
    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << ToJson();
    file.close();
    return true;
}

InferenceWitness InferenceWitness::LoadFromFile(const std::string& path) {
    InferenceWitness witness;
    // TODO: Implement JSON parsing if needed
    return witness;
}

// ============================================================================
// WitnessRecorder Methods
// ============================================================================

WitnessRecorder::WitnessRecorder(const std::string& modelPath, const std::string& prompt) {
    m_witness.modelPath = modelPath;
    m_witness.promptSha256 = ComputeSha256(prompt);
    m_witness.gitCommit = GetGitCommitHash();
    m_witness.buildTimestamp = GetCurrentTimestampIso8601();
    
    // TODO: Compute binary SHA256
    // TODO: Compute model SHA256 and size
}

WitnessRecorder::~WitnessRecorder() {
    if (!m_finalized) {
        Finalize(false);
    }
}

void WitnessRecorder::SetParameters(uint32_t seed, float temperature, float topP, uint32_t topK, uint32_t maxTokens) {
    m_witness.seed = seed;
    m_witness.temperature = temperature;
    m_witness.topP = topP;
    m_witness.topK = topK;
    m_witness.maxTokens = maxTokens;
}

void WitnessRecorder::RecordStageStart(InferenceStage stage) {
    m_witness.RecordStageStart(stage);
    m_stageStartTimes[stage] = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void WitnessRecorder::RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum) {
    auto it = m_stageStartTimes.find(stage);
    if (it != m_stageStartTimes.end()) {
        uint64_t endTime = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        m_witness.stages[stage].durationMicros = endTime - it->second;
    }
    m_witness.RecordStageComplete(stage, success, checksum);
}

void WitnessRecorder::RecordStageError(InferenceStage stage, const std::string& error) {
    m_witness.RecordStageError(stage, error);
    m_witness.failureStage = StageToString(stage);
    m_witness.failureReason = error;
}

void WitnessRecorder::SetOutput(const std::string& text, const std::string& tokenChecksum, const std::string& logitsChecksum) {
    m_witness.outputText = text;
    m_witness.outputTokenChecksum = tokenChecksum;
    m_witness.logitsChecksum = logitsChecksum;
}

void WitnessRecorder::Finalize(bool success) {
    if (m_finalized) return;
    m_finalized = true;
    m_witness.Finalize(success);
}

std::string WitnessRecorder::SaveToDefaultLocation() const {
    std::string path = "evidence/inference_witness_" + 
        std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".json";
    m_witness.SaveToFile(path);
    return path;
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string ComputeSha256(const std::string& data) {
    // Placeholder - implement actual SHA256
    std::ostringstream oss;
    oss << "sha256:" << std::hex << std::hash<std::string>{}(data);
    return oss.str();
}

std::string ComputeSha256(const std::vector<uint8_t>& data) {
    // Placeholder - implement actual SHA256
    std::ostringstream oss;
    size_t hash = 0;
    for (auto b : data) {
        hash = hash * 31 + b;
    }
    oss << "sha256:" << std::hex << hash;
    return oss.str();
}

std::string ComputeFileSha256(const std::string& path) {
    // Placeholder - implement actual file SHA256
    return "sha256:file_placeholder";
}

std::string GetCurrentTimestampIso8601() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return oss.str();
}

std::string GetGitCommitHash() {
    // Placeholder - would be populated at build time
    return "unknown";
}

std::string StageToString(InferenceStage stage) {
    switch (stage) {
        case InferenceStage::ModelLoad: return "modelLoad";
        case InferenceStage::Tokenizer: return "tokenizer";
        case InferenceStage::Embedding: return "embedding";
        case InferenceStage::ForwardPass: return "forwardPass";
        case InferenceStage::KVCache: return "kvCache";
        case InferenceStage::Sampler: return "sampler";
        case InferenceStage::TokenOutput: return "tokenOutput";
        default: return "unknown";
    }
}

std::string EscapeJsonString(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    oss << c;
                } else {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
        }
    }
    return oss.str();
}

} // namespace Evidence
} // namespace RawrXD
