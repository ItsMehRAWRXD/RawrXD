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

// Forward declarations
std::string EscapeJsonString(const std::string& input);
std::string StageToString(InferenceStage stage);

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
        "tokenization", "embedding", "prefill", "generation",
        "detokenization", "postprocessing"
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
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return witness; // Return empty witness on failure
    }
    
    std::string json((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    file.close();
    
    // Simple JSON parsing for key fields
    auto extractString = [&json](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        
        // Skip whitespace and quotes
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '"')) pos++;
        
        size_t end = pos;
        while (end < json.size() && json[end] != '"' && json[end] != ',' && json[end] != '}') end++;
        
        return json.substr(pos, end - pos);
    };
    
    auto extractUint32 = [&json](const std::string& key) -> uint32_t {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        return static_cast<uint32_t>(std::stoul(json.substr(pos)));
    };
    
    auto extractFloat = [&json](const std::string& key) -> float {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0f;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0f;
        
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        return std::stof(json.substr(pos));
    };
    
    // Extract fields
    witness.modelPath = extractString("modelPath");
    witness.modelSha256 = extractString("modelSha256");
    witness.binarySha256 = extractString("binarySha256");
    witness.promptSha256 = extractString("promptSha256");
    witness.gitCommit = extractString("gitCommit");
    witness.buildTimestamp = extractString("buildTimestamp");
    witness.outputSha256 = extractString("outputSha256");
    witness.errorMessage = extractString("errorMessage");
    
    witness.seed = extractUint32("seed");
    witness.maxTokens = extractUint32("maxTokens");
    witness.topK = extractUint32("topK");
    witness.modelSizeBytes = extractUint32("modelSizeBytes");
    
    witness.temperature = extractFloat("temperature");
    witness.topP = extractFloat("topP");
    
    // Parse stages object
    size_t stagesPos = json.find("\"stages\"");
    if (stagesPos != std::string::npos) {
        size_t braceOpen = json.find("{", stagesPos);
        size_t braceClose = json.find("}", braceOpen);
        
        if (braceOpen != std::string::npos && braceClose != std::string::npos) {
            std::string stagesJson = json.substr(braceOpen + 1, braceClose - braceOpen - 1);
            
            // Parse each stage
            size_t stagePos = 0;
            while ((stagePos = stagesJson.find("\"", stagePos)) != std::string::npos) {
                size_t stageEnd = stagesJson.find("\"", stagePos + 1);
                if (stageEnd == std::string::npos) break;
                
                std::string stageName = stagesJson.substr(stagePos + 1, stageEnd - stagePos - 1);
                
                // Find stage object
                size_t objOpen = stagesJson.find("{", stageEnd);
                size_t objClose = stagesJson.find("}", objOpen);
                if (objOpen == std::string::npos || objClose == std::string::npos) break;
                
                std::string stageObj = stagesJson.substr(objOpen, objClose - objOpen + 1);
                
                StageResult result;
                result.completed = (stageObj.find("\"completed\": true") != std::string::npos);
                result.success = (stageObj.find("\"success\": true") != std::string::npos);
                
                // Extract checksum
                size_t checksumPos = stageObj.find("\"checksum\"");
                if (checksumPos != std::string::npos) {
                    checksumPos = stageObj.find(":", checksumPos);
                    if (checksumPos != std::string::npos) {
                        checksumPos++;
                        while (checksumPos < stageObj.size() && 
                               (stageObj[checksumPos] == ' ' || stageObj[checksumPos] == '\t' || stageObj[checksumPos] == '"')) checksumPos++;
                        
                        size_t checksumEnd = checksumPos;
                        while (checksumEnd < stageObj.size() && 
                               stageObj[checksumEnd] != '"' && stageObj[checksumEnd] != ',' && stageObj[checksumEnd] != '}') checksumEnd++;
                        
                        result.checksum = stageObj.substr(checksumPos, checksumEnd - checksumPos);
                    }
                }
                
                // Map stage name to enum
                InferenceStage stage = InferenceStage::TOKENIZATION;
                if (stageName == "tokenization") stage = InferenceStage::TOKENIZATION;
                else if (stageName == "embedding") stage = InferenceStage::EMBEDDING;
                else if (stageName == "prefill") stage = InferenceStage::PREFILL;
                else if (stageName == "generation") stage = InferenceStage::GENERATION;
                else if (stageName == "detokenization") stage = InferenceStage::DETOKENIZATION;
                else if (stageName == "postprocessing") stage = InferenceStage::POSTPROCESSING;
                
                witness.stages[stage] = result;
                stagePos = objClose + 1;
            }
        }
    }
    
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
    
    // Compute binary SHA256 (current executable)
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) > 0) {
        m_witness.binarySha256 = ComputeFileSha256(exePath);
    } else {
        m_witness.binarySha256 = "sha256:unknown";
    }
    
    // Compute model SHA256 and size
    if (!modelPath.empty()) {
        m_witness.modelSha256 = ComputeFileSha256(modelPath);
        
        // Get model file size
        HANDLE hFile = CreateFileA(modelPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            if (GetFileSizeEx(hFile, &fileSize)) {
                m_witness.modelSizeBytes = static_cast<uint32_t>(fileSize.QuadPart);
            }
            CloseHandle(hFile);
        }
    }
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
    // Windows CryptoAPI SHA256 implementation
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];  // SHA256 produces 32 bytes
    DWORD cbHash = 32;
    std::string result = "sha256:";
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)data.c_str(), (DWORD)data.length(), 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                    // Convert to hex string
                    char hexBuffer[65];
                    for (DWORD i = 0; i < cbHash; i++) {
                        sprintf(hexBuffer + (i * 2), "%02x", rgbHash[i]);
                    }
                    hexBuffer[64] = '\0';
                    result += hexBuffer;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    // Fallback if CryptoAPI fails
    if (result == "sha256:") {
        std::ostringstream oss;
        oss << std::hex << std::hash<std::string>{}(data);
        result += oss.str();
    }
    
    return result;
}

std::string ComputeSha256(const std::vector<uint8_t>& data) {
    // Windows CryptoAPI SHA256 implementation
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 32;
    std::string result = "sha256:";
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data.data(), (DWORD)data.size(), 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                    char hexBuffer[65];
                    for (DWORD i = 0; i < cbHash; i++) {
                        sprintf(hexBuffer + (i * 2), "%02x", rgbHash[i]);
                    }
                    hexBuffer[64] = '\0';
                    result += hexBuffer;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    // Fallback
    if (result == "sha256:") {
        std::ostringstream oss;
        size_t hash = 0;
        for (auto b : data) {
            hash = hash * 31 + b;
        }
        oss << std::hex << hash;
        result += oss.str();
    }
    
    return result;
}

std::string ComputeFileSha256(const std::string& path) {
    // Windows CryptoAPI SHA256 for file
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 32;
    std::string result = "sha256:";
    
    // Open file
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return result + "file_not_found";
    }
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            // Read file in chunks and hash
            const DWORD CHUNK_SIZE = 65536;
            std::vector<BYTE> buffer(CHUNK_SIZE);
            DWORD bytesRead;
            BOOL hashSuccess = TRUE;
            
            while (ReadFile(hFile, buffer.data(), CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
                if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) {
                    hashSuccess = FALSE;
                    break;
                }
            }
            
            if (hashSuccess && CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                char hexBuffer[65];
                for (DWORD i = 0; i < cbHash; i++) {
                    sprintf(hexBuffer + (i * 2), "%02x", rgbHash[i]);
                }
                hexBuffer[64] = '\0';
                result += hexBuffer;
            }
            
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    CloseHandle(hFile);
    
    // Fallback
    if (result == "sha256:") {
        result += "hash_failed";
    }
    
    return result;
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
        case InferenceStage::TOKENIZATION: return "tokenization";
        case InferenceStage::EMBEDDING: return "embedding";
        case InferenceStage::PREFILL: return "prefill";
        case InferenceStage::GENERATION: return "generation";
        case InferenceStage::DETOKENIZATION: return "detokenization";
        case InferenceStage::POSTPROCESSING: return "postprocessing";
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
