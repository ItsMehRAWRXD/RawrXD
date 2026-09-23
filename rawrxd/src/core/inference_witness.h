// ============================================================================
// inference_witness.h — VAL-051 Deterministic Generation Witness
// ============================================================================
#pragma once

#include <string>
#include <map>
#include <vector>
#include <cstdint>

namespace RawrXD {
namespace Evidence {

enum class InferenceStage {
    TOKENIZATION,
    EMBEDDING,
    PREFILL,
    GENERATION,
    DETOKENIZATION,
    POSTPROCESSING,
    COUNT
};

struct StageResult {
    bool completed = false;
    bool success = false;
    std::string checksum;
    std::string errorMessage;
    uint64_t durationMicros = 0;
};

class InferenceWitness {
public:
    static constexpr const char* SCHEMA = "rawrxd.inference.witness.v1";
    static constexpr int VERSION = 1;

    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum);
    void RecordStageError(InferenceStage stage, const std::string& error);
    void Finalize(bool success);
    std::string ToJson() const;
    bool SaveToFile(const std::string& path) const;
    static InferenceWitness LoadFromFile(const std::string& path);

    std::map<InferenceStage, StageResult> stages;
    bool executionSuccess = false;
    std::string executionTimestamp;
    uint64_t totalDurationMicros = 0;

    std::string gitCommit;
    std::string binarySha256;
    std::string buildTimestamp;

    std::string modelPath;
    std::string modelSha256;
    uint64_t modelSizeBytes = 0;
    std::string modelFormat;

    std::string promptSha256;
    uint64_t promptTokenCount = 0;
    int64_t seed = 0;
    double temperature = 0.0;
    double topP = 0.0;
    int topK = 0;
    uint64_t maxTokens = 0;

    std::string outputText;
    std::string outputTokenChecksum;
    std::string logitsChecksum;
    uint64_t outputTokenCount = 0;

    std::string failureStage;
    std::string failureReason;

    // Additional fields used by LoadFromFile
    std::string outputSha256;
    std::string errorMessage;
};

class WitnessRecorder {
public:
    WitnessRecorder(const std::string& modelPath, const std::string& prompt);
    ~WitnessRecorder();
    void SetParameters(uint32_t seed, float temperature, float topP, uint32_t topK, uint32_t maxTokens);
    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum);
    void RecordStageError(InferenceStage stage, const std::string& error);
    void SetOutput(const std::string& text, const std::string& tokenChecksum, const std::string& logitsChecksum);
    void Finalize(bool success);
    std::string SaveToDefaultLocation() const;
    const InferenceWitness& Witness() const { return m_witness; }
private:
    InferenceWitness m_witness;
    std::map<InferenceStage, uint64_t> m_stageStartTimes;
    bool m_finalized = false;
};

std::string GetCurrentTimestampIso8601();
std::string GetGitCommitHash();
std::string ComputeSha256(const std::string& data);
std::string ComputeSha256(const std::vector<uint8_t>& data);
std::string ComputeFileSha256(const std::string& path);
std::string EscapeJsonString(const std::string& input);
std::string StageToString(InferenceStage stage);

} // namespace Evidence
} // namespace RawrXD
