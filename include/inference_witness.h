// ============================================================================
// inference_witness.h — VAL-051 Deterministic Generation Witness
// ============================================================================
// Execution manifest for inference pipeline evidence capture.
// Every run produces a witness artifact, whether success or failure.
//
// Schema: VAL-051
// Purpose: Transform "component exists" into "exact binary produced exact output"
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace RawrXD {
namespace Evidence {

// ============================================================================
// Inference Stage Status
// ============================================================================
enum class InferenceStage : uint32_t {
    ModelLoad     = 0,
    Tokenizer     = 1,
    Embedding     = 2,
    ForwardPass   = 3,
    KVCache       = 4,
    Sampler       = 5,
    TokenOutput   = 6,
    COUNT
};

// ============================================================================
// Stage Result
// ============================================================================
struct StageResult {
    bool completed = false;
    bool success = false;
    uint64_t durationMicros = 0;
    std::string errorMessage;
    std::string checksum;  // Stage-specific hash (e.g., tensor hash, token hash)
};

// ============================================================================
// Inference Witness — VAL-051 Schema
// ============================================================================
struct InferenceWitness {
    // Schema version
    static constexpr const char* SCHEMA = "VAL-051";
    static constexpr uint32_t VERSION = 1;

    // Build provenance
    std::string gitCommit;
    std::string binarySha256;
    std::string buildTimestamp;

    // Model provenance
    std::string modelPath;
    std::string modelSha256;
    uint64_t modelSizeBytes = 0;
    std::string modelFormat;  // "GGUF", "GGML", etc.

    // Execution parameters
    std::string promptSha256;
    uint64_t promptTokenCount = 0;
    uint32_t seed = 42;
    float temperature = 0.0f;
    float topP = 0.0f;
    uint32_t topK = 0;
    uint32_t maxTokens = 0;

    // Stage execution results
    std::map<InferenceStage, StageResult> stages;

    // Output (if successful)
    std::string outputText;
    std::string outputTokenChecksum;
    std::string logitsChecksum;
    uint64_t outputTokenCount = 0;

    // Overall result
    bool executionSuccess = false;
    uint64_t totalDurationMicros = 0;
    std::string executionTimestamp;

    // Failure context (if failed)
    std::string failureStage;
    std::string failureReason;

    // Methods
    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum = "");
    void RecordStageError(InferenceStage stage, const std::string& error);
    void Finalize(bool success);

    // Serialization
    std::string ToJson() const;
    bool SaveToFile(const std::string& path) const;
    static InferenceWitness LoadFromFile(const std::string& path);
};

// ============================================================================
// Witness Recorder — RAII evidence capture
// ============================================================================
class WitnessRecorder {
public:
    explicit WitnessRecorder(const std::string& modelPath, const std::string& prompt);
    ~WitnessRecorder();

    void SetParameters(uint32_t seed, float temperature, float topP, uint32_t topK, uint32_t maxTokens);
    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success, const std::string& checksum = "");
    void RecordStageError(InferenceStage stage, const std::string& error);
    void SetOutput(const std::string& text, const std::string& tokenChecksum, const std::string& logitsChecksum);
    void Finalize(bool success);

    const InferenceWitness& GetWitness() const { return m_witness; }
    std::string SaveToDefaultLocation() const;

private:
    InferenceWitness m_witness;
    std::map<InferenceStage, uint64_t> m_stageStartTimes;
    bool m_finalized = false;
};

// ============================================================================
// Utility Functions
// ============================================================================
std::string ComputeSha256(const std::string& data);
std::string ComputeSha256(const std::vector<uint8_t>& data);
std::string ComputeFileSha256(const std::string& path);
std::string GetCurrentTimestampIso8601();
std::string GetGitCommitHash();

} // namespace Evidence
} // namespace RawrXD
