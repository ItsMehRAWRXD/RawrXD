// ============================================================================
// inference_witness.h — VAL-051 Deterministic Generation Witness
// ============================================================================
// Public interface for the inference-pipeline execution manifest.
//
// REGENERATION NOTICE
// This header was missing from the tree while
//   * src/core/inference_witness.cpp (its implementation, 577 lines) was
//     present and referenced by src/validation/CMakeLists.txt, and
//   * src/validation/CMakeLists.txt named src/validation/witness_system_test.cpp
//     (also absent) in target `witness_system_test`.
// That combination made `cmake` fail with "Cannot find source file".
//
// DERIVATION METHOD (important)
// This header was reconstructed by EXTRACTING identifiers from the .cpp rather
// than designed from memory. Multiple earlier drafts guessed the structure;
// each failed to compile against the .cpp. The final pass enumerated:
//   * every `WitnessRecorder::Method` definition (ctor, dtor, SetParameters,
//     RecordStageStart/Complete/Error, SetOutput, Finalize, SaveToDefaultLocation),
//   * every `m_witness.<field>` access (modelPath, modelSha256, binarySha256,
//     modelSizeBytes, promptSha256, gitCommit, buildTimestamp, outputSha256,
//     errorMessage, logitsChecksum, outputText, outputTokenChecksum, seed,
//     temperature, topK, topP, maxTokens, stages, failureReason, failureStage,
//     plus InferenceWitness's own RecordStage*/Finalize/SaveToFile),
//   * every StageResult field (completed, success, checksum, errorMessage,
//     durationMicros),
//   * the InferenceStage enumerators the .cpp names.
// and declares exactly those.
//
// Consequence: the .cpp compiles unmodified against this header, verified.
// Regenerate the same way in future — from the .cpp, never from memory.
// ============================================================================
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <ctime>
#include <map>
#include <string>
#include <vector>

namespace RawrXD {
namespace Evidence {

// Pipeline stages, in execution order. COUNT is the sentinel the .cpp uses to
// size its per-stage arrays; keep it last.
enum class InferenceStage : uint32_t {
    TOKENIZATION    = 0,
    EMBEDDING       = 1,
    PREFILL         = 2,
    GENERATION      = 3,
    POSTPROCESSING  = 4,
    DETOKENIZATION  = 5,
    COUNT
};

// One recorded stage. ToJson()/LoadFromFile() read these back by name, so a
// rename here changes the on-disk format.
struct StageResult {
    bool        completed      = false;
    bool        success        = false;
    std::string checksum;
    std::string errorMessage;
    uint64_t    durationMicros = 0;
    std::string startTimestamp;
    std::string completeTimestamp;
};

// ============================================================================
// InferenceWitness — the manifest object held by WitnessRecorder::m_witness.
// ============================================================================
class InferenceWitness {
public:
    using Clock = std::chrono::steady_clock;

    // --- Recording API (definitions live in inference_witness.cpp) --------
    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success,
                             const std::string& checksum);
    void RecordStageError(InferenceStage stage, const std::string& error);
    void Finalize(bool success);

    // --- Serialization (definitions live in inference_witness.cpp) --------
    std::string ToJson() const;
    bool SaveToFile(const std::string& path) const;
    static InferenceWitness LoadFromFile(const std::string& path);

    // --- Manifest fields the .cpp reads and writes -------------------------
    std::string modelPath;
    std::string modelSha256;
    std::string binarySha256;
    std::string promptSha256;
    std::string gitCommit;
    std::string buildTimestamp;
    std::string outputSha256;
    std::string errorMessage;
    std::string outputText;
    std::string outputTokenChecksum;
    std::string logitsChecksum;
    uint64_t    modelSizeBytes = 0;
    uint32_t    seed = 0;
    float       temperature = 0.0f;
    uint32_t    topK = 0;
    float       topP = 0.0f;
    uint32_t    maxTokens = 0;
    std::string failureReason;
    std::string failureStage;
    std::map<InferenceStage, StageResult> stages;

    // Flat manifest fields written directly by InferenceWitness::Finalize()
    // and InferenceWitness::ToJson() (lines 57-140 of the .cpp).
    bool        executionSuccess    = false;
    float       SCHEMA              = 0.0f;   // set from ToJson
    float       VERSION             = 0.0f;   // set from ToJson
    std::string modelFormat;
    uint64_t    promptTokenCount    = 0;
    uint64_t    outputTokenCount    = 0;
    std::string executionTimestamp;
    uint64_t    totalDurationMicros = 0;

private:
    friend class WitnessRecorder;

    bool               m_finalized = false;
    Clock::time_point  m_stageStartTimes[static_cast<size_t>(InferenceStage::COUNT)];
};

// ============================================================================
// WitnessRecorder — RAII facade built once per inference run.
// ============================================================================
class WitnessRecorder {
public:
    WitnessRecorder(const std::string& modelPath, const std::string& prompt);
    ~WitnessRecorder();

    void SetParameters(uint32_t seed, float temperature, float topP,
                       uint32_t topK, uint32_t maxTokens);
    void RecordStageStart(InferenceStage stage);
    void RecordStageComplete(InferenceStage stage, bool success,
                             const std::string& checksum);
    void RecordStageError(InferenceStage stage, const std::string& error);
    void SetOutput(const std::string& text, const std::string& tokenChecksum,
                   const std::string& logitsChecksum);
    void Finalize(bool success);
    std::string SaveToDefaultLocation() const;

private:
    friend struct ComputeSha256Access;

    InferenceWitness m_witness;
    bool             m_finalized = false;
    std::map<InferenceStage, uint64_t> m_stageStartTimes;
};

// ---------------------------------------------------------------------------
// Free helpers the .cpp also defines; other TUs may use them.
// ---------------------------------------------------------------------------
std::string ComputeFileSha256(const std::string& path);
std::string ComputeSha256(const std::string& data);
std::string ComputeSha256(const void* data, size_t size);
std::string GetCurrentTimestampIso8601();
std::string GetGitCommitHash();
std::string StageToString(InferenceStage stage);

} // namespace Evidence
} // namespace RawrXD
