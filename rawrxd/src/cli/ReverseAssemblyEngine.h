// RAWRXD_REVERSE_ASSEMBLY_ENGINE_001
// BigDaddyG-Reverse-Model v1.5 C++ integration
// Loads JSON model, performs sequence matching, predicts bytes with confidence.

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace rawrxd::reverse {

// ---------------------------------------------------------------------------
// Model structures (match JSON schema exactly)
// ---------------------------------------------------------------------------
struct Pattern {
    std::string id;
    std::string patternText;
    std::string description;
    std::vector<uint8_t> bytes;
};

struct Sample {
    std::string input;
    uint8_t output = 0;
    double confidence = 0.0;
};

struct PostProcessing {
    bool dedupeConsecutive = true;
    bool normalizeByteRange = true;
    uint8_t clipMin = 0;
    uint8_t clipMax = 255;
};

struct ModelMetadata {
    double accuracy = 0.0;
    uint32_t trainingSamples = 0;
    std::string lastTrained;
};

struct ReverseAssemblyModel {
    std::string name;
    std::string type;
    std::string version;
    std::string description;
    ModelMetadata metadata;
    std::vector<Pattern> patterns;
    std::vector<Sample> samples;
    PostProcessing postProcessing;
    double minConfidence = 0.65;
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------
class ReverseAssemblyEngine {
public:
    // Load model from JSON file. Returns false with diagnostic on failure.
    bool loadFromFile(const std::string& path, std::string* diag = nullptr);

    // Predict next byte from input text (e.g. "Reverse assembly for: push ebp").
    // Returns empty if no pattern or confidence below threshold.
    std::optional<uint8_t> predictByte(const std::string& input, double* outConfidence = nullptr) const;

    // Match a pattern ID against known patterns.
    const Pattern* findPattern(const std::string& id) const;

    // Run post-processing on a predicted byte sequence.
    std::vector<uint8_t> postProcess(std::vector<uint8_t> bytes) const;

    // Diagnostics
    size_t patternCount() const { return model_.patterns.size(); }
    size_t sampleCount() const { return model_.samples.size(); }
    const ReverseAssemblyModel& model() const { return model_; }

private:
    ReverseAssemblyModel model_;
    std::unordered_map<std::string, size_t> patternIndex_; // id -> patterns[] index
};

// ---------------------------------------------------------------------------
// JSON loader (standalone, no external deps beyond nlohmann/json if available)
// ---------------------------------------------------------------------------
// If nlohmann/json is NOT in the build, a minimal fallback parser is used.
// The fallback only supports the exact schema v1.5 produces.
bool LoadReverseModelFromJson(const std::string& jsonText, ReverseAssemblyModel* out, std::string* diag);

} // namespace rawrxd::reverse
