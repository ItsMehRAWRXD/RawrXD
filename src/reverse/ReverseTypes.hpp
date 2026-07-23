#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace rxd::reverse {

struct Pattern {
    std::string id;
    std::string mnemonic;
    std::string description;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;      // optional: 0xFF = must match, 0x00 = ignore
    double weight = 1.0;
    int priority = 0;
};

struct Sample {
    std::string input;
    uint8_t output;
    double confidence;
};

struct ReverseModel {
    std::string name;
    std::string type;
    std::string version;
    std::string description;
    std::vector<Pattern> patterns;
    std::vector<Sample> samples;
    double minConfidence = 0.65;
    bool allowPartial = true;
    bool normalizeBytes = true;
    bool dedupeConsecutive = true;
    uint8_t clipMin = 0;
    uint8_t clipMax = 255;
    std::vector<std::string> compatibleWith;
};

struct Match {
    std::string patternId;
    std::string patternName;
    size_t offset;
    size_t length;
    double confidence;
    uint8_t predictedByte;
    std::vector<uint8_t> extractedBytes;
    std::string contextHex;      // surrounding bytes as hex
    bool isValid = true;
};

struct Reconstruction {
    std::vector<uint8_t> bytes;
    std::vector<Match> matches;
    double overallConfidence;
};

} // namespace rxd::reverse
