// RAWRXD_REVERSE_ASSEMBLY_ENGINE_001
// Implementation of BigDaddyG-Reverse-Model v1.5 engine

#include "ReverseAssemblyEngine.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace rawrxd::reverse {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// JSON loading
// ---------------------------------------------------------------------------
bool LoadReverseModelFromJson(const std::string& jsonText, ReverseAssemblyModel* out, std::string* diag) {
    if (!out) {
        if (diag) *diag = "Null output pointer";
        return false;
    }
    try {
        json j = json::parse(jsonText);
        
        out->name = j.value("name", "");
        out->type = j.value("type", "");
        out->version = j.value("version", "");
        out->description = j.value("model_description", "");
        
        // Metadata
        if (j.contains("metadata")) {
            auto& md = j["metadata"];
            out->metadata.accuracy = md.value("accuracy", 0.0);
            out->metadata.trainingSamples = md.value("training_samples", 0);
            if (md.contains("last_trained") && md["last_trained"].contains("DateTime")) {
                out->metadata.lastTrained = md["last_trained"]["DateTime"].get<std::string>();
            }
        }
        
        // Pattern settings
        if (j.contains("pattern_settings")) {
            auto& ps = j["pattern_settings"];
            out->minConfidence = ps.value("min_confidence", 0.65);
        }
        
        // Patterns
        if (j.contains("patterns")) {
            for (auto& p : j["patterns"]) {
                Pattern pat;
                pat.id = p.value("id", "");
                pat.patternText = p.value("pattern", "");
                pat.description = p.value("description", "");
                if (p.contains("bytes")) {
                    for (auto& b : p["bytes"]) {
                        pat.bytes.push_back(static_cast<uint8_t>(b.get<int>()));
                    }
                }
                out->patterns.push_back(std::move(pat));
            }
        }
        
        // Samples
        if (j.contains("samples")) {
            for (auto& s : j["samples"]) {
                Sample sam;
                sam.input = s.value("input", "");
                sam.output = static_cast<uint8_t>(s.value("output", 0));
                sam.confidence = s.value("confidence", 0.0);
                out->samples.push_back(std::move(sam));
            }
        }
        
        // Post-processing
        if (j.contains("post_processing")) {
            auto& pp = j["post_processing"];
            out->postProcessing.dedupeConsecutive = pp.value("dedupe_consecutive", true);
            out->postProcessing.normalizeByteRange = pp.value("normalize_byte_range", true);
            if (pp.contains("clip_range") && pp["clip_range"].size() >= 2) {
                out->postProcessing.clipMin = static_cast<uint8_t>(pp["clip_range"][0].get<int>());
                out->postProcessing.clipMax = static_cast<uint8_t>(pp["clip_range"][1].get<int>());
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        if (diag) *diag = std::string("JSON parse error: ") + e.what();
        return false;
    }
}

// ---------------------------------------------------------------------------
// ReverseAssemblyEngine
// ---------------------------------------------------------------------------
bool ReverseAssemblyEngine::loadFromFile(const std::string& path, std::string* diag) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (diag) *diag = "Cannot open file: " + path;
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (!LoadReverseModelFromJson(content, &model_, diag)) {
        return false;
    }
    // Build pattern index
    patternIndex_.clear();
    for (size_t i = 0; i < model_.patterns.size(); ++i) {
        patternIndex_[model_.patterns[i].id] = i;
    }
    return true;
}

const Pattern* ReverseAssemblyEngine::findPattern(const std::string& id) const {
    auto it = patternIndex_.find(id);
    if (it != patternIndex_.end()) {
        return &model_.patterns[it->second];
    }
    return nullptr;
}

std::optional<uint8_t> ReverseAssemblyEngine::predictByte(const std::string& input, double* outConfidence) const {
    // Simple lookup: find exact pattern match in input string
    for (const auto& pat : model_.patterns) {
        if (input.find(pat.patternText) != std::string::npos) {
            if (!pat.bytes.empty()) {
                if (outConfidence) {
                    // Containment is not an exact match. Report measured coverage
                    // as confidence; never assert 1.0 from a substring test.
                    const double hit = input.empty() ? 0.0
                        : pat.patternText.size() / (double)input.size();
                    *outConfidence = hit < 1.0 ? hit : 1.0;
                }
                return pat.bytes[0];
            }
        }
    }
    
    // Fallback: sample-based prediction using input similarity
    double bestScore = model_.minConfidence;
    uint8_t bestByte = 0;
    bool found = false;
    
    for (const auto& sam : model_.samples) {
        // Very basic string similarity: exact prefix match or containment
        if (input.find(sam.input) != std::string::npos || sam.input.find(input) != std::string::npos) {
            if (sam.confidence > bestScore) {
                bestScore = sam.confidence;
                bestByte = sam.output;
                found = true;
            }
        }
    }
    
    if (found) {
        if (outConfidence) *outConfidence = bestScore;
        return bestByte;
    }
    
    return std::nullopt;
}

std::vector<uint8_t> ReverseAssemblyEngine::postProcess(std::vector<uint8_t> bytes) const {
    if (model_.postProcessing.normalizeByteRange) {
        if (model_.postProcessing.clipMin <= model_.postProcessing.clipMax) {
            for (auto& b : bytes) {
                if (b < model_.postProcessing.clipMin) b = model_.postProcessing.clipMin;
                if (b > model_.postProcessing.clipMax) b = model_.postProcessing.clipMax;
            }
        }
        // If clipMin > clipMax the range is invalid; return unmodified.
    }
    if (model_.postProcessing.dedupeConsecutive) {
        // std::unique removes ALL duplicates, not just consecutive runs, so
        // {0x41,0x42,0x41} would collapse to {0x41}. Collapse adjacent runs only.
        auto out = bytes.begin();
        for (auto it = bytes.begin(); it != bytes.end(); ++it) {
            if (out == bytes.begin() || *(out - 1) != *it) *out++ = *it;
        }
        bytes.erase(out, bytes.end());
    }
    return bytes;
}

} // namespace rawrxd::reverse
