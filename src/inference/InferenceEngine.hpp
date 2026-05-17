#pragma once

#include <filesystem>
#include <string>

// Compatibility shim for legacy tool targets that include
// src/inference/InferenceEngine.hpp and expect this simple API.
class InferenceEngine {
public:
    // Accepts a null or typed config pointer; ignored in this shim.
    explicit InferenceEngine(void* /*config*/) {}
public:
    // Alias expected by test targets that call Initialize instead of loadModel.
    bool Initialize(const std::string& modelPath) { return loadModel(modelPath); }
    int GetVocabSize() const { return 0; }
    int GetEmbeddingDim() const { return 0; }

    bool loadModel(const std::string& modelPath) {
        m_modelPath = modelPath;
        if (m_modelPath.empty()) {
            return false;
        }

        std::error_code ec;
        return std::filesystem::exists(std::filesystem::path(m_modelPath), ec);
    }

    std::string generate(const std::string& prompt, int maxTokens) {
        if (m_modelPath.empty() || maxTokens <= 0) {
            return {};
        }

        // Deterministic local text expansion for CLI tool smoke/bench flows.
        const std::string seed = prompt.empty() ? "RawrXD" : prompt;
        std::string output;
        output.reserve(static_cast<size_t>(maxTokens) * 8);

        for (int i = 0; i < maxTokens; ++i) {
            output += seed;
            if (i + 1 < maxTokens) {
                output.push_back(' ');
            }
        }
        return output;
    }

    void unloadModel() {
        m_modelPath.clear();
    }

private:
    std::string m_modelPath;
};
