// ============================================================================
// cpu_inference_engine_mock.h — Minimal Mock for Test Compilation
// ============================================================================
// Lightweight replacement for the full cpu_inference_engine.h to satisfy
// dependencies without requiring swarm_scheduler.hpp (C++23 std::expected).
// This mock is ONLY for test compilation - production code uses the real header.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace RawrXD {

// Minimal CPUInferenceEngine mock for testing ModelOperationsBridge
class CPUInferenceEngine {
public:
    static CPUInferenceEngine* GetSharedInstance() {
        static CPUInferenceEngine instance;
        return &instance;
    }

    bool IsModelLoaded() const { return m_modelLoaded; }
    
    bool LoadModel(const std::string& path) {
        m_modelLoaded = true;
        m_modelPath = path;
        return true;
    }

    std::vector<int32_t> Tokenize(const std::string& text) {
        // Mock tokenization - just return character codes
        std::vector<int32_t> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<int32_t>(c));
        }
        return tokens;
    }

    std::string Detokenize(const std::vector<int32_t>& tokens) {
        // Mock detokenization - just convert back to string
        std::string text;
        for (int32_t t : tokens) {
            text += static_cast<char>(t);
        }
        return text;
    }

    void GenerateStreaming(
        const std::vector<int32_t>& prompt,
        int maxTokens,
        std::function<void(const std::string&)> onToken,
        std::function<void()> onComplete,
        void* /*userData*/
    ) {
        // Mock generation - just emit some test tokens
        for (int i = 0; i < maxTokens && i < 10; ++i) {
            onToken("test");
        }
        if (onComplete) {
            onComplete();
        }
    }

    size_t GetContextLimit() const { return 4096; }

private:
    CPUInferenceEngine() = default;
    ~CPUInferenceEngine() = default;
    
    bool m_modelLoaded = false;
    std::string m_modelPath;
};

} // namespace RawrXD