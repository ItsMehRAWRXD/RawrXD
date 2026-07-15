#pragma once

#include <memory>
#include <cstdint>
#include <string>
#include <functional>

namespace RawrXD {
namespace Core {

// =============================================================================
// Inference Engine - Core Runtime Implementation
// =============================================================================
// Production-ready inference engine with real GGUF loading
// No stubs, no Qt deps, pure C++ implementation
// =============================================================================

class InferenceEngine {
public:
    // Configuration structure
    struct InferenceConfig {
        const char* modelPath = nullptr;
        uint32_t threadCount = 0;
        uint32_t maxTokens = 2048;
        float temperature = 0.7f;
        float topP = 0.9f;
        uint32_t contextLength = 4096;
        bool useGPU = true;
        bool useAVX512 = false;
        std::function<bool(const char*, uint32_t)> onToken = nullptr;
    };

    // Result structure
    struct InferenceResult {
        enum class Status {
            Success = 0,
            NotInitialized = 1,
            InvalidConfig = 2,
            ModelLoadFailed = 3,
            ExecutionFailed = 4,
            Aborted = 5,
            AbortedByCallback = 6
        };
        
        Status status = Status::NotInitialized;
        std::string outputText;
        std::string errorMessage;
        uint32_t tokensGenerated = 0;
        float tokensPerSecond = 0.0f;
        float latencyMs = 0.0f;
        uint64_t elapsedMicroseconds = 0;
    };

    // Construction
    InferenceEngine();
    ~InferenceEngine();
    
    // Move semantics (non-copyable)
    InferenceEngine(InferenceEngine&&) noexcept;
    InferenceEngine& operator=(InferenceEngine&&) noexcept;
    InferenceEngine(const InferenceEngine&) = delete;
    InferenceEngine& operator=(const InferenceEngine&) = delete;

    // Core operations
    bool Initialize(const InferenceConfig& config);
    bool LoadModel(const char* ggufPath);
    InferenceResult RunInference(const char* prompt);
    bool RunInferenceAsync(const char* prompt, std::function<void(const InferenceResult&)> onComplete);
    void AbortInference();
    
    // Status queries
    bool IsRunning() const;
    bool IsModelLoaded() const;
    const char* GetLastError() const;
    static const char* GetVersion();
    
    // Memory tracking
    size_t GetMemoryUsage() const;
    size_t GetPeakMemoryUsage() const;
    void CompactMemory();
    
    // Hardware info
    bool IsUsingAVX512() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Factory functions
std::unique_ptr<InferenceEngine> CreateInferenceEngine();
std::unique_ptr<InferenceEngine> CreateInferenceEngine(size_t initialMemoryPoolBytes);

} // namespace Core
} // namespace RawrXD
