//==============================================================================
// SovereignTitanRuntime.hpp
// C++ Wrapper for Titan MASM64 Runtime
// Bridges Titan persistent model cache with Sovereign kernel dispatch
//
// Date: 2026-07-10
// Status: PRODUCTION READY
//==============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>

//==============================================================================
// TITAN C API (MASM Exports)
//==============================================================================

extern "C" {

// Titan Core API
__declspec(dllimport) int Titan_Initialize(void);
__declspec(dllimport) void Titan_Shutdown(void);

// Model Management
__declspec(dllimport) int Titan_LoadModelPersistent(const wchar_t* filePath, const char* modelName);
__declspec(dllimport) int Titan_UnloadModel(int modelSlot);
__declspec(dllimport) int Titan_GetModelSlot(const char* modelName);
__declspec(dllimport) bool Titan_IsModelLoaded(int modelSlot);

// Inference
struct TitanInferenceContext;
__declspec(dllimport) TitanInferenceContext* Titan_CreateInferenceContext(int modelSlot);
__declspec(dllimport) void Titan_DestroyInferenceContext(TitanInferenceContext* ctx);
__declspec(dllimport) int Titan_RunInference(TitanInferenceContext* ctx, const char* prompt, int maxTokens);
__declspec(dllimport) int Titan_GetGeneratedTokenCount(TitanInferenceContext* ctx);
__declspec(dllimport) const char* Titan_GetGeneratedText(TitanInferenceContext* ctx);

// Performance
struct TitanPerformanceStats {
    uint64_t totalTokensGenerated;
    uint64_t totalTimeUs;
    float tokensPerSecond;
    uint64_t lastAccessTime;
    uint32_t refCount;
};
__declspec(dllimport) bool Titan_GetPerformanceStats(int modelSlot, TitanPerformanceStats* stats);

// DMA Compute
struct GPUKernelDescriptor;
__declspec(dllimport) int Titan_ExecuteComputeKernel(GPUKernelDescriptor* desc, void* resultBuffer, size_t resultSize);
__declspec(dllimport) int Titan_PerformCopy(void* copyOp, uint32_t flags);
__declspec(dllimport) int Titan_PerformDMA(void* dmaDesc, uint32_t maxRetries);

} // extern "C"

//==============================================================================
// SOVEREIGN C++ WRAPPER
//==============================================================================

namespace Sovereign {

//==============================================================================
// Forward Declarations
//==============================================================================

class KernelDispatch;
class TensorView;
struct InferenceConfig;

//==============================================================================
// Titan Runtime Configuration
//==============================================================================

struct TitanConfig {
    // Model Cache
    uint32_t maxPersistentModels = 64;      // Titan supports up to 64
    uint64_t maxCacheMemoryMB = 8192;       // 8GB cache limit
    bool enableLRU = true;                  // LRU eviction
    
    // Inference
    uint32_t defaultMaxTokens = 2048;
    float defaultTemperature = 0.8f;
    float defaultTopP = 0.9f;
    uint32_t defaultTopK = 40;
    
    // Performance
    bool enableGPU = true;
    bool enableDMA = true;
    uint32_t dmaChunkSizeMB = 4;
    
    // Threading
    uint32_t inferenceThreads = 4;
    bool threadSafe = true;
};

//==============================================================================
// Model Info
//==============================================================================

struct ModelInfo {
    std::string name;
    int slot;
    bool isLoaded;
    uint64_t tensorCount;
    uint64_t dataSize;
    uint64_t lastAccessTime;
    uint32_t refCount;
    
    // Performance
    float avgTokensPerSecond;
    uint64_t totalTokensGenerated;
    uint64_t totalInferences;
};

//==============================================================================
// Inference Result
//==============================================================================

struct InferenceResult {
    std::string text;
    uint32_t tokensGenerated;
    float tokensPerSecond;
    uint64_t timeUs;
    bool success;
    std::string errorMessage;
};

//==============================================================================
// Titan Runtime (Singleton)
//==============================================================================

class TitanRuntime {
public:
    //==========================================================================
    // Lifecycle
    //==========================================================================
    
    // Initialize Titan runtime (call once at startup)
    static bool Initialize(const TitanConfig& config = TitanConfig{});
    
    // Shutdown Titan runtime (call once at exit)
    static void Shutdown();
    
    // Check if initialized
    static bool IsInitialized();
    
    //==========================================================================
    // Model Management
    //==========================================================================
    
    // Load model into persistent cache
    // Returns: slot index (0-63) or -1 on error
    static int LoadModel(const std::wstring& filePath, const std::string& name);
    
    // Load model with auto-generated name
    static int LoadModel(const std::wstring& filePath);
    
    // Unload model from cache
    static bool UnloadModel(int slot);
    static bool UnloadModel(const std::string& name);
    
    // Get slot by name
    static int GetModelSlot(const std::string& name);
    
    // Check if model is loaded
    static bool IsModelLoaded(int slot);
    static bool IsModelLoaded(const std::string& name);
    
    // Get model info
    static bool GetModelInfo(int slot, ModelInfo& info);
    static bool GetModelInfo(const std::string& name, ModelInfo& info);
    
    // List all loaded models
    static std::vector<ModelInfo> ListLoadedModels();
    
    // Get cache statistics
    static void GetCacheStats(uint32_t& loadedCount, uint64_t& totalMemoryMB);
    
    //==========================================================================
    // Inference
    //==========================================================================
    
    // Run inference (synchronous)
    static InferenceResult RunInference(
        int modelSlot,
        const std::string& prompt,
        int maxTokens = -1,  // -1 = use default
        float temperature = -1.0f,
        float topP = -1.0f,
        uint32_t topK = 0
    );
    
    // Run inference by name
    static InferenceResult RunInference(
        const std::string& modelName,
        const std::string& prompt,
        int maxTokens = -1,
        float temperature = -1.0f,
        float topP = -1.0f,
        uint32_t topK = 0
    );
    
    // Run inference (asynchronous with callback)
    using InferenceCallback = std::function<void(const InferenceResult&)>;
    static void RunInferenceAsync(
        int modelSlot,
        const std::string& prompt,
        InferenceCallback callback,
        int maxTokens = -1,
        float temperature = -1.0f,
        float topP = -1.0f,
        uint32_t topK = 0
    );
    
    // Stream tokens during generation
    using TokenCallback = std::function<void(const std::string& token, bool isLast)>;
    static void RunInferenceStreaming(
        int modelSlot,
        const std::string& prompt,
        TokenCallback callback,
        int maxTokens = -1,
        float temperature = -1.0f,
        float topP = -1.0f,
        uint32_t topK = 0
    );
    
    //==========================================================================
    // Performance
    //==========================================================================
    
    // Get performance stats for a model
    static bool GetPerformanceStats(int modelSlot, TitanPerformanceStats& stats);
    static bool GetPerformanceStats(const std::string& name, TitanPerformanceStats& stats);
    
    // Reset performance stats
    static void ResetPerformanceStats(int modelSlot);
    static void ResetPerformanceStats(const std::string& name);
    
    // Get global performance summary
    static void GetGlobalPerformanceStats(
        uint64_t& totalInferences,
        uint64_t& totalTokens,
        float& avgTokensPerSecond
    );
    
    //==========================================================================
    // GPU/DMA Operations
    //==========================================================================
    
    // Execute compute kernel on GPU
    static int ExecuteComputeKernel(
        void* inputBuffer,
        size_t inputSize,
        void* outputBuffer,
        size_t outputSize,
        const std::string& kernelName,
        uint32_t gridDimX = 1,
        uint32_t gridDimY = 1,
        uint32_t gridDimZ = 1,
        uint32_t blockDimX = 256,
        uint32_t blockDimY = 1,
        uint32_t blockDimZ = 1
    );
    
    // Perform async memory copy
    static int PerformCopy(
        void* source,
        void* dest,
        size_t size,
        bool async = false,
        std::function<void()> callback = nullptr
    );
    
    // Perform DMA transfer
    static int PerformDMA(
        void* source,
        void* dest,
        size_t size,
        uint32_t priority = 5,
        bool allowPartial = false
    );
    
    //==========================================================================
    // Advanced: Direct Titan Access
    //==========================================================================
    
    // Get raw Titan inference context (advanced use)
    static TitanInferenceContext* CreateRawContext(int modelSlot);
    static void DestroyRawContext(TitanInferenceContext* ctx);
    
    // Direct inference call (advanced use)
    static int RunInferenceRaw(TitanInferenceContext* ctx, const char* prompt, int maxTokens);

private:
    //==========================================================================
    // Implementation
    //==========================================================================
    
    TitanRuntime() = delete;  // Singleton
    ~TitanRuntime() = delete;
    
    static bool s_initialized;
    static TitanConfig s_config;
    static std::mutex s_mutex;
    static uint64_t s_totalInferences;
    static uint64_t s_totalTokens;
};

//==============================================================================
// RAII Model Handle
//==============================================================================

class TitanModelHandle {
public:
    explicit TitanModelHandle(int slot) : m_slot(slot), m_valid(true) {}
    explicit TitanModelHandle(const std::string& name);
    ~TitanModelHandle();
    
    // Move only
    TitanModelHandle(TitanModelHandle&& other) noexcept;
    TitanModelHandle& operator=(TitanModelHandle&& other) noexcept;
    
    TitanModelHandle(const TitanModelHandle&) = delete;
    TitanModelHandle& operator=(const TitanModelHandle&) = delete;
    
    // Accessors
    int GetSlot() const { return m_slot; }
    bool IsValid() const { return m_valid && TitanRuntime::IsModelLoaded(m_slot); }
    
    // Inference
    InferenceResult RunInference(
        const std::string& prompt,
        int maxTokens = -1,
        float temperature = -1.0f,
        float topP = -1.0f,
        uint32_t topK = 0
    );
    
    ModelInfo GetInfo() const;
    
private:
    int m_slot;
    bool m_valid;
};

//==============================================================================
// Convenience Functions
//==============================================================================

// Quick inference: load model, run inference, unload
InferenceResult QuickInference(
    const std::wstring& modelPath,
    const std::string& prompt,
    int maxTokens = 256
);

// Batch inference on multiple prompts
std::vector<InferenceResult> BatchInference(
    int modelSlot,
    const std::vector<std::string>& prompts,
    int maxTokens = 256
);

// Compare performance of two models
struct ComparisonResult {
    std::string modelA;
    std::string modelB;
    float speedup;  // B vs A (1.0 = same, 2.0 = B 2x faster)
    float memoryRatio;
    float qualityScore;
};

ComparisonResult CompareModels(
    int modelSlotA,
    int modelSlotB,
    const std::vector<std::string>& testPrompts
);

} // namespace Sovereign

//==============================================================================
// USAGE EXAMPLES
//==============================================================================

/*

// Example 1: Basic Usage
// --------------------
#include "SovereignTitanRuntime.hpp"
using namespace Sovereign;

int main() {
    // Initialize Titan
    TitanConfig config;
    config.maxPersistentModels = 32;
    config.enableGPU = true;
    TitanRuntime::Initialize(config);
    
    // Load model
    int slot = TitanRuntime::LoadModel(
        L"D:\\models\\qwen2.5-7b-q4.gguf",
        "qwen7b"
    );
    
    if (slot < 0) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    // Run inference
    auto result = TitanRuntime::RunInference(slot, "Hello, how are you?", 100);
    
    if (result.success) {
        std::cout << "Generated: " << result.text << "\n";
        std::cout << "TPS: " << result.tokensPerSecond << "\n";
    }
    
    // Cleanup
    TitanRuntime::UnloadModel(slot);
    TitanRuntime::Shutdown();
    return 0;
}


// Example 2: RAII Handle
// ----------------------
{
    TitanModelHandle model("qwen7b");
    
    auto result = model.RunInference("What is AI?", 200, 0.8f, 0.9f, 40);
    
    // Model automatically unloaded when handle goes out of scope
}


// Example 3: Streaming
// --------------------
TitanRuntime::RunInferenceStreaming(
    slot,
    "Tell me a story",
    [](const std::string& token, bool isLast) {
        std::cout << token << std::flush;
        if (isLast) std::cout << "\n";
    },
    500  // max tokens
);


// Example 4: Async
// ----------------
TitanRuntime::RunInferenceAsync(
    slot,
    "Explain quantum computing",
    [](const InferenceResult& result) {
        if (result.success) {
            std::cout << "Async result: " << result.text << "\n";
        }
    },
    300
);
// Continue with other work...


// Example 5: Performance Monitoring
// -----------------------------------
TitanPerformanceStats stats;
TitanRuntime::GetPerformanceStats("qwen7b", &stats);

std::cout << "Total tokens: " << stats.totalTokensGenerated << "\n";
std::cout << "TPS: " << stats.tokensPerSecond << "\n";
std::cout << "Reference count: " << stats.refCount << "\n";

*/
