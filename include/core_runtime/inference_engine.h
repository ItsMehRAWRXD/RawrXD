// =============================================================================
// RawrXD-CoreRuntime Public API: Inference Engine
// =============================================================================
// PURPOSE: Headless inference execution without UI dependencies
// RULES:
//   - No Win32 API calls
//   - No UI callbacks
//   - No logging to visual components
//   - Pure compute: model → graph → execution → memory
// =============================================================================

#ifndef RAWRXD_CORE_INFERENCE_ENGINE_H
#define RAWRXD_CORE_INFERENCE_ENGINE_H

#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>
#include "core_export.h"

namespace RawrXD {
namespace Core {

// Forward declarations (implementation hidden)
class InferenceContext;
class GraphExecutor;
class MemoryPool;

// =============================================================================
// Inference Configuration (Pure Data, No UI)
// =============================================================================

struct RAWRXD_CORE_EXPORT InferenceConfig {
    // Model path (GGUF format)
    const char* modelPath = nullptr;
    
    // Execution parameters
    uint32_t maxTokens = 2048;
    uint32_t batchSize = 1;
    uint32_t threadCount = 4;
    
    // Memory constraints
    size_t maxMemoryBytes = 8ULL * 1024 * 1024 * 1024;  // 8GB default
    
    // Precision mode
    enum class Precision {
        FP32,
        FP16,
        Q8_0,
        Q4_0
    } precision = Precision::Q4_0;
    
    // Callback for token generation (function pointer, no UI refs)
    // Returns false to abort generation
    using TokenCallback = std::function<bool(const char* token, uint32_t tokenId)>;
    TokenCallback onToken = nullptr;
};

// =============================================================================
// Inference Result (Status Code, No Exceptions to UI)
// =============================================================================

struct RAWRXD_CORE_EXPORT InferenceResult {
    enum class Status : uint32_t {
        Success = 0,
        ModelNotFound,
        OutOfMemory,
        InvalidConfig,
        ExecutionFailed,
        AbortedByCallback,
        HardwareError
    };
    
    Status status = Status::Success;
    uint32_t tokensGenerated = 0;
    uint64_t elapsedMicroseconds = 0;
    const char* errorMessage = nullptr;
};

// =============================================================================
// Core Inference Engine (Opaque Handle)
// =============================================================================

class RAWRXD_CORE_EXPORT InferenceEngine {
public:
    // Construction / Destruction
    InferenceEngine();
    ~InferenceEngine();
    
    // Non-copyable (unique resource ownership)
    InferenceEngine(const InferenceEngine&) = delete;
    InferenceEngine& operator=(const InferenceEngine&) = delete;
    
    // Movable
    InferenceEngine(InferenceEngine&&) noexcept;
    InferenceEngine& operator=(InferenceEngine&&) noexcept;
    
    // =============================================================================
    // Core Operations
    // =============================================================================
    
    // Initialize with configuration
    // Returns false if initialization fails (check GetLastError for details)
    bool Initialize(const InferenceConfig& config);
    
    // Load model from GGUF file
    // This is separate from Initialize to allow model hot-swapping
    bool LoadModel(const char* ggufPath);
    
    // Run inference on a prompt
    // Blocks until completion or callback returns false
    InferenceResult RunInference(const char* prompt);
    
    // Run inference asynchronously (returns immediately)
    // Result available via callback or polling
    bool RunInferenceAsync(const char* prompt, 
                           std::function<void(const InferenceResult&)> onComplete);
    
    // Abort current inference (thread-safe)
    void AbortInference();
    
    // Check if inference is currently running
    bool IsRunning() const;
    
    // =============================================================================
    // Memory Management
    // =============================================================================
    
    // Get current memory usage in bytes
    size_t GetMemoryUsage() const;
    
    // Get peak memory usage since initialization
    size_t GetPeakMemoryUsage() const;
    
    // Force memory pool compaction
    void CompactMemory();
    
    // =============================================================================
    // State Queries
    // =============================================================================
    
    // Get last error message (valid if operation returned false)
    const char* GetLastError() const;
    
    // Get engine version string
    static const char* GetVersion();
    
    // Check if AVX-512 is available and being used
    bool IsUsingAVX512() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// Factory Functions
// =============================================================================

// Create a new inference engine instance
RAWRXD_CORE_EXPORT std::unique_ptr<InferenceEngine> CreateInferenceEngine();

// Create with specific memory pool size
RAWRXD_CORE_EXPORT std::unique_ptr<InferenceEngine> CreateInferenceEngine(
    size_t initialMemoryPoolBytes
);

} // namespace Core
} // namespace RawrXD

#endif // RAWRXD_CORE_INFERENCE_ENGINE_H
