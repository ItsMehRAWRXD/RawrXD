/*===========================================================================
 * ModelLoaderDispatch.hpp
 * 
 * Mode-aware dispatch table for model loading.
 * 
 * Architecture:
 *   - Eliminates if/else chains in hot path
 *   - Function pointer dispatch for pipeline stability
 *   - Extensible for future modes (Quantized_EXL2, Medusa, etc.)
 * 
 * Memory Strategy:
 *   - Synthetic: Fixed small allocation (4MB)
 *   - GGUF: Dynamic allocation based on header metadata
 *   - Pre-allocation: Reserve max theoretical before load begins
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Runtime {

// Forward declarations
struct InferenceConfig;
class InferenceEngine;

// Model loader interface
struct IModelLoader {
    // Load weights from source (GGUF file or synthetic)
    virtual bool LoadWeights(void* weightsBuffer, size_t bufferSize) = 0;
    
    // Initialize context (KV cache, etc.)
    virtual bool InitializeContext(uint32_t contextLength) = 0;
    
    // Get required memory size before allocation
    virtual size_t GetRequiredMemoryBytes() const = 0;
    
    // Get model metadata
    virtual uint32_t GetVocabSize() const = 0;
    virtual uint32_t GetLayerCount() const = 0;
    virtual uint32_t GetHiddenDim() const = 0;
    virtual const char* GetQuantizationType() const = 0;
    
    // Check if loader supports speculative decoding (Medusa)
    virtual bool HasSpeculativeHeads() const = 0;
    virtual uint32_t GetSpeculativeHeadCount() const = 0;
    
    // Get actual bytes loaded (for validation against reservation)
    virtual size_t GetActualLoadedBytes() const = 0;
    
    // Get last error message
    virtual const char* GetLastError() const = 0;
    
    virtual ~IModelLoader() = default;
};

// Synthetic loader - fixed small memory footprint
class SyntheticModelLoader : public IModelLoader {
public:
    SyntheticModelLoader();
    
    bool LoadWeights(void* weightsBuffer, size_t bufferSize) override;
    bool InitializeContext(uint32_t contextLength) override;
    size_t GetRequiredMemoryBytes() const override;
    uint32_t GetVocabSize() const override { return 32000; }
    uint32_t GetLayerCount() const override { return 32; }
    uint32_t GetHiddenDim() const override { return 4096; }
    const char* GetQuantizationType() const override { return "F32"; }
    bool HasSpeculativeHeads() const override { return false; }
    uint32_t GetSpeculativeHeadCount() const override { return 0; }
    
private:
    static constexpr size_t SYNTHETIC_WEIGHT_SIZE = 4 * 1024 * 1024;  // 4MB fixed
};

// GGUF loader - dynamic allocation based on file metadata
class GgufModelLoader : public IModelLoader {
public:
    GgufModelLoader(const void* ggufMapping, size_t mappingSize);
    
    bool LoadWeights(void* weightsBuffer, size_t bufferSize) override;
    bool InitializeContext(uint32_t contextLength) override;
    size_t GetRequiredMemoryBytes() const override;
    uint32_t GetVocabSize() const override { return vocabSize_; }
    uint32_t GetLayerCount() const override { return layerCount_; }
    uint32_t GetHiddenDim() const override { return hiddenDim_; }
    const char* GetQuantizationType() const override { return quantizationType_; }
    bool HasSpeculativeHeads() const override { return speculativeHeadCount_ > 0; }
    uint32_t GetSpeculativeHeadCount() const override { return speculativeHeadCount_; }
    
private:
    const void* ggufMapping_;
    size_t mappingSize_;
    
    // Parsed from GGUF header
    uint32_t vocabSize_ = 0;
    uint32_t layerCount_ = 0;
    uint32_t hiddenDim_ = 0;
    uint32_t speculativeHeadCount_ = 0;
    char quantizationType_[16] = {0};
    size_t requiredMemoryBytes_ = 0;
    
    bool ParseGgufHeader();
    size_t CalculateTensorMemoryRequirements();
};

// Loader dispatch table entry
struct LoaderDispatchEntry {
    const char* name;
    std::function<std::unique_ptr<IModelLoader>()> factory;
};

// Global dispatch table
class ModelLoaderDispatch {
public:
    // Get loader for execution mode
    static std::unique_ptr<IModelLoader> GetLoader(ExecutionMode mode, 
                                                      const void* ggufMapping = nullptr,
                                                      size_t mappingSize = 0);
    
    // Register custom loader
    static void RegisterLoader(ExecutionMode mode, LoaderDispatchEntry entry);
    
private:
    static LoaderDispatchEntry dispatchTable_[4];  // One per ExecutionMode
    static bool initialized_;
    static void Initialize();
};

// Memory allocation strategy
enum class MemoryStrategy {
    FixedSmall,      // Synthetic: 4MB fixed
    DynamicGrowth,   // Grow as needed (fragmentation risk)
    PreAllocateMax,  // Reserve based on header before load
    PoolAllocator    // Use memory pool for frequent loads
};

// Memory manager for model loading
class ModelMemoryManager {
public:
    // Allocate memory for model weights
    static void* AllocateWeights(size_t bytes, MemoryStrategy strategy);
    
    // Free allocated memory
    static void FreeWeights(void* ptr);
    
    // Get current memory usage
    static size_t GetCurrentUsage();
    static size_t GetPeakUsage();
    
    // Reserve maximum theoretical memory (for GGUF)
    static bool ReserveMaxMemory(const IModelLoader* loader);
    
private:
    static size_t currentUsage_;
    static size_t peakUsage_;
};

} // namespace Runtime
} // namespace RawrXD
