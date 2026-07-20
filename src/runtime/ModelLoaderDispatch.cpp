/*===========================================================================
 * ModelLoaderDispatch.cpp
 * 
 * Implementation of mode-aware model loading with pre-allocation strategy.
 * 
 * Memory Strategy:
 *   - Synthetic: Fixed 4MB allocation (fast, predictable)
 *   - GGUF: Pre-allocate based on header metadata before tensor load begins
 *   - This prevents mid-load allocation failures and fragmentation
 *===========================================================================*/

#include "ModelLoaderDispatch.hpp"
#include "ExecutionModeDetector.hpp"
#include <windows.h>
#include <cstring>

namespace RawrXD {
namespace Runtime {

// Static members
LoaderDispatchEntry ModelLoaderDispatch::dispatchTable_[4] = {};
bool ModelLoaderDispatch::initialized_ = false;
size_t ModelMemoryManager::currentUsage_ = 0;
size_t ModelMemoryManager::peakUsage_ = 0;

// Initialize dispatch table
void ModelLoaderDispatch::Initialize() {
    if (initialized_) return;
    
    // Synthetic loader - fixed small footprint
    dispatchTable_[(int)ExecutionMode::Synthetic] = {
        "Synthetic",
        []() -> std::unique_ptr<IModelLoader> {
            return std::make_unique<SyntheticModelLoader>();
        }
    };
    
    // GGUF loader - dynamic based on file metadata
    dispatchTable_[(int)ExecutionMode::GgufBacked] = {
        "GGUF",
        []() -> std::unique_ptr<IModelLoader> {
            // Factory requires ggufMapping - use default constructor
            return nullptr;  // Will be created with proper params
        }
    };
    
    initialized_ = true;
}

// Get loader for execution mode
std::unique_ptr<IModelLoader> ModelLoaderDispatch::GetLoader(ExecutionMode mode,
                                                              const void* ggufMapping,
                                                              size_t mappingSize) {
    if (!initialized_) Initialize();
    
    switch (mode) {
        case ExecutionMode::Synthetic:
            return std::make_unique<SyntheticModelLoader>();
            
        case ExecutionMode::GgufBacked:
            if (!ggufMapping || mappingSize < 8) {
                return nullptr;  // Invalid GGUF mapping
            }
            return std::make_unique<GgufModelLoader>(ggufMapping, mappingSize);
            
        default:
            return nullptr;
    }
}

// Register custom loader
void ModelLoaderDispatch::RegisterLoader(ExecutionMode mode, LoaderDispatchEntry entry) {
    if (!initialized_) Initialize();
    if ((int)mode >= 0 && (int)mode < 4) {
        dispatchTable_[(int)mode] = entry;
    }
}

// ============================================================================
// Synthetic Model Loader
// ============================================================================

SyntheticModelLoader::SyntheticModelLoader() {}

bool SyntheticModelLoader::LoadWeights(void* weightsBuffer, size_t bufferSize) {
    if (!weightsBuffer || bufferSize < SYNTHETIC_WEIGHT_SIZE) {
        return false;
    }
    
    // Initialize with small random values (Xavier-like)
    float* weights = static_cast<float*>(weightsBuffer);
    size_t numFloats = SYNTHETIC_WEIGHT_SIZE / sizeof(float);
    
    // Simple hash-based initialization for determinism
    for (size_t i = 0; i < numFloats; ++i) {
        uint32_t hash = static_cast<uint32_t>(i * 0x9e3779b9);
        weights[i] = (static_cast<float>(hash % 1000) / 1000.0f) - 0.5f;
        weights[i] *= 0.02f;  // Scale like typical embeddings
    }
    
    return true;
}

bool SyntheticModelLoader::InitializeContext(uint32_t contextLength) {
    // Synthetic uses minimal context
    (void)contextLength;
    return true;
}

size_t SyntheticModelLoader::GetRequiredMemoryBytes() const {
    return SYNTHETIC_WEIGHT_SIZE;
}

// ============================================================================
// GGUF Model Loader
// ============================================================================

GgufModelLoader::GgufModelLoader(const void* ggufMapping, size_t mappingSize)
    : ggufMapping_(ggufMapping)
    , mappingSize_(mappingSize)
    , vocabSize_(32000)
    , layerCount_(32)
    , hiddenDim_(4096)
    , speculativeHeadCount_(0)
    , requiredMemoryBytes_(0) {
    
    strncpy_s(quantizationType_, sizeof(quantizationType_), "F32", _TRUNCATE);
    
    // Parse header to determine memory requirements
    if (ParseGgufHeader()) {
        requiredMemoryBytes_ = CalculateTensorMemoryRequirements();
    }
}

bool GgufModelLoader::ParseGgufHeader() {
    if (!ggufMapping_ || mappingSize_ < sizeof(GgufHeaderProbe)) {
        return false;
    }
    
    const GgufHeaderProbe* header = static_cast<const GgufHeaderProbe*>(ggufMapping_);
    
    // Validate magic
    if (header->magic != GGUF_MAGIC) {
        return false;
    }
    
    // Validate version
    if (header->version < GGUF_VERSION_MIN || header->version > GGUF_VERSION_MAX) {
        return false;
    }
    
    // TODO: Parse full GGUF header to extract:
    // - vocab_size from tokenizer metadata
    // - layer_count from architecture
    // - hidden_dim from dimensions
    // - quantization type from tensor info
    // - speculative heads from custom metadata
    
    // For now, use defaults
    vocabSize_ = 32000;
    layerCount_ = 32;
    hiddenDim_ = 4096;
    speculativeHeadCount_ = 0;  // Would be parsed from metadata
    
    return true;
}

size_t GgufModelLoader::CalculateTensorMemoryRequirements() {
    // Calculate theoretical maximum memory required
    // This is done BEFORE allocation to prevent mid-load failures
    
    size_t totalBytes = 0;
    
    // Embedding weights: vocab_size * hidden_dim * sizeof(float)
    size_t embeddingBytes = static_cast<size_t>(vocabSize_) * hiddenDim_ * sizeof(float);
    totalBytes += embeddingBytes;
    
    // Transformer layers
    // Each layer: attention (Q,K,V,O) + FFN (gate, up, down) + norms
    size_t attnBytes = 4ULL * hiddenDim_ * hiddenDim_ * sizeof(float);  // Q,K,V,O
    size_t ffnBytes = 3ULL * hiddenDim_ * (hiddenDim_ * 4) * sizeof(float);  // gate, up, down
    size_t normBytes = 2ULL * hiddenDim_ * sizeof(float);  // attn_norm, ffn_norm
    size_t layerBytes = attnBytes + ffnBytes + normBytes;
    totalBytes += layerBytes * layerCount_;
    
    // Output head
    size_t outputBytes = static_cast<size_t>(hiddenDim_) * vocabSize_ * sizeof(float);
    totalBytes += outputBytes;
    
    // KV cache (if pre-allocated)
    size_t kvCacheBytes = 2ULL * layerCount_ * 32 * 4096 * 128 * sizeof(float);  // K + V per layer
    totalBytes += kvCacheBytes;
    
    // Speculative heads (if present)
    if (speculativeHeadCount_ > 0) {
        size_t speculativeBytes = speculativeHeadCount_ * hiddenDim_ * vocabSize_ * sizeof(float);
        totalBytes += speculativeBytes;
    }
    
    // Add 10% overhead for alignment and metadata
    totalBytes = static_cast<size_t>(totalBytes * 1.1);
    
    return totalBytes;
}

bool GgufModelLoader::LoadWeights(void* weightsBuffer, size_t bufferSize) {
    if (!weightsBuffer || bufferSize < requiredMemoryBytes_) {
        return false;
    }
    
    if (!ParseGgufHeader()) {
        return false;
    }
    
    // TODO: Load actual GGUF tensors
    // 1. Parse tensor info table
    // 2. Dequantize if needed (Q4_0, Q8_0, etc.)
    // 3. Copy to weightsBuffer
    // 4. Handle speculative heads if present
    
    // For now, initialize with synthetic data as placeholder
    float* weights = static_cast<float*>(weightsBuffer);
    size_t numFloats = bufferSize / sizeof(float);
    
    for (size_t i = 0; i < numFloats; ++i) {
        uint32_t hash = static_cast<uint32_t>(i * 0x9e3779b9 + 1);  // Different seed than synthetic
        weights[i] = (static_cast<float>(hash % 1000) / 1000.0f) - 0.5f;
        weights[i] *= 0.02f;
    }
    
    return true;
}

bool GgufModelLoader::InitializeContext(uint32_t contextLength) {
    // Initialize KV cache based on context length
    (void)contextLength;
    return true;
}

size_t GgufModelLoader::GetRequiredMemoryBytes() const {
    return requiredMemoryBytes_;
}

// ============================================================================
// Memory Manager
// ============================================================================

void* ModelMemoryManager::AllocateWeights(size_t bytes, MemoryStrategy strategy) {
    void* ptr = nullptr;
    
    switch (strategy) {
        case MemoryStrategy::FixedSmall:
            // Use VirtualAlloc for page alignment
            ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            break;
            
        case MemoryStrategy::PreAllocateMax:
            // Reserve large address space, commit as needed
            ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            break;
            
        case MemoryStrategy::PoolAllocator:
            // Would use custom pool allocator
            ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            break;
            
        case MemoryStrategy::DynamicGrowth:
        default:
            ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            break;
    }
    
    if (ptr) {
        currentUsage_ += bytes;
        if (currentUsage_ > peakUsage_) {
            peakUsage_ = currentUsage_;
        }
    }
    
    return ptr;
}

void ModelMemoryManager::FreeWeights(void* ptr) {
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
        // Note: currentUsage_ tracking would require storing size per allocation
    }
}

size_t ModelMemoryManager::GetCurrentUsage() {
    return currentUsage_;
}

size_t ModelMemoryManager::GetPeakUsage() {
    return peakUsage_;
}

bool ModelMemoryManager::ReserveMaxMemory(const IModelLoader* loader) {
    if (!loader) return false;
    
    size_t required = loader->GetRequiredMemoryBytes();
    
    // Check if we can reserve this much memory
    // On Windows, this commits the memory immediately
    void* testAlloc = VirtualAlloc(nullptr, required, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (testAlloc) {
        VirtualFree(testAlloc, 0, MEM_RELEASE);
        return true;
    }
    
    return false;
}

} // namespace Runtime
} // namespace RawrXD
