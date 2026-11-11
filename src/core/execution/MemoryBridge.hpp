//==============================================================================
// MemoryBridge.hpp
// Unified memory management between Titan and Sovereign kernels
//
// Provides:
// - Aligned memory allocation for AVX2/AVX-512
// - Memory pool management
// - Zero-copy buffer sharing
// - Unified memory for CPU/GPU (future)
//==============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Sovereign {

//==============================================================================
// Memory Alignment Constants
//==============================================================================
constexpr size_t MEMORY_ALIGNMENT_AVX2 = 32;      // 256-bit alignment
constexpr size_t MEMORY_ALIGNMENT_AVX512 = 64;    // 512-bit alignment
constexpr size_t MEMORY_ALIGNMENT_DEFAULT = 64;   // Default to 512-bit for future-proofing

//==============================================================================
// Buffer Types
//==============================================================================
enum class BufferType {
    ACTIVATION,      // Layer activations (f32)
    WEIGHT_Q4,       // Quantized weights (Q4)
    WEIGHT_Q8,       // Quantized weights (Q8)
    WEIGHT_F32,      // Full precision weights
    KV_CACHE,        // Key-value cache
    TEMPORARY,       // Scratch/temporary buffers
    UNIFIED          // Shared across all contexts
};

//==============================================================================
// Memory Buffer
//==============================================================================
struct MemoryBuffer {
    void* data;
    size_t size;
    size_t capacity;
    BufferType type;
    uint32_t alignment;
    bool owned;
    
    MemoryBuffer() : data(nullptr), size(0), capacity(0), 
                     type(BufferType::TEMPORARY), alignment(MEMORY_ALIGNMENT_DEFAULT), 
                     owned(true) {}
    
    ~MemoryBuffer() { Release(); }
    
    void Release();
    bool Allocate(size_t sz, BufferType t = BufferType::TEMPORARY, 
                  uint32_t align = MEMORY_ALIGNMENT_DEFAULT);
    bool Resize(size_t newSize);
    void Zero();
    
    // Disable copy, enable move
    MemoryBuffer(const MemoryBuffer&) = delete;
    MemoryBuffer& operator=(const MemoryBuffer&) = delete;
    MemoryBuffer(MemoryBuffer&& other) noexcept;
    MemoryBuffer& operator=(MemoryBuffer&& other) noexcept;
};

//==============================================================================
// Memory Pool
//==============================================================================
class MemoryPool {
public:
    MemoryPool();
    ~MemoryPool();
    
    // Initialize pool with pre-allocated memory
    bool Initialize(size_t totalSize);
    
    // Allocate from pool
    void* Allocate(size_t size, uint32_t alignment = MEMORY_ALIGNMENT_DEFAULT);
    
    // Free back to pool
    void Free(void* ptr);
    
    // Get stats
    size_t GetTotalSize() const { return totalSize_; }
    size_t GetUsedSize() const;
    size_t GetFreeSize() const { return totalSize_ - GetUsedSize(); }
    
    // Reset pool
    void Reset();
    
    // Check if pointer belongs to pool
    bool Contains(void* ptr) const;

private:
    struct Block {
        void* ptr;
        size_t size;
        bool used;
    };
    
    std::vector<Block> blocks_;
    void* poolBase_;
    size_t totalSize_;
    mutable std::mutex mutex_;
};

//==============================================================================
// Memory Bridge
// Central memory management for kernel execution
//==============================================================================
class MemoryBridge {
public:
    MemoryBridge();
    ~MemoryBridge();
    
    // Initialize memory bridge
    bool Initialize(size_t poolSize = 1024 * 1024 * 1024); // 1GB default
    
    // Allocate aligned memory
    static void* AlignedAlloc(size_t size, uint32_t alignment = MEMORY_ALIGNMENT_DEFAULT);
    static void AlignedFree(void* ptr);
    
    // Create managed buffer
    std::shared_ptr<MemoryBuffer> CreateBuffer(size_t size, 
                                                  BufferType type = BufferType::TEMPORARY,
                                                  uint32_t alignment = MEMORY_ALIGNMENT_DEFAULT);
    
    // Get or create persistent buffer
    std::shared_ptr<MemoryBuffer> GetOrCreateBuffer(const std::string& name,
                                                      size_t size,
                                                      BufferType type = BufferType::ACTIVATION);
    
    // Release named buffer
    void ReleaseBuffer(const std::string& name);
    
    // Get memory pool
    MemoryPool* GetPool() { return &pool_; }
    
    // Get stats
    struct Stats {
        size_t totalAllocated;
        size_t totalUsed;
        size_t poolSize;
        size_t poolUsed;
        size_t bufferCount;
    };
    Stats GetStats() const;
    
    // Print stats
    void PrintStats() const;
    
    // Singleton access
    static MemoryBridge& GetInstance();

private:
    MemoryPool pool_;
    std::unordered_map<std::string, std::shared_ptr<MemoryBuffer>> namedBuffers_;
    mutable std::mutex mutex_;
    size_t totalAllocated_;
};

} // namespace Sovereign
