//=============================================================================
// RawrXD Paged KV Cache - Sovereign Memory Integration
// Phase 3A Integration: Replaces std::vector/std::mutex with NUMA-aware allocator
//
// This is the bridge between the legacy PagedKVCache and the new
// SovereignMemoryAllocator, providing:
// - NUMA-local block allocation
// - Large page backing for KV cache
// - Lock-free block management
// - Residency telemetry
//=============================================================================

#pragma once

#include "../memory/SovereignMemoryAllocator.hpp"
#include <vector>
#include <atomic>
#include <memory>

namespace RawrXD {
namespace KVCache {

//=============================================================================
// Configuration
//=============================================================================
struct SovereignPagedKVConfig {
    // Block configuration
    uint32_t blockSize = 16;           // Tokens per block
    uint32_t numLayers = 32;           // Transformer layers
    uint32_t numHeads = 32;            // Attention heads
    uint32_t headDim = 128;            // Dimension per head
    uint32_t maxBlocks = 8192;         // Maximum physical blocks
    
    // Memory configuration
    MemoryTier memoryTier = MemoryTier::LARGE_PAGE_DRAM;
    bool useNumaAffinity = true;         // Bind to current NUMA node
    bool lockPages = false;            // Lock pages in memory
    bool prefault = true;              // Prefault on allocation
    
    // Compute derived values
    size_t GetTokensPerBlock() const { return blockSize; }
    size_t GetHeadDim() const { return headDim; }
    size_t GetKSizePerToken() const { return numHeads * headDim * sizeof(float); }
    size_t GetVSizePerToken() const { return numHeads * headDim * sizeof(float); }
    size_t GetKVSizePerToken() const { return GetKSizePerToken() + GetVSizePerToken(); }
    size_t GetBlockSizeBytes() const { return blockSize * GetKVSizePerToken(); }
};

//=============================================================================
// KV Cache Block with Sovereign Memory
// Aligned, NUMA-local memory block for K and V tensors
//=============================================================================
class SovereignKVBlock {
public:
    SovereignKVBlock();
    ~SovereignKVBlock();
    
    // Disable copy
    SovereignKVBlock(const SovereignKVBlock&) = delete;
    SovereignKVBlock& operator=(const SovereignKVBlock&) = delete;
    
    // Enable move
    SovereignKVBlock(SovereignKVBlock&& other) noexcept;
    SovereignKVBlock& operator=(SovereignKVBlock&& other) noexcept;
    
    // Initialize with sovereign memory
    bool Initialize(const SovereignPagedKVConfig& config, 
                    uint32_t numaNode,
                    MemoryTier tier);
    void Shutdown();
    
    // Access K and V data
    float* GetK() { return kData_; }
    float* GetV() { return vData_; }
    const float* GetK() const { return kData_; }
    const float* GetV() const { return vData_; }
    
    // Get pointer to specific token's K/V
    float* GetKToken(uint32_t tokenInBlock);
    float* GetVToken(uint32_t tokenInBlock);
    
    // Block metadata
    uint32_t GetTokenCount() const { return tokenCount_; }
    void SetTokenCount(uint32_t count) { tokenCount_ = count; }
    uint32_t GetNumaNode() const { return numaNode_; }
    bool IsValid() const { return kHandle_.IsValid() && vHandle_.IsValid(); }
    
    // Lock/unlock pages
    bool Lock();
    void Unlock();
    
private:
    // Memory handles
    MemoryResidencyHandle kHandle_;
    MemoryResidencyHandle vHandle_;
    
    // Direct pointers (for fast access)
    float* kData_ = nullptr;
    float* vData_ = nullptr;
    
    // Metadata
    uint32_t tokenCount_ = 0;
    uint32_t numaNode_ = 0;
    size_t kSize_ = 0;
    size_t vSize_ = 0;
    
    void Reset();
};

//=============================================================================
// Lock-Free Block Index
// Atomic free list for O(1) block allocation
//=============================================================================
class LockFreeBlockIndex {
public:
    struct BlockEntry {
        std::atomic<uint32_t> nextFree;
        std::atomic<bool> inUse;
        uint32_t blockId;
    };
    
    LockFreeBlockIndex();
    ~LockFreeBlockIndex();
    
    // Initialize with number of blocks
    bool Initialize(uint32_t numBlocks);
    void Shutdown();
    
    // Allocate a block (returns block ID or UINT32_MAX on failure)
    uint32_t AllocateBlock();
    
    // Free a block
    void FreeBlock(uint32_t blockId);
    
    // Check if block is in use
    bool IsBlockInUse(uint32_t blockId) const;
    
    // Statistics
    uint32_t GetFreeCount() const { return freeCount_.load(); }
    uint32_t GetUsedCount() const { return usedCount_.load(); }
    
private:
    std::vector<BlockEntry> entries_;
    alignas(64) std::atomic<uint32_t> freeHead_{UINT32_MAX};
    alignas(64) std::atomic<uint32_t> freeCount_{0};
    alignas(64) std::atomic<uint32_t> usedCount_{0};
    uint32_t numBlocks_ = 0;
};

//=============================================================================
// Sovereign Block Manager
// Manages physical blocks with NUMA-aware allocation
//=============================================================================
class SovereignBlockManager {
public:
    SovereignBlockManager();
    ~SovereignBlockManager();
    
    // Initialize with configuration
    bool Initialize(const SovereignPagedKVConfig& config);
    void Shutdown();
    
    // Allocate a block (returns block ID or UINT32_MAX)
    uint32_t AllocateBlock();
    
    // Free a block
    void FreeBlock(uint32_t blockId);
    
    // Get block by ID
    SovereignKVBlock* GetBlock(uint32_t blockId);
    const SovereignKVBlock* GetBlock(uint32_t blockId) const;
    
    // Statistics
    uint32_t GetNumBlocks() const { return numBlocks_; }
    uint32_t GetFreeBlocks() const;
    uint32_t GetUsedBlocks() const;
    
    // Residency info
    uint32_t GetNumaNode() const { return numaNode_; }
    MemoryTier GetMemoryTier() const { return config_.memoryTier; }
    
    // Telemetry
    std::string GetResidencyReport() const;
    
private:
    SovereignPagedKVConfig config_;
    uint32_t numaNode_ = 0;
    uint32_t numBlocks_ = 0;
    
    // Block storage
    std::vector<std::unique_ptr<SovereignKVBlock>> blocks_;
    LockFreeBlockIndex blockIndex_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> allocationCount_{0};
    alignas(64) std::atomic<uint64_t> deallocationCount_{0};
};

//=============================================================================
// Sovereign Paged KV Cache
// Main interface - drop-in replacement for PagedKVCache
//=============================================================================
class SovereignPagedKVCache {
public:
    SovereignPagedKVCache();
    ~SovereignPagedKVCache();
    
    // Initialize with configuration
    bool Initialize(const SovereignPagedKVConfig& config);
    void Shutdown();
    
    // Append a token's KV to the cache
    void AppendToken(const float* k, const float* v);
    
    // Append multiple tokens (batch)
    void AppendTokens(const float* k, const float* v, uint32_t numTokens);
    
    // Get block table for attention kernel
    const std::vector<uint32_t>& GetBlockTable() const { return blockTable_; }
    
    // Get context length
    uint32_t GetContextLength() const { return currentLength_; }
    
    // Get block manager
    SovereignBlockManager* GetBlockManager() { return blockManager_.get(); }
    
    // Access K/V data for a specific token
    // Note: This is for debugging/testing; kernels should use block table directly
    bool GetK(uint32_t tokenIdx, float* outK);
    bool GetV(uint32_t tokenIdx, float* outV);
    
    // Clear cache
    void Clear();
    
    // Residency and telemetry
    std::string GetResidencyReport() const;
    
    // Configuration access
    const SovereignPagedKVConfig& GetConfig() const { return config_; }
    
private:
    SovereignPagedKVConfig config_;
    std::unique_ptr<SovereignBlockManager> blockManager_;
    
    // Block table: logical block index -> physical block ID
    std::vector<uint32_t> blockTable_;
    
    // Current position
    uint32_t currentLength_ = 0;
    
    // Ensure block exists for logical index
    bool EnsureBlock(uint32_t logicalBlockIdx);
};

} // namespace KVCache
} // namespace RawrXD
