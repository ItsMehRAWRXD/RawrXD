// RawrXD Memory Optimizer
// Phase AN: Memory Optimization

#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace rawrxd {
namespace memory {

// Memory allocation strategies
enum class AllocationStrategy {
    STANDARD,           // Standard malloc/free
    POOL,               // Memory pool
    ARENA,              // Arena allocator
    BUMP,               // Bump allocator
    STACK,              // Stack allocator
    CUSTOM
};

// Memory pressure levels
enum class MemoryPressure {
    NONE,               // No pressure
    LOW,                // Low pressure
    MEDIUM,             // Medium pressure
    HIGH,               // High pressure
    CRITICAL            // Critical pressure
};

// Memory statistics
struct MemoryStats {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t system_total;
    size_t system_available;
    size_t cache_size;
    size_t pool_size;
    size_t fragmentation;
    MemoryPressure pressure_level;
    
    MemoryStats()
        : total_allocated(0)
        , total_freed(0)
        , current_usage(0)
        , peak_usage(0)
        , system_total(0)
        , system_available(0)
        , cache_size(0)
        , pool_size(0)
        , fragmentation(0)
        , pressure_level(MemoryPressure::NONE) {}
};

// Memory block info
struct MemoryBlock {
    void* ptr;
    size_t size;
    size_t alignment;
    bool is_pinned;
    bool is_cached;
    std::string tag;
    
    MemoryBlock() : ptr(nullptr), size(0), alignment(0), is_pinned(false), is_cached(false) {}
};

// Memory pool configuration
struct PoolConfig {
    size_t block_size;
    size_t initial_blocks;
    size_t max_blocks;
    bool growable;
    
    PoolConfig()
        : block_size(4096)
        , initial_blocks(1024)
        , max_blocks(65536)
        , growable(true) {}
};

// Forward declarations
class IMemoryAllocator;
class MemoryPool;
class MemoryOptimizer;

/**
 * MemoryOptimizer - Central memory management and optimization
 */
class MemoryOptimizer {
public:
    MemoryOptimizer();
    ~MemoryOptimizer();
    
    // Initialize memory optimizer
    bool initialize();
    void shutdown();
    
    // Allocation
    void* allocate(size_t size, size_t alignment = 64, const std::string& tag = "");
    void deallocate(void* ptr);
    void* reallocate(void* ptr, size_t new_size);
    
    // Pinned memory (for GPU transfers)
    void* allocatePinned(size_t size, const std::string& tag = "");
    void deallocatePinned(void* ptr);
    
    // Aligned allocation
    void* allocateAligned(size_t size, size_t alignment);
    void deallocateAligned(void* ptr);
    
    // Memory pools
    bool createPool(const std::string& name, const PoolConfig& config);
    void destroyPool(const std::string& name);
    void* allocateFromPool(const std::string& name);
    void deallocateToPool(const std::string& name, void* ptr);
    
    // Cache management
    void* allocateCached(size_t size, const std::string& tag = "");
    void releaseCache();
    void setCacheLimit(size_t limit);
    
    // Memory defragmentation
    bool defragment();
    size_t getFragmentation() const;
    
    // Statistics
    MemoryStats getStats() const;
    void resetStats();
    void printStats() const;
    
    // Memory pressure handling
    MemoryPressure getPressureLevel() const;
    void setPressureCallback(std::function<void(MemoryPressure)> callback);
    void handleMemoryPressure();
    
    // Garbage collection
    void collectGarbage();
    void setGCThreshold(size_t threshold);
    
    // Memory mapping
    void* mapFile(const std::string& path, size_t offset, size_t size);
    void unmapFile(void* ptr, size_t size);
    
    // Prefetch
    void prefetch(void* ptr, size_t size);
    
    // Memory advice
    void adviseSequential(void* ptr, size_t size);
    void adviseRandom(void* ptr, size_t size);
    void adviseWillNeed(void* ptr, size_t size);
    void adviseDontNeed(void* ptr, size_t size);
    
private:
    std::unordered_map<std::string, std::unique_ptr<MemoryPool>> pools_;
    std::unordered_map<void*, MemoryBlock> allocations_;
    std::unordered_map<std::string, std::vector<void*>> cache_;
    
    mutable std::mutex mutex_;
    
    MemoryStats stats_;
    size_t cache_limit_;
    size_t gc_threshold_;
    
    std::function<void(MemoryPressure)> pressure_callback_;
    
    bool initialized_;
    
    // Internal methods
    void updatePressureLevel();
    void* allocateInternal(size_t size, size_t alignment);
    void deallocateInternal(void* ptr);
};

/**
 * MemoryPool - Fixed-size block memory pool
 */
class MemoryPool {
public:
    MemoryPool(const PoolConfig& config);
    ~MemoryPool();
    
    bool initialize();
    void* allocate();
    void deallocate(void* ptr);
    bool grow();
    
    size_t getBlockSize() const { return config_.block_size; }
    size_t getFreeBlocks() const;
    size_t getTotalBlocks() const;
    
private:
    PoolConfig config_;
    std::vector<void*> free_blocks_;
    std::vector<void*> allocated_blocks_;
    std::vector<std::unique_ptr<uint8_t[]>> memory_chunks_;
    
    mutable std::mutex mutex_;
};

/**
 * ArenaAllocator - Arena-style allocator
 */
class ArenaAllocator {
public:
    ArenaAllocator(size_t initial_size = 1024 * 1024);  // 1MB default
    ~ArenaAllocator();
    
    void* allocate(size_t size, size_t alignment = 64);
    void reset();
    size_t getUsed() const { return used_; }
    size_t getCapacity() const { return capacity_; }
    
private:
    std::unique_ptr<uint8_t[]> memory_;
    size_t capacity_;
    size_t used_;
    mutable std::mutex mutex_;
};

// Global memory optimizer accessor
MemoryOptimizer* getMemoryOptimizer();
void setMemoryOptimizer(std::unique_ptr<MemoryOptimizer> optimizer);

// Convenience macros
#define RAWRXD_ALLOC(size) \
    rawrxd::memory::getMemoryOptimizer() ? \
    rawrxd::memory::getMemoryOptimizer()->allocate(size) : malloc(size)

#define RAWRXD_FREE(ptr) \
    do { \
        if (rawrxd::memory::getMemoryOptimizer()) { \
            rawrxd::memory::getMemoryOptimizer()->deallocate(ptr); \
        } else { \
            free(ptr); \
        } \
    } while(0)

} // namespace memory
} // namespace rawrxd
