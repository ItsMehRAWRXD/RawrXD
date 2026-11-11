// memory_pool_allocator.cpp
// Batch 9: Memory Pool Allocator for Benchmark Data
//
// Reduces allocation overhead during benchmark runs
// Uses object pools and arena allocation strategies

#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <new>

namespace Benchmark {
namespace Performance {

// Fixed-size object pool for sample data
class SamplePoolAllocator {
public:
    explicit SamplePoolAllocator(size_t block_size = 64, size_t initial_blocks = 1024)
        : block_size_(block_size),
          blocks_allocated_(0) {
        // Pre-allocate initial blocks
        AllocateBlock(initial_blocks);
    }

    ~SamplePoolAllocator() {
        // Free all blocks
        for (auto* block : blocks_) {
            delete[] block;
        }
    }

    // Allocate a block from the pool
    void* Allocate() {
        // Try to get from free list (lock-free)
        Block* block = free_list_.load(std::memory_order_acquire);
        
        while (block != nullptr) {
            Block* next = block->next;
            if (free_list_.compare_exchange_weak(block, next,
                                                  std::memory_order_release,
                                                  std::memory_order_acquire)) {
                return reinterpret_cast<void*>(block);
            }
        }

        // Free list empty, allocate new block
        std::lock_guard<std::mutex> lock(mutex_);
        AllocateBlock(1);
        
        // Try again
        block = free_list_.load(std::memory_order_acquire);
        if (block != nullptr) {
            Block* next = block->next;
            free_list_.store(next, std::memory_order_release);
            return reinterpret_cast<void*>(block);
        }
        
        return nullptr;
    }

    // Return a block to the pool
    void Deallocate(void* ptr) {
        if (!ptr) return;
        
        Block* block = reinterpret_cast<Block*>(ptr);
        
        // Push onto free list (lock-free stack)
        Block* old_head = free_list_.load(std::memory_order_acquire);
        do {
            block->next = old_head;
        } while (!free_list_.compare_exchange_weak(old_head, block,
                                                    std::memory_order_release,
                                                    std::memory_order_acquire));
    }

    // Get number of blocks in use
    size_t BlocksInUse() const {
        return blocks_allocated_ - FreeListSize();
    }

    // Get total blocks allocated
    size_t TotalBlocks() const {
        return blocks_allocated_;
    }

private:
    struct Block {
        Block* next = nullptr;
        alignas(64) char data[56]; // Pad to 64 bytes (cache line)
    };

    size_t block_size_;
    std::vector<Block*> blocks_;
    alignas(64) std::atomic<Block*> free_list_{nullptr};
    alignas(64) std::atomic<size_t> blocks_allocated_{0};
    std::mutex mutex_;

    void AllocateBlock(size_t count) {
        for (size_t i = 0; i < count; ++i) {
            Block* block = new Block();
            blocks_.push_back(block);
            
            // Add to free list
            Block* old_head = free_list_.load(std::memory_order_relaxed);
            block->next = old_head;
            free_list_.store(block, std::memory_order_relaxed);
            
            blocks_allocated_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    size_t FreeListSize() const {
        size_t count = 0;
        Block* current = free_list_.load(std::memory_order_acquire);
        while (current != nullptr) {
            ++count;
            current = current->next;
        }
        return count;
    }
};

// Arena allocator for temporary allocations during benchmarks
class ArenaAllocator {
public:
    explicit ArenaAllocator(size_t initial_size = 1024 * 1024) // 1MB default
        : current_size_(initial_size),
          used_(0) {
        arena_ = static_cast<char*>(std::aligned_alloc(64, initial_size));
    }

    ~ArenaAllocator() {
        std::free(arena_);
    }

    // Allocate from arena (no individual deallocation)
    void* Allocate(size_t size, size_t alignment = 64) {
        // Align current position
        size_t aligned_used = (used_ + alignment - 1) & ~(alignment - 1);
        
        if (aligned_used + size > current_size_) {
            // Arena full - in production, would allocate new arena
            return nullptr;
        }
        
        void* result = arena_ + aligned_used;
        used_ = aligned_used + size;
        return result;
    }

    // Reset arena (frees all allocations at once)
    void Reset() noexcept {
        used_ = 0;
    }

    // Get bytes used
    size_t Used() const noexcept {
        return used_;
    }

    // Get total capacity
    size_t Capacity() const noexcept {
        return current_size_;
    }

private:
    char* arena_;
    size_t current_size_;
    alignas(64) size_t used_;
};

// Ring buffer for lock-free sample collection
class RingBuffer {
public:
    explicit RingBuffer(size_t capacity)
        : capacity_(capacity),
          buffer_(capacity),
          write_index_(0),
          read_index_(0) {}

    // Try to write a value (non-blocking)
    bool TryWrite(uint64_t value) noexcept {
        size_t current_write = write_index_.load(std::memory_order_relaxed);
        size_t next_write = (current_write + 1) % capacity_;
        
        // Check if buffer is full
        if (next_write == read_index_.load(std::memory_order_acquire)) {
            return false; // Buffer full
        }
        
        buffer_[current_write].value = value;
        write_index_.store(next_write, std::memory_order_release);
        return true;
    }

    // Try to read a value (non-blocking)
    bool TryRead(uint64_t& value) noexcept {
        size_t current_read = read_index_.load(std::memory_order_relaxed);
        
        // Check if buffer is empty
        if (current_read == write_index_.load(std::memory_order_acquire)) {
            return false; // Buffer empty
        }
        
        value = buffer_[current_read].value;
        read_index_.store((current_read + 1) % capacity_, std::memory_order_release);
        return true;
    }

    // Get number of items in buffer
    size_t Size() const noexcept {
        size_t write = write_index_.load(std::memory_order_acquire);
        size_t read = read_index_.load(std::memory_order_acquire);
        
        if (write >= read) {
            return write - read;
        } else {
            return capacity_ - (read - write);
        }
    }

    // Check if buffer is empty
    bool Empty() const noexcept {
        return write_index_.load(std::memory_order_acquire) == 
               read_index_.load(std::memory_order_acquire);
    }

    // Check if buffer is full
    bool Full() const noexcept {
        size_t next_write = (write_index_.load(std::memory_order_acquire) + 1) % capacity_;
        return next_write == read_index_.load(std::memory_order_acquire);
    }

private:
    struct alignas(64) Item {
        uint64_t value;
    };

    size_t capacity_;
    std::vector<Item> buffer_;
    alignas(64) std::atomic<size_t> write_index_;
    alignas(64) std::atomic<size_t> read_index_;
};

// Smart pointer for pooled allocations
template<typename T>
class PooledPtr {
public:
    PooledPtr(T* ptr, SamplePoolAllocator* pool) 
        : ptr_(ptr), pool_(pool) {}
    
    ~PooledPtr() {
        if (ptr_ && pool_) {
            ptr_->~T(); // Call destructor
            pool_->Deallocate(ptr_);
        }
    }

    // Move semantics
    PooledPtr(PooledPtr&& other) noexcept
        : ptr_(other.ptr_), pool_(other.pool_) {
        other.ptr_ = nullptr;
        other.pool_ = nullptr;
    }
    
    PooledPtr& operator=(PooledPtr&& other) noexcept {
        if (this != &other) {
            if (ptr_ && pool_) {
                ptr_->~T();
                pool_->Deallocate(ptr_);
            }
            ptr_ = other.ptr_;
            pool_ = other.pool_;
            other.ptr_ = nullptr;
            other.pool_ = nullptr;
        }
        return *this;
    }

    // Disable copy
    PooledPtr(const PooledPtr&) = delete;
    PooledPtr& operator=(const PooledPtr&) = delete;

    T* get() const noexcept { return ptr_; }
    T* operator->() const noexcept { return ptr_; }
    T& operator*() const noexcept { return *ptr_; }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

private:
    T* ptr_;
    SamplePoolAllocator* pool_;
};

// Memory usage tracker
class MemoryTracker {
public:
    static size_t GetCurrentRSS() {
#ifdef _WIN32
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize;
        }
        return 0;
#else
        // Parse /proc/self/status
        FILE* fp = fopen("/proc/self/status", "r");
        if (!fp) return 0;
        
        char line[256];
        size_t rss = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line, "VmRSS: %zu", &rss);
                rss *= 1024; // Convert from kB to bytes
                break;
            }
        }
        fclose(fp);
        return rss;
#endif
    }

    static size_t GetPeakRSS() {
#ifdef _WIN32
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.PeakWorkingSetSize;
        }
        return 0;
#else
        struct rusage rusage;
        if (getrusage(RUSAGE_SELF, &rusage) == 0) {
            return static_cast<size_t>(rusage.ru_maxrss) * 1024;
        }
        return 0;
#endif
    }
};

} // namespace Performance
} // namespace Benchmark
