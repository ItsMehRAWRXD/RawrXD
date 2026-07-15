// RawrXD Memory Optimizer Implementation
// Phase AN: Memory Optimization

#include "memory_optimizer.hpp"
#include <iostream>
#include <cstring>
#include <algorithm>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace rawrxd {
namespace memory {

// Global memory optimizer instance
static std::unique_ptr<MemoryOptimizer> g_memory_optimizer;

MemoryOptimizer* getMemoryOptimizer() {
    return g_memory_optimizer.get();
}

void setMemoryOptimizer(std::unique_ptr<MemoryOptimizer> optimizer) {
    g_memory_optimizer = std::move(optimizer);
}

// MemoryOptimizer implementation
MemoryOptimizer::MemoryOptimizer()
    : cache_limit_(1024 * 1024 * 1024)  // 1GB default
    , gc_threshold_(512 * 1024 * 1024)  // 512MB default
    , initialized_(false) {
}

MemoryOptimizer::~MemoryOptimizer() {
    shutdown();
}

bool MemoryOptimizer::initialize() {
    // Get system memory info
#ifdef _WIN32
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    stats_.system_total = memInfo.ullTotalPhys;
    stats_.system_available = memInfo.ullAvailPhys;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    stats_.system_total = pages * page_size;
    stats_.system_available = sysconf(_SC_AVPHYS_PAGES) * page_size;
#endif

    initialized_ = true;
    return true;
}

void MemoryOptimizer::shutdown() {
    if (!initialized_) return;

    // Release all cached memory
    releaseCache();

    // Free all pools
    pools_.clear();

    // Free remaining allocations
    for (const auto& [ptr, block] : allocations_) {
        deallocateInternal(ptr);
    }
    allocations_.clear();

    initialized_ = false;
}

void* MemoryOptimizer::allocate(size_t size, size_t alignment, const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);

    void* ptr = allocateInternal(size, alignment);
    if (!ptr) return nullptr;

    MemoryBlock block;
    block.ptr = ptr;
    block.size = size;
    block.alignment = alignment;
    block.tag = tag;

    allocations_[ptr] = block;

    stats_.total_allocated += size;
    stats_.current_usage += size;
    stats_.peak_usage = std::max(stats_.peak_usage, stats_.current_usage);

    updatePressureLevel();

    return ptr;
}

void MemoryOptimizer::deallocate(void* ptr) {
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) {
        // Not tracked, use standard free
        deallocateInternal(ptr);
        return;
    }

    size_t size = it->second.size;
    allocations_.erase(it);

    deallocateInternal(ptr);

    stats_.total_freed += size;
    stats_.current_usage -= size;

    updatePressureLevel();
}

void* MemoryOptimizer::reallocate(void* ptr, size_t new_size) {
    if (!ptr) return allocate(new_size);
    if (new_size == 0) {
        deallocate(ptr);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) {
        return nullptr;
    }

    size_t old_size = it->second.size;

    // Allocate new block
    void* new_ptr = allocateInternal(new_size, it->second.alignment);
    if (!new_ptr) return nullptr;

    // Copy data
    std::memcpy(new_ptr, ptr, std::min(old_size, new_size));

    // Free old block
    deallocateInternal(ptr);

    // Update tracking
    allocations_.erase(it);

    MemoryBlock block;
    block.ptr = new_ptr;
    block.size = new_size;
    block.alignment = it->second.alignment;
    block.tag = it->second.tag;

    allocations_[new_ptr] = block;

    stats_.total_allocated += new_size;
    stats_.total_freed += old_size;
    stats_.current_usage += new_size - old_size;
    stats_.peak_usage = std::max(stats_.peak_usage, stats_.current_usage);

    return new_ptr;
}

void* MemoryOptimizer::allocatePinned(size_t size, const std::string& tag) {
#ifdef _WIN32
    // Windows pinned memory
    void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    // Linux pinned memory
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (ptr == MAP_FAILED) ptr = nullptr;
#endif

    if (ptr) {
        std::lock_guard<std::mutex> lock(mutex_);

        MemoryBlock block;
        block.ptr = ptr;
        block.size = size;
        block.is_pinned = true;
        block.tag = tag;

        allocations_[ptr] = block;

        stats_.total_allocated += size;
        stats_.current_usage += size;
    }

    return ptr;
}

void MemoryOptimizer::deallocatePinned(void* ptr) {
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it != allocations_.end()) {
        stats_.total_freed += it->second.size;
        stats_.current_usage -= it->second.size;
        allocations_.erase(it);
    }

#ifdef _WIN32
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    munmap(ptr, it->second.size);
#endif
}

void* MemoryOptimizer::allocateAligned(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void* ptr = nullptr;
    posix_memalign(&ptr, alignment, size);
    return ptr;
#endif
}

void MemoryOptimizer::deallocateAligned(void* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

bool MemoryOptimizer::createPool(const std::string& name, const PoolConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pools_.find(name) != pools_.end()) {
        return false; // Pool already exists
    }

    auto pool = std::make_unique<MemoryPool>(config);
    if (!pool->initialize()) {
        return false;
    }

    pools_[name] = std::move(pool);
    stats_.pool_size += config.block_size * config.initial_blocks;

    return true;
}

void MemoryOptimizer::destroyPool(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(name);
    if (it != pools_.end()) {
        stats_.pool_size -= it->second->getBlockSize() * it->second->getTotalBlocks();
        pools_.erase(it);
    }
}

void* MemoryOptimizer::allocateFromPool(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(name);
    if (it == pools_.end()) {
        return nullptr;
    }

    return it->second->allocate();
}

void MemoryOptimizer::deallocateToPool(const std::string& name, void* ptr) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pools_.find(name);
    if (it != pools_.end()) {
        it->second->deallocate(ptr);
    }
}

void* MemoryOptimizer::allocateCached(size_t size, const std::string& tag) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we have a cached block of suitable size
    auto& cached = cache_[tag];
    for (auto it = cached.begin(); it != cached.end(); ++it) {
        auto alloc_it = allocations_.find(*it);
        if (alloc_it != allocations_.end() && alloc_it->second.size >= size) {
            void* ptr = *it;
            cached.erase(it);
            alloc_it->second.is_cached = false;
            stats_.cache_size -= alloc_it->second.size;
            return ptr;
        }
    }

    // Allocate new block
    return allocate(size, 64, tag);
}

void MemoryOptimizer::releaseCache() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [tag, cached] : cache_) {
        for (void* ptr : cached) {
            auto it = allocations_.find(ptr);
            if (it != allocations_.end()) {
                stats_.total_freed += it->second.size;
                stats_.current_usage -= it->second.size;
                deallocateInternal(ptr);
                allocations_.erase(it);
            }
        }
    }

    cache_.clear();
    stats_.cache_size = 0;
}

void MemoryOptimizer::setCacheLimit(size_t limit) {
    cache_limit_ = limit;

    // If current cache exceeds limit, release some
    if (stats_.cache_size > cache_limit_) {
        releaseCache();
    }
}

bool MemoryOptimizer::defragment() {
    // Memory defragmentation is complex and platform-specific
    // This is a simplified placeholder
    return true;
}

size_t MemoryOptimizer::getFragmentation() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.fragmentation;
}

MemoryStats MemoryOptimizer::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void MemoryOptimizer::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = MemoryStats();
}

void MemoryOptimizer::printStats() const {
    auto stats = getStats();

    std::cout << "Memory Statistics:" << std::endl;
    std::cout << "  Total allocated: " << stats.total_allocated << " bytes" << std::endl;
    std::cout << "  Total freed: " << stats.total_freed << " bytes" << std::endl;
    std::cout << "  Current usage: " << stats.current_usage << " bytes" << std::endl;
    std::cout << "  Peak usage: " << stats.peak_usage << " bytes" << std::endl;
    std::cout << "  System total: " << stats.system_total << " bytes" << std::endl;
    std::cout << "  System available: " << stats.system_available << " bytes" << std::endl;
    std::cout << "  Cache size: " << stats.cache_size << " bytes" << std::endl;
    std::cout << "  Pool size: " << stats.pool_size << " bytes" << std::endl;
    std::cout << "  Fragmentation: " << stats.fragmentation << " bytes" << std::endl;
}

MemoryPressure MemoryOptimizer::getPressureLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.pressure_level;
}

void MemoryOptimizer::setPressureCallback(std::function<void(MemoryPressure)> callback) {
    pressure_callback_ = callback;
}

void MemoryOptimizer::handleMemoryPressure() {
    auto level = getPressureLevel();

    switch (level) {
        case MemoryPressure::LOW:
            // Light cleanup
            collectGarbage();
            break;
        case MemoryPressure::MEDIUM:
            // Moderate cleanup
            releaseCache();
            collectGarbage();
            break;
        case MemoryPressure::HIGH:
            // Aggressive cleanup
            releaseCache();
            defragment();
            collectGarbage();
            break;
        case MemoryPressure::CRITICAL:
            // Emergency cleanup
            releaseCache();
            defragment();
            collectGarbage();
            // Could also trigger model offloading
            break;
        default:
            break;
    }

    if (pressure_callback_) {
        pressure_callback_(level);
    }
}

void MemoryOptimizer::collectGarbage() {
    // Trigger system garbage collection if applicable
    // This is a placeholder for garbage collection logic
}

void MemoryOptimizer::setGCThreshold(size_t threshold) {
    gc_threshold_ = threshold;
}

void* MemoryOptimizer::mapFile(const std::string& path, size_t offset, size_t size) {
#ifdef _WIN32
    // Windows file mapping
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return nullptr;
    }

    void* ptr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, offset, size);

    CloseHandle(hMapping);
    CloseHandle(hFile);

    return ptr;
#else
    // Linux file mapping
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return nullptr;

    void* ptr = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, offset);
    close(fd);

    if (ptr == MAP_FAILED) return nullptr;
    return ptr;
#endif
}

void MemoryOptimizer::unmapFile(void* ptr, size_t size) {
#ifdef _WIN32
    UnmapViewOfFile(ptr);
#else
    munmap(ptr, size);
#endif
}

void MemoryOptimizer::prefetch(void* ptr, size_t size) {
#ifdef _WIN32
    // Windows prefetch
    WIN32_MEMORY_RANGE_ENTRY entry;
    entry.VirtualAddress = ptr;
    entry.NumberOfBytes = size;
    PrefetchVirtualMemory(GetCurrentProcess(), 1, &entry, 0);
#else
    // Linux prefetch
    madvise(ptr, size, MADV_WILLNEED);
#endif
}

void MemoryOptimizer::adviseSequential(void* ptr, size_t size) {
#ifdef _WIN32
    // Windows sequential access hint
    // Not directly supported, use VirtualAlloc hints if needed
#else
    madvise(ptr, size, MADV_SEQUENTIAL);
#endif
}

void MemoryOptimizer::adviseRandom(void* ptr, size_t size) {
#ifdef _WIN32
    // Windows random access hint
#else
    madvise(ptr, size, MADV_RANDOM);
#endif
}

void MemoryOptimizer::adviseWillNeed(void* ptr, size_t size) {
    prefetch(ptr, size);
}

void MemoryOptimizer::adviseDontNeed(void* ptr, size_t size) {
#ifdef _WIN32
    // Windows discard hint
    VirtualUnlock(ptr, size);
#else
    madvise(ptr, size, MADV_DONTNEED);
#endif
}

void MemoryOptimizer::updatePressureLevel() {
    if (stats_.system_total == 0) return;

    double usage_ratio = static_cast<double>(stats_.current_usage) / stats_.system_total;

    if (usage_ratio > 0.95) {
        stats_.pressure_level = MemoryPressure::CRITICAL;
    } else if (usage_ratio > 0.85) {
        stats_.pressure_level = MemoryPressure::HIGH;
    } else if (usage_ratio > 0.70) {
        stats_.pressure_level = MemoryPressure::MEDIUM;
    } else if (usage_ratio > 0.50) {
        stats_.pressure_level = MemoryPressure::LOW;
    } else {
        stats_.pressure_level = MemoryPressure::NONE;
    }
}

void* MemoryOptimizer::allocateInternal(size_t size, size_t alignment) {
    return allocateAligned(size, alignment);
}

void MemoryOptimizer::deallocateInternal(void* ptr) {
    deallocateAligned(ptr);
}

// MemoryPool implementation
MemoryPool::MemoryPool(const PoolConfig& config) : config_(config) {}

MemoryPool::~MemoryPool() = default;

bool MemoryPool::initialize() {
    return grow();
}

void* MemoryPool::allocate() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (free_blocks_.empty()) {
        if (!config_.growable || !grow()) {
            return nullptr;
        }
    }

    void* ptr = free_blocks_.back();
    free_blocks_.pop_back();
    allocated_blocks_.push_back(ptr);

    return ptr;
}

void MemoryPool::deallocate(void* ptr) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find(allocated_blocks_.begin(), allocated_blocks_.end(), ptr);
    if (it != allocated_blocks_.end()) {
        allocated_blocks_.erase(it);
        free_blocks_.push_back(ptr);
    }
}

bool MemoryPool::grow() {
    if (getTotalBlocks() >= config_.max_blocks) {
        return false;
    }

    size_t blocks_to_add = std::min(config_.initial_blocks, config_.max_blocks - getTotalBlocks());
    size_t chunk_size = blocks_to_add * config_.block_size;

    auto chunk = std::make_unique<uint8_t[]>(chunk_size);
    uint8_t* chunk_ptr = chunk.get();

    for (size_t i = 0; i < blocks_to_add; ++i) {
        free_blocks_.push_back(chunk_ptr + i * config_.block_size);
    }

    memory_chunks_.push_back(std::move(chunk));

    return true;
}

size_t MemoryPool::getFreeBlocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return free_blocks_.size();
}

size_t MemoryPool::getTotalBlocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return free_blocks_.size() + allocated_blocks_.size();
}

// ArenaAllocator implementation
ArenaAllocator::ArenaAllocator(size_t initial_size)
    : capacity_(initial_size)
    , used_(0) {
    memory_ = std::make_unique<uint8_t[]>(capacity_);
}

ArenaAllocator::~ArenaAllocator() = default;

void* ArenaAllocator::allocate(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Align current position
    size_t aligned_used = (used_ + alignment - 1) & ~(alignment - 1);

    if (aligned_used + size > capacity_) {
        return nullptr; // Out of memory
    }

    void* ptr = memory_.get() + aligned_used;
    used_ = aligned_used + size;

    return ptr;
}

void ArenaAllocator::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    used_ = 0;
}

} // namespace memory
} // namespace rawrxd
