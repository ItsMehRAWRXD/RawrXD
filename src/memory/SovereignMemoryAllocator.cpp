//=============================================================================
// RawrXD Sovereign Memory Allocator - Implementation
// Phase 3A: NUMA-Aware Large Page Memory Management
//=============================================================================

#include "SovereignMemoryAllocator.hpp"
#include <processthreadsapi.h>
#include <sysinfoapi.h>
#include <profileapi.h>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Memory {

//=============================================================================
// NUMA Topology Detection
//=============================================================================
NumaTopology NumaTopology::Detect() {
    NumaTopology topo{};
    
    // Get number of NUMA nodes
    ULONG numNodes = 0;
    if (!GetNumaHighestNodeNumber(&numNodes)) {
        // NUMA not supported or single node
        topo.numNodes = 1;
        topo.numProcessors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        topo.processorsPerNode = topo.numProcessors;
        
        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            topo.totalPhysicalMemory = memStatus.ullTotalPhys;
        }
        topo.nodeMemory.push_back(topo.totalPhysicalMemory);
        return topo;
    }
    
    topo.numNodes = numNodes + 1;  // GetNumaHighestNodeNumber returns max index
    topo.numProcessors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    topo.processorsPerNode = topo.numProcessors / topo.numNodes;
    
    // Get memory per node
    for (uint32_t i = 0; i < topo.numNodes; i++) {
        ULONGLONG nodeMem = 0;
        if (GetNumaAvailableMemoryNodeEx(i, &nodeMem)) {
            topo.nodeMemory.push_back(nodeMem);
            topo.totalPhysicalMemory += nodeMem;
        } else {
            topo.nodeMemory.push_back(0);
        }
    }
    
    return topo;
}

//=============================================================================
// Memory Statistics
//=============================================================================
void MemoryStats::Reset() {
    totalAllocations = 0;
    totalDeallocations = 0;
    activeAllocations = 0;
    bytesAllocated = 0;
    bytesCommitted = 0;
    largePageAllocations = 0;
    standardPageAllocations = 0;
    numaLocalAllocations = 0;
    numaRemoteAllocations = 0;
    allocationTimeUs = 0;
    allocationCount = 0;
    tlbMisses = 0;
    pageFaults = 0;
}

//=============================================================================
// Memory Residency Handle
//=============================================================================
MemoryResidencyHandle::MemoryResidencyHandle(
    void* ptr, 
    size_t size, 
    MemoryTier tier,
    uint32_t numaNode,
    SovereignMemoryAllocator* allocator
) : ptr_(ptr), size_(size), tier_(tier), numaNode_(numaNode), allocator_(allocator) {
}

MemoryResidencyHandle::~MemoryResidencyHandle() {
    if (ptr_ && allocator_) {
        if (locked_) {
            Unlock();
        }
        allocator_->Free(ptr_, size_, tier_, numaNode_);
    }
}

MemoryResidencyHandle::MemoryResidencyHandle(MemoryResidencyHandle&& other) noexcept {
    ptr_ = other.ptr_;
    size_ = other.size_;
    tier_ = other.tier_;
    numaNode_ = other.numaNode_;
    allocator_ = other.allocator_;
    locked_ = other.locked_;
    other.Reset();
}

MemoryResidencyHandle& MemoryResidencyHandle::operator=(MemoryResidencyHandle&& other) noexcept {
    if (this != &other) {
        if (ptr_ && allocator_) {
            if (locked_) Unlock();
            allocator_->Free(ptr_, size_, tier_, numaNode_);
        }
        ptr_ = other.ptr_;
        size_ = other.size_;
        tier_ = other.tier_;
        numaNode_ = other.numaNode_;
        allocator_ = other.allocator_;
        locked_ = other.locked_;
        other.Reset();
    }
    return *this;
}

void* MemoryResidencyHandle::Release() {
    void* p = ptr_;
    Reset();
    return p;
}

void MemoryResidencyHandle::Reset() {
    ptr_ = nullptr;
    size_ = 0;
    tier_ = MemoryTier::STANDARD_DRAM;
    numaNode_ = 0;
    allocator_ = nullptr;
    locked_ = false;
}

void MemoryResidencyHandle::Prefault() {
    if (!ptr_ || size_ == 0) return;
    
    // Touch each page to force allocation
    volatile char* p = static_cast<volatile char*>(ptr_);
    const size_t pageSize = 4096;  // Standard page size
    for (size_t i = 0; i < size_; i += pageSize) {
        p[i] = 0;
    }
}

bool MemoryResidencyHandle::Lock() {
    if (!ptr_ || locked_) return false;
    
    // Lock pages in memory (prevent swapping)
    SIZE_T size = size_;
    if (VirtualLock(ptr_, size)) {
        locked_ = true;
        return true;
    }
    return false;
}

void MemoryResidencyHandle::Unlock() {
    if (!ptr_ || !locked_) return;
    
    SIZE_T size = size_;
    VirtualUnlock(ptr_, size);
    locked_ = false;
}

//=============================================================================
// NUMA Memory Pool
//=============================================================================
NumaMemoryPool::NumaMemoryPool(uint32_t numaNode, size_t blockSize)
    : numaNode_(numaNode), blockSize_(blockSize) {
}

NumaMemoryPool::~NumaMemoryPool() {
    Shutdown();
}

bool NumaMemoryPool::Initialize(size_t poolSize, bool useLargePages) {
    if (poolBase_) return false;  // Already initialized
    
    // Allocate pool memory with NUMA affinity
    DWORD allocType = MEM_RESERVE | MEM_COMMIT;
    DWORD protect = PAGE_READWRITE;
    
    if (useLargePages) {
        // Try to allocate with large pages
        HANDLE hToken = GetCurrentProcess();
        TOKEN_PRIVILEGES tp{};
        if (OpenProcessToken(hToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            if (LookupPrivilegeValue(nullptr, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
                    allocType |= MEM_LARGE_PAGES;
                }
            }
            CloseHandle(hToken);
        }
    }
    
    // Use VirtualAllocExNuma for NUMA-aware allocation
    poolBase_ = VirtualAllocExNuma(
        GetCurrentProcess(),
        nullptr,
        poolSize,
        allocType,
        protect,
        numaNode_
    );
    
    if (!poolBase_) {
        // Fallback to standard VirtualAlloc
        poolBase_ = VirtualAlloc(nullptr, poolSize, allocType, protect);
        if (!poolBase_) return false;
    }
    
    poolSize_ = poolSize;
    
    // Initialize free list
    size_t numBlocks = poolSize / blockSize_;
    char* current = static_cast<char*>(poolBase_);
    
    for (size_t i = 0; i < numBlocks; i++) {
        Block* block = reinterpret_cast<Block*>(current);
        block->size = blockSize_;
        block->allocationId = 0;
        PushFreeBlock(block);
        current += blockSize_;
    }
    
    freeBlockCount_ = numBlocks;
    return true;
}

void NumaMemoryPool::Shutdown() {
    if (poolBase_) {
        VirtualFree(poolBase_, 0, MEM_RELEASE);
        poolBase_ = nullptr;
        poolSize_ = 0;
        freeList_.store(nullptr);
        allocatedBlocks_ = 0;
        freeBlockCount_ = 0;
    }
}

void* NumaMemoryPool::Allocate(size_t size) {
    if (size > blockSize_) return nullptr;
    
    Block* block = PopFreeBlock();
    if (!block) return nullptr;
    
    allocatedBlocks_++;
    freeBlockCount_--;
    block->allocationId = allocatedBlocks_.load();
    
    return block;
}

void NumaMemoryPool::Free(void* ptr, size_t size) {
    if (!ptr) return;
    
    Block* block = static_cast<Block*>(ptr);
    block->allocationId = 0;
    PushFreeBlock(block);
    
    allocatedBlocks_--;
    freeBlockCount_++;
}

void NumaMemoryPool::PushFreeBlock(Block* block) {
    Block* expected = freeList_.load(std::memory_order_relaxed);
    do {
        block->next = expected;
    } while (!freeList_.compare_exchange_weak(
        expected, block,
        std::memory_order_release,
        std::memory_order_relaxed));
}

NumaMemoryPool::Block* NumaMemoryPool::PopFreeBlock() {
    Block* block = freeList_.load(std::memory_order_relaxed);
    while (block) {
        Block* next = block->next;
        if (freeList_.compare_exchange_weak(
            block, next,
            std::memory_order_acquire,
            std::memory_order_relaxed)) {
            return block;
        }
    }
    return nullptr;
}

size_t NumaMemoryPool::GetFreeBlocks() const {
    return freeBlockCount_.load();
}

size_t NumaMemoryPool::GetUsedBlocks() const {
    return allocatedBlocks_.load();
}

//=============================================================================
// Sovereign Memory Allocator
//=============================================================================
SovereignMemoryAllocator::SovereignMemoryAllocator() = default;

SovereignMemoryAllocator::~SovereignMemoryAllocator() {
    Shutdown();
}

bool SovereignMemoryAllocator::Initialize() {
    if (initialized_) return true;
    
    // Detect NUMA topology
    topology_ = NumaTopology::Detect();
    
    // Check large page support
    largePageSize_ = GetLargePageMinimum();
    largePagesAvailable_ = (largePageSize_ > 0);
    
    // Try to enable large page privilege
    if (largePagesAvailable_) {
        EnableLargePagePrivilege();
    }
    
    // Initialize NUMA pools
    numaPools_.resize(topology_.numNodes);
    
    initialized_ = true;
    return true;
}

void SovereignMemoryAllocator::Shutdown() {
    if (!initialized_) return;
    
    // Destroy all NUMA pools
    for (auto& pool : numaPools_) {
        if (pool) {
            pool->Shutdown();
            pool.reset();
        }
    }
    numaPools_.clear();
    
    initialized_ = false;
}

MemoryResidencyHandle SovereignMemoryAllocator::Allocate(
    size_t bytes,
    MemoryTier tier,
    uint32_t numaNode,
    AllocFlags flags
) {
    if (!initialized_) {
        return MemoryResidencyHandle();
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Sanitize NUMA node
    numaNode = SanitizeNumaNode(numaNode);
    
    // Determine actual tier based on availability
    MemoryTier actualTier = tier;
    if (tier == MemoryTier::LARGE_PAGE_DRAM && !largePagesAvailable_) {
        actualTier = MemoryTier::STANDARD_DRAM;
    }
    
    // Allocate based on tier
    void* ptr = nullptr;
    switch (actualTier) {
        case MemoryTier::LARGE_PAGE_DRAM:
            ptr = AllocateLargePages(bytes, numaNode, flags);
            break;
        case MemoryTier::STANDARD_DRAM:
        default:
            ptr = AllocateStandardPages(bytes, numaNode, flags);
            break;
    }
    
    if (!ptr) {
        return MemoryResidencyHandle();
    }
    
    // Calculate allocation time
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
    
    // Record telemetry
    RecordAllocation(bytes, actualTier, numaNode, duration.count());
    
    // Handle additional flags
    if (HasFlag(flags, AllocFlags::ZERO_INIT)) {
        memset(ptr, 0, bytes);
    }
    
    if (HasFlag(flags, AllocFlags::PREFETCH)) {
        // Prefault pages
        volatile char* p = static_cast<volatile char*>(ptr);
        const size_t pageSize = (actualTier == MemoryTier::LARGE_PAGE_DRAM) 
            ? largePageSize_ : 4096;
        for (size_t i = 0; i < bytes; i += pageSize) {
            p[i] = 0;
        }
    }
    
    return MemoryResidencyHandle(ptr, bytes, actualTier, numaNode, this);
}

void* SovereignMemoryAllocator::AllocateRaw(
    size_t bytes,
    MemoryTier tier,
    uint32_t numaNode,
    AllocFlags flags
) {
    auto handle = Allocate(bytes, tier, numaNode, flags);
    return handle.Release();
}

void SovereignMemoryAllocator::Free(void* ptr, size_t size, MemoryTier tier, uint32_t numaNode) {
    if (!ptr) return;
    
    switch (tier) {
        case MemoryTier::LARGE_PAGE_DRAM:
            FreeLargePages(ptr, size);
            break;
        case MemoryTier::STANDARD_DRAM:
        default:
            FreeStandardPages(ptr, size);
            break;
    }
    
    RecordDeallocation(size, tier, numaNode);
}

void* SovereignMemoryAllocator::AllocateStandardPages(size_t size, uint32_t numaNode, AllocFlags flags) {
    DWORD allocType = MEM_RESERVE | MEM_COMMIT;
    DWORD protect = PAGE_READWRITE;
    
    // Try NUMA-aware allocation first
    void* ptr = VirtualAllocExNuma(
        GetCurrentProcess(),
        nullptr,
        size,
        allocType,
        protect,
        numaNode
    );
    
    if (!ptr) {
        // Fallback to standard allocation
        ptr = VirtualAlloc(nullptr, size, allocType, protect);
    }
    
    return ptr;
}

void* SovereignMemoryAllocator::AllocateLargePages(size_t size, uint32_t numaNode, AllocFlags flags) {
    if (!largePagesAvailable_) {
        return AllocateStandardPages(size, numaNode, flags);
    }
    
    // Align size to large page boundary
    size = AlignUp(size, largePageSize_);
    
    DWORD allocType = MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES;
    DWORD protect = PAGE_READWRITE;
    
    // Try NUMA-aware large page allocation
    void* ptr = VirtualAllocExNuma(
        GetCurrentProcess(),
        nullptr,
        size,
        allocType,
        protect,
        numaNode
    );
    
    if (!ptr) {
        // Fallback to standard large pages
        ptr = VirtualAlloc(nullptr, size, allocType, protect);
    }
    
    return ptr;
}

void SovereignMemoryAllocator::FreeStandardPages(void* ptr, size_t size) {
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void SovereignMemoryAllocator::FreeLargePages(void* ptr, size_t size) {
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

uint32_t SovereignMemoryAllocator::GetCurrentNumaNode() const {
    PROCESSOR_NUMBER procNum;
    GetCurrentProcessorNumberEx(&procNum);
    
    uint16_t node = 0;
    GetNumaProcessorNodeEx(&procNum, &node);
    return node;
}

uint32_t SovereignMemoryAllocator::GetPreferredNumaNode() const {
    // Return the NUMA node with most available memory
    uint32_t bestNode = 0;
    uint64_t maxMemory = 0;
    
    for (uint32_t i = 0; i < topology_.numNodes; i++) {
        ULONGLONG available = 0;
        if (GetNumaAvailableMemoryNodeEx(i, &available)) {
            if (available > maxMemory) {
                maxMemory = available;
                bestNode = i;
            }
        }
    }
    
    return bestNode;
}

bool SovereignMemoryAllocator::BindThreadToNumaNode(uint32_t node) {
    if (node >= topology_.numNodes) return false;
    
    // Get processor mask for this node
    ULONGLONG processorMask = 0;
    if (!GetNumaNodeProcessorMaskEx(node, &processorMask)) {
        return false;
    }
    
    // Set thread affinity to processors on this node
    HANDLE hThread = GetCurrentThread();
    DWORD_PTR oldAffinity = SetThreadAffinityMask(hThread, processorMask);
    
    return (oldAffinity != 0);
}

bool SovereignMemoryAllocator::EnableLargePagePrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};
    
    if (!OpenProcessToken(GetCurrentProcess(), 
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                          &hToken)) {
        return false;
    }
    
    if (!LookupPrivilegeValue(nullptr, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);
    
    return (result && GetLastError() == ERROR_SUCCESS);
}

size_t SovereignMemoryAllocator::GetTierPageSize(MemoryTier tier) const {
    switch (tier) {
        case MemoryTier::LARGE_PAGE_DRAM:
            return largePageSize_;
        case MemoryTier::STANDARD_DRAM:
        default:
            return 4096;
    }
}

bool SovereignMemoryAllocator::IsTierAvailable(MemoryTier tier) const {
    switch (tier) {
        case MemoryTier::LARGE_PAGE_DRAM:
            return largePagesAvailable_;
        case MemoryTier::STANDARD_DRAM:
            return true;
        default:
            return false;
    }
}

MemoryStats SovereignMemoryAllocator::GetSnapshot() const {
    return stats_;
}

std::string SovereignMemoryAllocator::GetResidencyReport() const {
    std::ostringstream report;
    
    report << "╔══════════════════════════════════════════════════════════════╗\n";
    report << "║         RawrXD Memory Residency Report                       ║\n";
    report << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // NUMA topology
    report << "║ NUMA Topology:\n";
    report << "║   Nodes: " << topology_.numNodes << "\n";
    report << "║   Processors: " << topology_.numProcessors << "\n";
    report << "║   Total Physical Memory: " 
           << std::fixed << std::setprecision(2) 
           << (topology_.totalPhysicalMemory / (1024.0 * 1024.0 * 1024.0)) << " GB\n";
    
    for (size_t i = 0; i < topology_.nodeMemory.size(); i++) {
        report << "║   Node " << i << ": " 
               << (topology_.nodeMemory[i] / (1024.0 * 1024.0 * 1024.0)) << " GB\n";
    }
    report << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Memory tiers
    report << "║ Memory Tiers:\n";
    report << "║   Large Pages: " << (largePagesAvailable_ ? "Available" : "Not Available") 
           << " (" << (largePageSize_ / (1024 * 1024)) << " MB)\n";
    report << "║   Standard Pages: 4 KB\n";
    report << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Allocation statistics
    report << "║ Allocation Statistics:\n";
    report << "║   Total Allocations: " << stats_.totalAllocations.load() << "\n";
    report << "║   Active Allocations: " << stats_.activeAllocations.load() << "\n";
    report << "║   Bytes Allocated: " 
           << std::fixed << std::setprecision(2)
           << (stats_.bytesAllocated.load() / (1024.0 * 1024.0)) << " MB\n";
    report << "║   Large Page Allocations: " << stats_.largePageAllocations.load() << "\n";
    report << "║   Standard Page Allocations: " << stats_.standardPageAllocations.load() << "\n";
    report << "║   NUMA Local: " << stats_.numaLocalAllocations.load() << "\n";
    report << "║   NUMA Remote: " << stats_.numaRemoteAllocations.load() << "\n";
    report << "║   Avg Allocation Time: " << stats_.GetAverageAllocationTimeUs() << " us\n";
    report << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return report.str();
}

bool SovereignMemoryAllocator::CreateNumaPool(uint32_t numaNode, size_t poolSize, bool useLargePages) {
    if (numaNode >= topology_.numNodes) return false;
    
    std::lock_guard<std::mutex> lock(poolsMutex_);
    
    if (numaPools_[numaNode]) {
        return false;  // Pool already exists
    }
    
    auto pool = std::make_unique<NumaMemoryPool>(numaNode, 64 * 1024);  // 64KB blocks
    if (!pool->Initialize(poolSize, useLargePages)) {
        return false;
    }
    
    numaPools_[numaNode] = std::move(pool);
    return true;
}

void SovereignMemoryAllocator::DestroyNumaPool(uint32_t numaNode) {
    std::lock_guard<std::mutex> lock(poolsMutex_);
    
    if (numaNode < numaPools_.size() && numaPools_[numaNode]) {
        numaPools_[numaNode]->Shutdown();
        numaPools_[numaNode].reset();
    }
}

size_t SovereignMemoryAllocator::AlignUp(size_t size, size_t alignment) const {
    return (size + alignment - 1) & ~(alignment - 1);
}

uint32_t SovereignMemoryAllocator::SanitizeNumaNode(uint32_t node) const {
    if (node == UINT32_MAX || node >= topology_.numNodes) {
        return GetCurrentNumaNode();
    }
    return node;
}

void SovereignMemoryAllocator::RecordAllocation(size_t size, MemoryTier tier, uint32_t numaNode, uint64_t timeUs) {
    stats_.totalAllocations++;
    stats_.activeAllocations++;
    stats_.bytesAllocated += size;
    stats_.allocationTimeUs += timeUs;
    stats_.allocationCount++;
    
    if (tier == MemoryTier::LARGE_PAGE_DRAM) {
        stats_.largePageAllocations++;
    } else {
        stats_.standardPageAllocations++;
    }
    
    uint32_t currentNode = GetCurrentNumaNode();
    if (numaNode == currentNode) {
        stats_.numaLocalAllocations++;
    } else {
        stats_.numaRemoteAllocations++;
    }
}

void SovereignMemoryAllocator::RecordDeallocation(size_t size, MemoryTier tier, uint32_t numaNode) {
    stats_.totalDeallocations++;
    stats_.activeAllocations--;
    stats_.bytesAllocated -= size;
}

//=============================================================================
// Global Allocator Singleton
//=============================================================================
static std::unique_ptr<SovereignMemoryAllocator> g_globalAllocator;
static std::once_flag g_initFlag;

SovereignMemoryAllocator& GetGlobalAllocator() {
    std::call_once(g_initFlag, []() {
        g_globalAllocator = std::make_unique<SovereignMemoryAllocator>();
        g_globalAllocator->Initialize();
    });
    return *g_globalAllocator;
}

bool InitializeGlobalAllocator() {
    return GetGlobalAllocator().IsInitialized();
}

void ShutdownGlobalAllocator() {
    if (g_globalAllocator) {
        g_globalAllocator->Shutdown();
        g_globalAllocator.reset();
    }
}

} // namespace Memory
} // namespace RawrXD
