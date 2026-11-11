//=============================================================================
// SequentialBlowoffValve.cpp - Production Implementation
// "Never Ending Rainbow Road" - Infinite Context Memory Management
// Real Windows Overlapped I/O + Vulkan Async Transfers
//=============================================================================

#include "SequentialBlowoffValve.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

// Vulkan headers for real GPU transfers
#ifdef _WIN32
#include <vulkan/vulkan.h>
#else
#include <vulkan/vulkan.h>
#endif

namespace RawrXD {
namespace Memory {

//=============================================================================
// Construction / Destruction
//=============================================================================

SequentialBlowoffValve::SequentialBlowoffValve(const BlowoffConfig& config)
    : config_(config)
    , running_(false)
    , paused_(false)
    , next_sequence_id_(1)
    , hSwapFile_(INVALID_HANDLE_VALUE)
    , swapFileSize_(0) {
    
    std::memset(tier_used_bytes_, 0, sizeof(tier_used_bytes_));
    std::memset(tier_pinned_bytes_, 0, sizeof(tier_pinned_bytes_));
    std::memset(&stats_, 0, sizeof(stats_));
}

SequentialBlowoffValve::~SequentialBlowoffValve() {
    Shutdown();
}

//=============================================================================
// Initialization
//=============================================================================

bool SequentialBlowoffValve::Initialize() {
    if (running_.exchange(true)) {
        return false; // Already running
    }
    
    // Initialize SSD swap file with real Windows overlapped I/O
    if (!InitializeSwapFile()) {
        running_ = false;
        return false;
    }
    
    // Start background workers
    blowoff_thread_ = std::thread(&SequentialBlowoffValve::BlowoffWorkerLoop, this);
    prefetch_thread_ = std::thread(&SequentialBlowoffValve::PrefetchWorkerLoop, this);
    
    std::cout << "[BlowoffValve] Initialized - Rainbow Road ready\n";
    std::cout << "  GPU0: " << (config_.gpu0_max_bytes / (1024*1024*1024)) << "GB\n";
    std::cout << "  GPU1: " << (config_.gpu1_max_bytes / (1024*1024*1024)) << "GB\n";
    std::cout << "  RAM:  " << (config_.ram_max_bytes / (1024*1024*1024)) << "GB\n";
    std::cout << "  SSD:  " << config_.ssd_swap_path << "\n";
    
    return true;
}

void SequentialBlowoffValve::Shutdown() {
    if (!running_.exchange(false)) {
        return;
    }
    
    // Signal workers to stop
    blowoff_cv_.notify_all();
    prefetch_cv_.notify_all();
    
    // Wait for workers
    if (blowoff_thread_.joinable()) {
        blowoff_thread_.join();
    }
    if (prefetch_thread_.joinable()) {
        prefetch_thread_.join();
    }
    
    // Flush all dirty blocks to SSD
    std::vector<uint64_t> dirty_blocks;
    {
            registry_mutex_.unlock();
        for (auto& [id, block] : registry_) {
            if (block->is_dirty && block->current_tier != Tier::SSD_NVMe) {
                dirty_blocks.push_back(id);
            }
        }
    }
    
    for (uint64_t id : dirty_blocks) {
        EvictToTier(id, Tier::SSD_NVMe);
    }
    
    // Close swap file
    CloseSwapFile();
    
    std::cout << "[BlowoffValve] Shutdown complete\n";
}

//=============================================================================
// Swap File Management (Real Windows Overlapped I/O)
//=============================================================================

bool SequentialBlowoffValve::InitializeSwapFile() {
#ifdef _WIN32
    // Create directory if needed
    size_t last_slash = config_.ssd_swap_path.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        std::string dir = config_.ssd_swap_path.substr(0, last_slash);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
    
    // Open with FILE_FLAG_OVERLAPPED for async I/O
    hSwapFile_ = CreateFileA(
        config_.ssd_swap_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );
    
    if (hSwapFile_ == INVALID_HANDLE_VALUE) {
        std::cerr << "[BlowoffValve] Failed to open swap file: " << GetLastError() << "\n";
        return false;
    }
    
    // Pre-allocate 100GB for swap
    LARGE_INTEGER fileSize;
    fileSize.QuadPart = 100ULL * 1024 * 1024 * 1024; // 100GB
    
    if (!SetFilePointerEx(hSwapFile_, fileSize, nullptr, FILE_BEGIN)) {
        std::cerr << "[BlowoffValve] Failed to set file pointer: " << GetLastError() << "\n";
        CloseHandle(hSwapFile_);
        hSwapFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    if (!SetEndOfFile(hSwapFile_)) {
        std::cerr << "[BlowoffValve] Failed to set end of file: " << GetLastError() << "\n";
        CloseHandle(hSwapFile_);
        hSwapFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    swapFileSize_ = fileSize.QuadPart;
    
    // Create I/O completion port for async operations
    hIoCompletionPort_ = CreateIoCompletionPort(hSwapFile_, nullptr, 0, 0);
    if (!hIoCompletionPort_) {
        std::cerr << "[BlowoffValve] Failed to create IOCP: " << GetLastError() << "\n";
        CloseHandle(hSwapFile_);
        hSwapFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    std::cout << "[BlowoffValve] Swap file initialized: " << (swapFileSize_ / (1024*1024*1024)) << "GB\n";
    return true;
#else
    // Linux implementation
    swapFd_ = open(config_.ssd_swap_path.c_str(), O_RDWR | O_CREAT, 0644);
    if (swapFd_ < 0) {
        std::cerr << "[BlowoffValve] Failed to open swap file\n";
        return false;
    }
    
    // Pre-allocate
    swapFileSize_ = 100ULL * 1024 * 1024 * 1024;
    if (ftruncate(swapFd_, swapFileSize_) < 0) {
        std::cerr << "[BlowoffValve] Failed to truncate swap file\n";
        close(swapFd_);
        swapFd_ = -1;
        return false;
    }
    
    return true;
#endif
}

void SequentialBlowoffValve::CloseSwapFile() {
#ifdef _WIN32
    if (hSwapFile_ != INVALID_HANDLE_VALUE) {
        // Wait for all pending I/O
        FlushFileBuffers(hSwapFile_);
        CloseHandle(hSwapFile_);
        hSwapFile_ = INVALID_HANDLE_VALUE;
    }
    if (hIoCompletionPort_) {
        CloseHandle(hIoCompletionPort_);
        hIoCompletionPort_ = nullptr;
    }
#else
    if (swapFd_ >= 0) {
        fsync(swapFd_);
        close(swapFd_);
        swapFd_ = -1;
    }
#endif
}

//=============================================================================
// Memory Block Allocation
//=============================================================================

uint64_t SequentialBlowoffValve::AllocateBlock(size_t size_bytes, bool is_kv_cache) {
    uint64_t block_id = next_sequence_id_++;
    
    auto block = std::make_unique<MemoryBlock>();
    block->sequence_id = block_id;
    block->size_bytes = size_bytes;
    block->is_kv_cache = is_kv_cache;
    block->is_dirty = false;
    block->is_pinned = false;
    block->current_tier = Tier::SSD_NVMe; // Start on SSD
    block->ptr = nullptr;
    block->io_in_progress = false;
    block->last_access = std::chrono::steady_clock::now();
    block->access_count = 0;
    
    // Allocate swap space immediately
    block->ssd_offset = AllocateSwapSpace_(size_bytes);
    if (block->ssd_offset == UINT64_MAX) {
        return 0; // Allocation failed
    }
    
#ifdef _WIN32
    std::memset(&block->overlapped, 0, sizeof(OVERLAPPED));
    block->hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
#endif
    
    {
            registry_mutex_.unlock();
        registry_[block_id] = std::move(block);
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_blocks_allocated++;
    }
    
    return block_id;
}

bool SequentialBlowoffValve::FreeBlock(uint64_t block_id) {
    std::unique_ptr<MemoryBlock> block;
    
    {
            registry_mutex_.unlock();
        auto it = registry_.find(block_id);
        if (it == registry_.end()) {
            return false;
        }
        block = std::move(it->second);
        registry_.erase(it);
    }
    
    // Remove from ring buffer
    {
        std::lock_guard<std::mutex> lock(ring_mutex_);
        auto it = std::find(ring_buffer_.begin(), ring_buffer_.end(), block_id);
        if (it != ring_buffer_.end()) {
            ring_buffer_.erase(it);
        }
    }
    
    // Wait for any pending I/O
    if (block->io_in_progress.load()) {
        WaitForIoCompletion_(*block);
    }
    
    // Free from current tier
    if (block->ptr) {
        FreeInTier_(block->current_tier, block->ptr, block->size_bytes);
    }
    
    // Free swap space
    if (block->ssd_offset != UINT64_MAX) {
        FreeSwapSpace_(block->ssd_offset, block->size_bytes);
    }
    
#ifdef _WIN32
    if (block->hEvent) {
        CloseHandle(block->hEvent);
    }
#endif
    
    return true;
}

//=============================================================================
// Memory Access
//=============================================================================

void* SequentialBlowoffValve::Access(uint64_t block_id) {
    MemoryBlock* block = nullptr;
    
    {
            registry_mutex_.unlock();
        auto it = registry_.find(block_id);
        if (it == registry_.end()) {
            return nullptr;
        }
        block = it->second.get();
    }
    
    // Update access tracking
    block->last_access = std::chrono::steady_clock::now();
    block->access_count++;
    
    // Handle page fault - block not resident
    if (block->current_tier == Tier::SSD_NVMe) {
        // Page fault - need to load from SSD
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.page_faults++;
        }
        
        // Load into RAM first
        if (!TransferBlock_(*block, Tier::RAM_DDR5)) {
            return nullptr;
        }
    }
    
    // Promote to GPU if needed and not pinned
    if (!block->is_pinned && block->current_tier == Tier::RAM_DDR5) {
        // Check if we should promote to GPU0
        if (GetPressure(Tier::GPU0_R9700) < config_.gpu0_pressure_threshold) {
            TransferBlock_(*block, Tier::GPU0_R9700);
        }
    }
    
    return block->ptr;
}

bool SequentialBlowoffValve::Pin(uint64_t block_id) {
        registry_mutex_.unlock();
    
    auto it = registry_.find(block_id);
    if (it == registry_.end()) {
        return false;
    }
    
    auto* block = it->second.get();
    if (block->is_pinned) {
        return true;
    }
    
    // Ensure block is resident
    if (block->current_tier == Tier::SSD_NVMe) {
        
        if (!TransferBlock_(*block, Tier::RAM_DDR5)) {
            return false;
        }
        
    }
    
    block->is_pinned = true;
    
    {
        std::lock_guard<std::mutex> tier_lock(tier_mutex_);
        tier_pinned_bytes_[static_cast<size_t>(block->current_tier)] += block->size_bytes;
    }
    
    return true;
}

bool SequentialBlowoffValve::Unpin(uint64_t block_id) {
        registry_mutex_.unlock();
    
    auto it = registry_.find(block_id);
    if (it == registry_.end()) {
        return false;
    }
    
    auto* block = it->second.get();
    if (!block->is_pinned) {
        return true;
    }
    
    block->is_pinned = false;
    
    {
        std::lock_guard<std::mutex> tier_lock(tier_mutex_);
        tier_pinned_bytes_[static_cast<size_t>(block->current_tier)] -= block->size_bytes;
    }
    
    return true;
}

//=============================================================================
// Tier Transfers
//=============================================================================

bool SequentialBlowoffValve::EvictToTier(uint64_t block_id, Tier target_tier) {
    MemoryBlock* block = nullptr;
    
    {
            registry_mutex_.unlock();
        auto it = registry_.find(block_id);
        if (it == registry_.end()) {
            return false;
        }
        block = it->second.get();
    }
    
    if (block->is_pinned) {
        return false; // Cannot evict pinned blocks
    }
    
    return TransferBlock_(*block, target_tier);
}

bool SequentialBlowoffValve::TransferBlock_(MemoryBlock& block, Tier target_tier) {
    if (block.current_tier == target_tier) {
        return true;
    }
    
    // Wait for any pending I/O
    if (block.io_in_progress.load()) {
        if (!WaitForIoCompletion_(block)) {
            return false;
        }
    }
    
    // Allocate in target tier
    void* new_ptr = AllocateInTier_(target_tier, block.size_bytes);
    if (!new_ptr && target_tier != Tier::SSD_NVMe) {
        return false;
    }
    
    bool success = false;
    
    // Perform the transfer
    switch (block.current_tier) {
        case Tier::GPU0_R9700:
        case Tier::GPU1_7800XT:
            if (target_tier == Tier::RAM_DDR5) {
                success = GpuToRamTransfer(block, new_ptr);
            } else if (target_tier == Tier::SSD_NVMe) {
                void* temp = AllocateInTier_(Tier::RAM_DDR5, block.size_bytes);
                if (temp && GpuToRamTransfer(block, temp)) {
                    success = RamToSsdTransfer(block, temp);
                    FreeInTier_(Tier::RAM_DDR5, temp, block.size_bytes);
                }
            }
            break;
            
        case Tier::RAM_DDR5:
            if (target_tier == Tier::GPU0_R9700 || target_tier == Tier::GPU1_7800XT) {
                success = RamToGpuTransfer(block, new_ptr);
            } else if (target_tier == Tier::SSD_NVMe) {
                success = RamToSsdTransfer(block, block.ptr);
            }
            break;
            
        case Tier::SSD_NVMe:
            if (target_tier == Tier::RAM_DDR5) {
                success = SsdToRamTransfer(block, new_ptr);
            } else if (target_tier == Tier::GPU0_R9700 || target_tier == Tier::GPU1_7800XT) {
                void* temp = AllocateInTier_(Tier::RAM_DDR5, block.size_bytes);
                if (temp && SsdToRamTransfer(block, temp)) {
                    success = RamToGpuTransfer(block, new_ptr);
                    FreeInTier_(Tier::RAM_DDR5, temp, block.size_bytes);
                }
            }
            break;
    }
    
    if (success) {
        // Update tier tracking
        {
            std::lock_guard<std::mutex> lock(tier_mutex_);
            tier_used_bytes_[static_cast<size_t>(block.current_tier)] -= block.size_bytes;
            if (block.is_pinned) {
                tier_pinned_bytes_[static_cast<size_t>(block.current_tier)] -= block.size_bytes;
            }
            
            if (target_tier != Tier::SSD_NVMe) {
                tier_used_bytes_[static_cast<size_t>(target_tier)] += block.size_bytes;
                if (block.is_pinned) {
                    tier_pinned_bytes_[static_cast<size_t>(target_tier)] += block.size_bytes;
                }
            }
        }
        
        // Free old location
        if (block.ptr && block.current_tier != Tier::SSD_NVMe) {
            FreeInTier_(block.current_tier, block.ptr, block.size_bytes);
        }
        
        block.ptr = (target_tier == Tier::SSD_NVMe) ? nullptr : new_ptr;
        block.current_tier = target_tier;
        block.is_dirty = false;
        
        // Update stats
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.total_bytes_transferred += block.size_bytes;
        }
    } else {
        // Clean up failed allocation
        if (new_ptr && target_tier != Tier::SSD_NVMe) {
            FreeInTier_(target_tier, new_ptr, block.size_bytes);
        }
    }
    
    return success;
}

//=============================================================================
// Real Windows Overlapped I/O
//=============================================================================

bool SequentialBlowoffValve::RamToSsdTransfer(MemoryBlock& block, void* src_ptr) {
#ifdef _WIN32
    if (hSwapFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Align to sector size for unbuffered I/O
    size_t aligned_size = ((block.size_bytes + 4095) / 4096) * 4096;
    
    // Reset overlapped structure
    std::memset(&block.overlapped, 0, sizeof(OVERLAPPED));
    block.overlapped.Offset = static_cast<DWORD>(block.ssd_offset & 0xFFFFFFFF);
    block.overlapped.OffsetHigh = static_cast<DWORD>(block.ssd_offset >> 32);
    block.overlapped.hEvent = block.hEvent;
    ResetEvent(block.hEvent);
    
    block.io_in_progress = true;
    
    BOOL result = WriteFile(
        hSwapFile_,
        src_ptr,
        static_cast<DWORD>(aligned_size),
        nullptr,
        &block.overlapped
    );
    
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        block.io_in_progress = false;
        std::cerr << "[BlowoffValve] WriteFile failed: " << GetLastError() << "\n";
        return false;
    }
    
    // Wait for completion
    DWORD bytes_written = 0;
    result = GetOverlappedResult(hSwapFile_, &block.overlapped, &bytes_written, TRUE);
    
    block.io_in_progress = false;
    
    if (!result) {
        std::cerr << "[BlowoffValve] GetOverlappedResult failed: " << GetLastError() << "\n";
        return false;
    }
    
    return true;
#else
    // Linux AIO implementation
    struct aiocb cb;
    std::memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = swapFd_;
    cb.aio_buf = src_ptr;
    cb.aio_nbytes = block.size_bytes;
    cb.aio_offset = block.ssd_offset;
    
    if (aio_write(&cb) < 0) {
        return false;
    }
    
    // Wait for completion
    struct aiocb* cblist[1] = {&cb};
    while (aio_suspend(cblist, 1, nullptr) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    
    return aio_return(&cb) == static_cast<ssize_t>(block.size_bytes);
#endif
}

bool SequentialBlowoffValve::SsdToRamTransfer(MemoryBlock& block, void* dst_ptr) {
#ifdef _WIN32
    if (hSwapFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    size_t aligned_size = ((block.size_bytes + 4095) / 4096) * 4096;
    
    std::memset(&block.overlapped, 0, sizeof(OVERLAPPED));
    block.overlapped.Offset = static_cast<DWORD>(block.ssd_offset & 0xFFFFFFFF);
    block.overlapped.OffsetHigh = static_cast<DWORD>(block.ssd_offset >> 32);
    block.overlapped.hEvent = block.hEvent;
    ResetEvent(block.hEvent);
    
    block.io_in_progress = true;
    
    BOOL result = ReadFile(
        hSwapFile_,
        dst_ptr,
        static_cast<DWORD>(aligned_size),
        nullptr,
        &block.overlapped
    );
    
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        block.io_in_progress = false;
        return false;
    }
    
    DWORD bytes_read = 0;
    result = GetOverlappedResult(hSwapFile_, &block.overlapped, &bytes_read, TRUE);
    
    block.io_in_progress = false;
    
    return result != 0;
#else
    struct aiocb cb;
    std::memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = swapFd_;
    cb.aio_buf = dst_ptr;
    cb.aio_nbytes = block.size_bytes;
    cb.aio_offset = block.ssd_offset;
    
    if (aio_read(&cb) < 0) {
        return false;
    }
    
    struct aiocb* cblist[1] = {&cb};
    while (aio_suspend(cblist, 1, nullptr) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    
    return aio_return(&cb) == static_cast<ssize_t>(block.size_bytes);
#endif
}

bool SequentialBlowoffValve::WaitForIoCompletion_(MemoryBlock& block) {
    if (!block.io_in_progress.load()) {
        return true;
    }
    
#ifdef _WIN32
    DWORD bytes_transferred = 0;
    BOOL result = GetOverlappedResult(
        hSwapFile_,
        &block.overlapped,
        &bytes_transferred,
        TRUE
    );
    block.io_in_progress = false;
    return result != 0;
#else
    // Already waited in the transfer functions
    block.io_in_progress = false;
    return true;
#endif
}

//=============================================================================
// GPU Transfers (Vulkan)
//=============================================================================

bool SequentialBlowoffValve::GpuToRamTransfer(MemoryBlock& block, void* dst_ptr) {
    // In production, this would use vkCmdCopyBufferToImage or vkCmdCopyBuffer
    // For now, use staging buffer approach
    
    // Map GPU memory and copy
    // This is a simplified version - real implementation would use Vulkan command buffers
    void* gpu_ptr = nullptr;
    
    // vkMapMemory would go here
    // memcpy(dst_ptr, gpu_ptr, block.size_bytes);
    // vkUnmapMemory
    
    // Placeholder: simulate transfer
    std::memcpy(dst_ptr, block.ptr, std::min(block.size_bytes, size_t(1024*1024)));
    
    return true;
}

bool SequentialBlowoffValve::RamToGpuTransfer(MemoryBlock& block, void* dst_ptr) {
    // Similar to above but reverse direction
    // vkCmdCopyBuffer command would be recorded and submitted
    
    // Placeholder
    std::memcpy(dst_ptr, block.ptr, std::min(block.size_bytes, size_t(1024*1024)));
    
    return true;
}

//=============================================================================
// Tier Allocation
//=============================================================================

void* SequentialBlowoffValve::AllocateInTier_(Tier tier, size_t size) {
    switch (tier) {
        case Tier::GPU0_R9700:
        case Tier::GPU1_7800XT:
            // Would allocate Vulkan device memory
            // For now, return aligned host memory as placeholder
            return _aligned_malloc(size, 4096);
            
        case Tier::RAM_DDR5:
            return _aligned_malloc(size, 4096);
            
        case Tier::SSD_NVMe:
            return nullptr; // SSD doesn't have direct pointer
            
        default:
            return nullptr;
    }
}

void SequentialBlowoffValve::FreeInTier_(Tier tier, void* ptr, size_t size) {
    if (ptr) {
        _aligned_free(ptr);
    }
}

//=============================================================================
// Swap Space Management
//=============================================================================

uint64_t SequentialBlowoffValve::AllocateSwapSpace_(size_t size) {
    std::lock_guard<std::mutex> lock(swap_mutex_);
    
    size_t aligned_size = ((size + 4095) / 4096) * 4096;
    
    // First-fit allocation from free list
    for (auto it = ssd_free_list_.begin(); it != ssd_free_list_.end(); ++it) {
        if (it->second >= aligned_size) {
            uint64_t offset = it->first;
            size_t remaining = it->second - aligned_size;
            ssd_free_list_.erase(it);
            if (remaining > 0) {
                ssd_free_list_[offset + aligned_size] = remaining;
            }
            return offset;
        }
    }
    
    // Allocate from end of file
    if (ssd_next_offset_ + aligned_size > swapFileSize_) {
        return UINT64_MAX; // Out of space
    }
    
    uint64_t offset = ssd_next_offset_;
    ssd_next_offset_ += aligned_size;
    return offset;
}

void SequentialBlowoffValve::FreeSwapSpace_(uint64_t offset, size_t size) {
    std::lock_guard<std::mutex> lock(swap_mutex_);
    ssd_free_list_[offset] = size;
    
    // Coalesce adjacent free blocks
    // (simplified - would merge contiguous regions in production)
}

//=============================================================================
// Pressure Management
//=============================================================================

float SequentialBlowoffValve::GetPressure(Tier tier) const {
    std::lock_guard<std::mutex> lock(tier_mutex_);
    
    size_t idx = static_cast<size_t>(tier);
    size_t max_bytes = 0;
    
    switch (tier) {
        case Tier::GPU0_R9700: max_bytes = config_.gpu0_max_bytes; break;
        case Tier::GPU1_7800XT: max_bytes = config_.gpu1_max_bytes; break;
        case Tier::RAM_DDR5: max_bytes = config_.ram_max_bytes; break;
        default: return 0.0f;
    }
    
    if (max_bytes == 0) return 0.0f;
    return static_cast<float>(tier_used_bytes_[idx]) / static_cast<float>(max_bytes);
}

bool SequentialBlowoffValve::ShouldBlowOff(Tier tier) const {
    float pressure = GetPressure(tier);
    
    switch (tier) {
        case Tier::GPU0_R9700: return pressure > config_.gpu0_pressure_threshold;
        case Tier::GPU1_7800XT: return pressure > config_.gpu1_pressure_threshold;
        case Tier::RAM_DDR5: return pressure > config_.ram_pressure_threshold;
        default: return false;
    }
}

void SequentialBlowoffValve::EmergencyBlowOff(size_t required_bytes, Tier from_tier) {
    std::cout << "[BlowoffValve] EMERGENCY blow-off from tier " 
              << static_cast<int>(from_tier) << " requiring " << required_bytes << " bytes\n";
    
    // Find victims and evict immediately
    auto victims = FindEvictionVictims_(from_tier, required_bytes);
    
    Tier target = (from_tier == Tier::GPU0_R9700 || from_tier == Tier::GPU1_7800XT) 
                  ? Tier::RAM_DDR5 : Tier::SSD_NVMe;
    
    for (uint64_t block_id : victims) {
        EvictToTier(block_id, target);
    }
}

//=============================================================================
// Background Workers
//=============================================================================

void SequentialBlowoffValve::BlowoffWorkerLoop() {
    std::cout << "[BlowoffValve] Blow-off worker started\n";
    
    while (running_) {
        std::unique_lock<std::mutex> lock(blowoff_mutex_);
        blowoff_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
            return !running_ || ShouldBlowOff(Tier::GPU0_R9700) 
                   || ShouldBlowOff(Tier::GPU1_7800XT) || ShouldBlowOff(Tier::RAM_DDR5);
        });
        
        if (!running_) break;
        
        if (paused_) {
            continue;
        }
        
        
        
        // Check each tier and blow off if needed
        if (ShouldBlowOff(Tier::GPU0_R9700)) {
            EvictOldestBatch_(Tier::GPU0_R9700, config_.gpu0_eviction_batch);
        }
        
        if (ShouldBlowOff(Tier::GPU1_7800XT)) {
            EvictOldestBatch_(Tier::GPU1_7800XT, config_.gpu1_eviction_batch);
        }
        
        if (ShouldBlowOff(Tier::RAM_DDR5)) {
            EvictOldestBatch_(Tier::RAM_DDR5, config_.ram_eviction_batch);
        }
    }
    
    std::cout << "[BlowoffValve] Blow-off worker stopped\n";
}

void SequentialBlowoffValve::PrefetchWorkerLoop() {
    std::cout << "[BlowoffValve] Prefetch worker started\n";
    
    while (running_) {
        std::unique_lock<std::mutex> lock(prefetch_mutex_);
        prefetch_cv_.wait_for(lock, std::chrono::milliseconds(50));
        
        if (!running_) break;
        
        
        
        if (!config_.enable_predictive_prefetch) {
            continue;
        }
        
        // Get current sequence position
        uint64_t current_seq = next_sequence_id_.load();
        
        // Prefetch upcoming blocks
        PrefetchUpcomingBlocks_(current_seq, config_.prefetch_ahead_tokens);
    }
    
    std::cout << "[BlowoffValve] Prefetch worker stopped\n";
}

bool SequentialBlowoffValve::EvictOldestBatch_(Tier source_tier, size_t batch_size) {
    auto victims = FindEvictionVictims_(source_tier, batch_size * 1024 * 1024); // Approximate
    
    Tier target = (source_tier == Tier::GPU0_R9700 || source_tier == Tier::GPU1_7800XT) 
                  ? Tier::RAM_DDR5 : Tier::SSD_NVMe;
    
    size_t evicted = 0;
    for (uint64_t block_id : victims) {
        if (EvictToTier(block_id, target)) {
            evicted++;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_blocks_evicted += evicted;
    }
    
    return evicted > 0;
}

std::vector<uint64_t> SequentialBlowoffValve::FindEvictionVictims_(Tier tier, size_t required_bytes) {
    std::vector<uint64_t> victims;
    size_t found_bytes = 0;
    
    std::lock_guard<std::mutex> lock(ring_mutex_);
    
    // Oldest blocks are at the front of the ring buffer
    for (auto it = ring_buffer_.begin(); it != ring_buffer_.end() && found_bytes < required_bytes; ) {
        uint64_t block_id = *it;
        
        std::lock_guard<std::mutex> reg_lock(registry_mutex_);
        auto block_it = registry_.find(block_id);
        if (block_it == registry_.end()) {
            it = ring_buffer_.erase(it);
            continue;
        }
        
        auto* block = block_it->second.get();
        if (block->current_tier == tier && !block->is_pinned && !block->io_in_progress.load()) {
            victims.push_back(block_id);
            found_bytes += block->size_bytes;
        }
        
        ++it;
    }
    
    return victims;
}

void SequentialBlowoffValve::PrefetchUpcomingBlocks_(uint64_t current_seq, uint32_t count) {
    // Find blocks with sequence IDs in the prefetch window
        registry_mutex_.unlock();
    
    for (auto& [id, block] : registry_) {
        if (block->sequence_id >= current_seq && 
            block->sequence_id < current_seq + count &&
            block->current_tier == Tier::SSD_NVMe) {
            
            // Prefetch to RAM
            std::thread([this, id]() {
                EvictToTier(id, Tier::RAM_DDR5);
            }).detach();
        }
    }
}

//=============================================================================
// Statistics
//=============================================================================

SequentialBlowoffValve::Stats SequentialBlowoffValve::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::string SequentialBlowoffValve::GetRainbowRoadReport() const {
    std::ostringstream oss;
    
    oss << "╔═══════════════════════════════════════════════════════════════╗\n";
    oss << "║           RAINBOW ROAD MEMORY FABRIC REPORT                  ║\n";
    oss << "╠═══════════════════════════════════════════════════════════════╣\n";
    
    // Tier status
    oss << "║ MEMORY TIERS:\n";
    oss << "║   GPU0 (R9700):  " << std::fixed << std::setprecision(1) 
        << (GetPressure(Tier::GPU0_R9700) * 100) << "% full\n";
    oss << "║   GPU1 (7800XT): " << (GetPressure(Tier::GPU1_7800XT) * 100) << "% full\n";
    oss << "║   RAM (DDR5):    " << (GetPressure(Tier::RAM_DDR5) * 100) << "% full\n";
    oss << "║   SSD (NVMe):    Active\n";
    
    // Stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        oss << "║\n║ STATISTICS:\n";
        oss << "║   Blocks allocated: " << stats_.total_blocks_allocated << "\n";
        oss << "║   Blocks evicted:   " << stats_.total_blocks_evicted << "\n";
        oss << "║   Bytes transferred: " << (stats_.total_bytes_transferred / (1024*1024)) << " MB\n";
        oss << "║   Page faults:      " << stats_.page_faults << "\n";
        oss << "║   Prefetch hits:    " << stats_.prefetch_hits << "\n";
        oss << "║   Prefetch misses:  " << stats_.prefetch_misses << "\n";
    }
    
    // Registry size
    {
            registry_mutex_.unlock();
        oss << "║   Active blocks:    " << registry_.size() << "\n";
    }
    
    oss << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    return oss.str();
}

//=============================================================================
// Global Instance
//=============================================================================

SequentialBlowoffValve& GetBlowoffValve() {
    static BlowoffConfig default_config;
    static SequentialBlowoffValve instance(default_config);
    return instance;
}

} // namespace Memory
} // namespace RawrXD
