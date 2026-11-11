// =============================================================================
// RawRamXD_Real.cpp - Real Memory Implementation
// =============================================================================
// Uses actual CUDA VRAM, VirtualAlloc RAM, and memory-mapped NVMe
// =============================================================================

#include "RawRamXD_Real.hpp"
#include <chrono>
#include <string>
#include <iostream>
#include <fstream>

namespace rawramxd {

// =============================================================================
// Real RawRamXD Implementation
// =============================================================================

RawRamXDFabric::RawRamXDFabric() = default;

RawRamXDFabric::~RawRamXDFabric() {
    shutdown();
}

bool RawRamXDFabric::initialize(size_t vramSize, size_t ramSize, size_t nvmeSize) {
    vramCapacity_ = vramSize;
    ramCapacity_ = ramSize;
    nvmeCapacity_ = nvmeSize;
    
    std::cout << "[RawRamXD] Initializing real memory fabric...\n";
    std::cout << "  VRAM: " << (vramSize / (1024ULL*1024*1024)) << " GB\n";
    std::cout << "  RAM:  " << (ramSize / (1024ULL*1024*1024)) << " GB\n";
    std::cout << "  NVMe: " << (nvmeSize / (1024ULL*1024*1024)) << " GB\n";
    
    // Initialize CUDA
    #ifdef HAS_CUDA
    CUresult result = cuInit(0);
    if (result == CUDA_SUCCESS) {
        CUdevice device;
        cuDeviceGet(&device, 0);
        cuCtxCreate(&cudaContext_, 0, device);
        std::cout << "  [OK] CUDA initialized\n";
    } else {
        std::cout << "  [!] CUDA not available, VRAM tier disabled\n";
        vramCapacity_ = 0;
    }
    #else
    std::cout << "  [!] CUDA not compiled in, VRAM tier disabled\n";
    vramCapacity_ = 0;
    #endif
    
    // Initialize NVMe backing file
    #ifdef _WIN32
    nvmeBackingFile_ = "rawramxd_nvme_backing.bin";
    
    // Create sparse file
    nvmeFileHandle_ = CreateFileA(
        nvmeBackingFile_.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr
    );
    
    if (nvmeFileHandle_ != INVALID_HANDLE_VALUE) {
        // Set file size
        LARGE_INTEGER size;
        size.QuadPart = nvmeSize;
        SetFilePointerEx(nvmeFileHandle_, size, nullptr, FILE_BEGIN);
        SetEndOfFile(nvmeFileHandle_);
        
        // Create file mapping
        nvmeMapping_ = CreateFileMapping(
            nvmeFileHandle_,
            nullptr,
            PAGE_READWRITE,
            size.HighPart,
            size.LowPart,
            nullptr
        );
        
        if (nvmeMapping_) {
            nvmeBasePtr_ = MapViewOfFile(nvmeMapping_, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            std::cout << "  [OK] NVMe backing: " << nvmeBackingFile_ << "\n";
        }
    }
    #else
    nvmeBackingFile_ = "/tmp/rawramxd_nvme_backing.bin";
    nvmeFd_ = open(nvmeBackingFile_.c_str(), O_RDWR | O_CREAT, 0666);
    if (nvmeFd_ >= 0) {
        ftruncate(nvmeFd_, nvmeSize);
        nvmeBasePtr_ = mmap(nullptr, nvmeSize, PROT_READ | PROT_WRITE, MAP_SHARED, nvmeFd_, 0);
        std::cout << "  [OK] NVMe backing: " << nvmeBackingFile_ << "\n";
    }
    #endif
    
    // Start threads
    running_ = true;
    schedulerThread_ = std::thread(&RawRamXDFabric::schedulerLoop, this);
    metricsThread_ = std::thread(&RawRamXDFabric::metricsLoop, this);
    
    std::cout << "[RawRamXD] Real fabric initialized\n";
    return true;
}

void RawRamXDFabric::shutdown() {
    running_ = false;
    queueCV_.notify_all();
    
    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }
    if (metricsThread_.joinable()) {
        metricsThread_.join();
    }
    
    // Cleanup tensors
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (auto& [id, handle] : tensors_) {
            free(handle.get());
        }
        tensors_.clear();
    }
    
    // Cleanup NVMe
    #ifdef _WIN32
    if (nvmeBasePtr_) UnmapViewOfFile(nvmeBasePtr_);
    if (nvmeMapping_) CloseHandle(nvmeMapping_);
    if (nvmeFileHandle_ != INVALID_HANDLE_VALUE) CloseHandle(nvmeFileHandle_);
    DeleteFileA(nvmeBackingFile_.c_str());
    #else
    if (nvmeBasePtr_) munmap(nvmeBasePtr_, nvmeCapacity_);
    if (nvmeFd_ >= 0) close(nvmeFd_);
    unlink(nvmeBackingFile_.c_str());
    #endif
    
    // Cleanup CUDA
    #ifdef HAS_CUDA
    if (cudaContext_) {
        cuCtxDestroy(cudaContext_);
    }
    #endif
}

// =============================================================================
// Real Physical Allocation
// =============================================================================

PhysicalBlock* RawRamXDFabric::allocateVRAM(size_t size) {
    #ifdef HAS_CUDA
    if (!cudaContext_) return nullptr;
    
    PhysicalBlock* block = new PhysicalBlock();
    block->tier = Tier::VRAM;
    block->size = size;
    block->timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    block->mapped = false;
    
    // Allocate CUDA device memory
    CUresult result = cuMemAlloc((CUdeviceptr*)&block->devicePtr, size);
    if (result != CUDA_SUCCESS) {
        delete block;
        return nullptr;
    }
    
    // Also allocate pinned host memory for transfers
    cuMemAllocHost(&block->hostPtr, size);
    
    vramUsed_ += size;
    return block;
    #else
    return nullptr;
    #endif
}

PhysicalBlock* RawRamXDFabric::allocateRAM(size_t size) {
    PhysicalBlock* block = new PhysicalBlock();
    block->tier = Tier::RAM;
    block->size = size;
    block->timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    block->mapped = true;
    
    #ifdef _WIN32
    block->hostPtr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    #else
    block->hostPtr = std::aligned_alloc(4096, size);
    std::memset(block->hostPtr, 0, size);
    #endif
    
    if (!block->hostPtr) {
        delete block;
        return nullptr;
    }
    
    block->devicePtr = nullptr;
    ramUsed_ += size;
    return block;
}

PhysicalBlock* RawRamXDFabric::allocateNVMe(size_t size) {
    std::lock_guard<std::mutex> lock(nvmeMutex_);
    
    if (nvmeFileOffset_ + size > nvmeCapacity_) {
        return nullptr; // Out of NVMe space
    }
    
    PhysicalBlock* block = new PhysicalBlock();
    block->tier = Tier::NVMe;
    block->size = size;
    block->timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    block->mapped = true;
    block->hostPtr = (char*)nvmeBasePtr_ + nvmeFileOffset_;
    block->devicePtr = nullptr;
    
    #ifdef _WIN32
    block->nvmeHandle = nvmeFileHandle_;
    #else
    block->nvmeFd = nvmeFd_;
    #endif
    
    nvmeFileOffset_ += size;
    nvmeUsed_ += size;
    return block;
}

void RawRamXDFabric::freeBlock(PhysicalBlock* block) {
    if (!block) return;
    
    switch (block->tier) {
        case Tier::VRAM:
            #ifdef HAS_CUDA
            if (block->devicePtr) cuMemFree((CUdeviceptr)block->devicePtr);
            if (block->hostPtr) cuMemFreeHost(block->hostPtr);
            vramUsed_ -= block->size;
            #endif
            break;
            
        case Tier::RAM:
            if (block->hostPtr) {
                #ifdef _WIN32
                VirtualFree(block->hostPtr, 0, MEM_RELEASE);
                #else
                std::free(block->hostPtr);
                #endif
            }
            ramUsed_ -= block->size;
            break;
            
        case Tier::NVMe:
            // NVMe is file-backed, just mark as free
            // In production, would maintain free list
            nvmeUsed_ -= block->size;
            break;
            
        default:
            break;
    }
    
    delete block;
}

// =============================================================================
// Tensor Allocation
// =============================================================================

TensorHandle* RawRamXDFabric::allocate(size_t size, const char* name, Tier preferred) {
    auto handle = std::make_unique<TensorHandle>();
    handle->id = nextId_++;
    handle->size = size;
    handle->currentTier = Tier::NONE;
    handle->preferredTier = preferred;
    handle->vramBlock = nullptr;
    handle->ramBlock = nullptr;
    handle->nvmeBlock = nullptr;
    handle->pinned = false;
    handle->migrating = false;
    handle->name = name ? name : "unnamed";
    handle->priority = 128;
    
    // Allocate in preferred tier
    switch (preferred) {
        case Tier::VRAM:
            handle->vramBlock = allocateVRAM(size);
            if (handle->vramBlock) handle->currentTier = Tier::VRAM;
            break;
        case Tier::RAM:
            handle->ramBlock = allocateRAM(size);
            if (handle->ramBlock) handle->currentTier = Tier::RAM;
            break;
        case Tier::NVMe:
            handle->nvmeBlock = allocateNVMe(size);
            if (handle->nvmeBlock) handle->currentTier = Tier::NVMe;
            break;
        default:
            break;
    }
    
    // If preferred tier failed, try fallback
    if (handle->currentTier == Tier::NONE) {
        handle->nvmeBlock = allocateNVMe(size);
        if (handle->nvmeBlock) handle->currentTier = Tier::NVMe;
    }
    
    if (handle->currentTier == Tier::NONE) {
        return nullptr; // Total allocation failure
    }
    
    TensorHandle* ptr = handle.get();
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        tensors_[handle->id] = std::move(handle);
    }
    
    return ptr;
}

void RawRamXDFabric::free(TensorHandle* handle) {
    if (!handle) return;
    
    // Free all physical blocks
    freeBlock(handle->vramBlock);
    freeBlock(handle->ramBlock);
    freeBlock(handle->nvmeBlock);
    
    // Remove from registry
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        tensors_.erase(handle->id);
    }
}

// =============================================================================
// Residency API
// =============================================================================

bool RawRamXDFabric::ensureInVRAM(TensorHandle* handle) {
    if (!handle) return false;
    
    std::lock_guard<std::mutex> lock(handle->stateMutex);
    
    if (handle->currentTier == Tier::VRAM && handle->vramBlock) {
        touch(handle);
        return true;
    }
    
    // Need to migrate
    return migrateReal(handle, Tier::VRAM);
}

bool RawRamXDFabric::ensureInRAM(TensorHandle* handle) {
    if (!handle) return false;
    
    std::lock_guard<std::mutex> lock(handle->stateMutex);
    
    if (handle->currentTier == Tier::RAM && handle->ramBlock) {
        touch(handle);
        return true;
    }
    
    return migrateReal(handle, Tier::RAM);
}

bool RawRamXDFabric::ensureInNVMe(TensorHandle* handle) {
    if (!handle) return false;
    
    std::lock_guard<std::mutex> lock(handle->stateMutex);
    
    if (handle->currentTier == Tier::NVMe && handle->nvmeBlock) {
        touch(handle);
        return true;
    }
    
    return migrateReal(handle, Tier::NVMe);
}

void RawRamXDFabric::touch(TensorHandle* handle) {
    if (!handle) return;
    
    handle->accessCount++;
    handle->lastAccessTime = std::chrono::steady_clock::now().time_since_epoch().count();
}

// =============================================================================
// Real Migration
// =============================================================================

bool RawRamXDFabric::migrateReal(TensorHandle* handle, Tier target) {
    if (!handle || handle->migrating) return false;
    if (handle->currentTier == target) return true;
    
    auto start = std::chrono::steady_clock::now();
    handle->migrating = true;
    
    bool success = false;
    
    // Ensure target block exists
    switch (target) {
        case Tier::VRAM:
            if (!handle->vramBlock) {
                handle->vramBlock = allocateVRAM(handle->size);
            }
            break;
        case Tier::RAM:
            if (!handle->ramBlock) {
                handle->ramBlock = allocateRAM(handle->size);
            }
            break;
        case Tier::NVMe:
            if (!handle->nvmeBlock) {
                handle->nvmeBlock = allocateNVMe(handle->size);
            }
            break;
        default:
            break;
    }
    
    // Perform copy based on source and target
    switch (handle->currentTier) {
        case Tier::NVMe:
            if (target == Tier::RAM && handle->nvmeBlock && handle->ramBlock) {
                success = copyNVMeToRAM(handle->nvmeBlock, handle->ramBlock, handle->size);
            }
            break;
        case Tier::RAM:
            if (target == Tier::VRAM && handle->ramBlock && handle->vramBlock) {
                success = copyRAMtoVRAM(handle->ramBlock, handle->vramBlock, handle->size);
            } else if (target == Tier::NVMe && handle->ramBlock && handle->nvmeBlock) {
                success = copyRAMtoNVMe(handle->ramBlock, handle->nvmeBlock, handle->size);
            }
            break;
        case Tier::VRAM:
            if (target == Tier::RAM && handle->vramBlock && handle->ramBlock) {
                success = copyVRAMtoRAM(handle->vramBlock, handle->ramBlock, handle->size);
            }
            break;
        default:
            break;
    }
    
    if (success) {
        handle->currentTier = target;
        handle->bytesTransferred += handle->size;
    }
    
    handle->migrating = false;
    handle->migrationCV.notify_all();
    
    // Record metrics
    auto end = std::chrono::steady_clock::now();
    double durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    MigrationMetrics metrics;
    metrics.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        end.time_since_epoch()).count();
    metrics.tensorId = handle->id;
    metrics.fromTier = handle->currentTier;
    metrics.toTier = target;
    metrics.bytes = handle->size;
    metrics.durationMs = durationMs;
    metrics.success = success;
    
    {
        std::lock_guard<std::mutex> lock(metricsMutex_);
        migrationHistory_.push_back(metrics);
    }
    
    return success;
}

bool RawRamXDFabric::copyVRAMtoRAM(PhysicalBlock* src, PhysicalBlock* dst, size_t size) {
    #ifdef HAS_CUDA
    if (!src || !dst || !src->devicePtr || !dst->hostPtr) return false;
    
    // cuMemcpyDtoH: Device to Host
    CUresult result = cuMemcpyDtoH(dst->hostPtr, (CUdeviceptr)src->devicePtr, size);
    return result == CUDA_SUCCESS;
    #else
    return false;
    #endif
}

bool RawRamXDFabric::copyRAMtoVRAM(PhysicalBlock* src, PhysicalBlock* dst, size_t size) {
    #ifdef HAS_CUDA
    if (!src || !dst || !src->hostPtr || !dst->devicePtr) return false;
    
    // cuMemcpyHtoD: Host to Device
    CUresult result = cuMemcpyHtoD((CUdeviceptr)dst->devicePtr, src->hostPtr, size);
    return result == CUDA_SUCCESS;
    #else
    return false;
    #endif
}

bool RawRamXDFabric::copyRAMtoNVMe(PhysicalBlock* src, PhysicalBlock* dst, size_t size) {
    if (!src || !dst || !src->hostPtr || !dst->hostPtr) return false;
    
    // Simple memcpy for NVMe (file-backed memory)
    std::memcpy(dst->hostPtr, src->hostPtr, size);
    
    #ifdef _WIN32
    FlushViewOfFile(dst->hostPtr, size);
    #else
    msync(dst->hostPtr, size, MS_SYNC);
    #endif
    
    return true;
}

bool RawRamXDFabric::copyNVMeToRAM(PhysicalBlock* src, PhysicalBlock* dst, size_t size) {
    if (!src || !dst || !src->hostPtr || !dst->hostPtr) return false;
    
    std::memcpy(dst->hostPtr, src->hostPtr, size);
    return true;
}

// =============================================================================
// Scheduler & Metrics
// =============================================================================

void RawRamXDFabric::schedulerLoop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        queueCV_.wait_for(lock, std::chrono::milliseconds(10), 
            [this] { return !migrationQueue_.empty() || !running_; });
        
        while (!migrationQueue_.empty()) {
            auto task = migrationQueue_.top();
            migrationQueue_.pop();
            lock.unlock();
            
            migrateReal(task.handle, task.target);
            
            lock.lock();
        }
    }
}

void RawRamXDFabric::metricsLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        auto now = std::chrono::steady_clock::now();
        
        ResidencyMetrics metrics;
        metrics.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        metrics.vramUsed = vramUsed_.load();
        metrics.ramUsed = ramUsed_.load();
        metrics.nvmeUsed = nvmeUsed_.load();
        metrics.vramPressure = getVRAMPressure();
        
        {
            std::lock_guard<std::mutex> lock(tensorsMutex_);
            metrics.activeTensors = static_cast<uint32_t>(tensors_.size());
        }
        
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            metrics.migrationsInFlight = static_cast<uint32_t>(migrationQueue_.size());
        }
        
        // Calculate average migration latency
        {
            std::lock_guard<std::mutex> lock(metricsMutex_);
            if (!migrationHistory_.empty()) {
                double total = 0;
                size_t count = std::min(migrationHistory_.size(), size_t{100});
                for (size_t i = migrationHistory_.size() - count; i < migrationHistory_.size(); i++) {
                    total += migrationHistory_[i].durationMs;
                }
                metrics.avgMigrationLatency = total / count;
            }
            currentMetrics_ = metrics;
        }
    }
}

float RawRamXDFabric::getVRAMPressure() const {
    if (vramCapacity_ == 0) return 0.0f;
    return static_cast<float>(vramUsed_.load()) / static_cast<float>(vramCapacity_);
}

ResidencyMetrics RawRamXDFabric::getMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return currentMetrics_;
}

std::vector<MigrationMetrics> RawRamXDFabric::getMigrationHistory() {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return migrationHistory_;
}

void RawRamXDFabric::dumpState() {
    std::cout << "\n=== RawRamXD Real State ===\n";
    std::cout << "VRAM: " << (vramUsed_.load() / (1024*1024)) << " MB / " 
              << (vramCapacity_ / (1024*1024)) << " MB ("
              << (int)(getVRAMPressure() * 100) << "%)\n";
    std::cout << "RAM:  " << (ramUsed_.load() / (1024*1024)) << " MB / "
              << (ramCapacity_ / (1024*1024)) << " MB\n";
    std::cout << "NVMe: " << (nvmeUsed_.load() / (1024*1024)) << " MB / "
              << (nvmeCapacity_ / (1024*1024)) << " MB\n";
    
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    std::cout << "Active tensors: " << tensors_.size() << "\n";
}

// =============================================================================
// Global Instance
// =============================================================================

RawRamXDFabric& getFabric() {
    static RawRamXDFabric fabric;
    return fabric;
}

} // namespace rawramxd