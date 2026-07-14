// =============================================================================
// RawRamXD_Fabric.cpp - Heterogeneous Compute Fabric Implementation
// =============================================================================
// Implements GPU-style compute targets for VRAM, RAM, and storage tiers
// =============================================================================

#include "RawRamXD_Fabric.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <cmath>

namespace RawRamXD {
namespace Fabric {

// =============================================================================
// STRING CONVERSIONS
// =============================================================================

const char* ComputeTargetTypeToString(ComputeTargetType type) {
    switch (type) {
        case ComputeTargetType::GPU_VRAM: return "GPU_VRAM";
        case ComputeTargetType::CPU_RAM: return "CPU_RAM";
        case ComputeTargetType::NVME_STORE: return "NVME_STORE";
        case ComputeTargetType::SATA_SSD: return "SATA_SSD";
        case ComputeTargetType::HDD_STORE: return "HDD_STORE";
        case ComputeTargetType::CXL_MEMORY: return "CXL_MEMORY";
        case ComputeTargetType::REMOTE: return "REMOTE";
        default: return "UNKNOWN";
    }
}

const char* ResidencyStateToString(ResidencyState state) {
    switch (state) {
        case ResidencyState::FREE: return "FREE";
        case ResidencyState::ALLOCATED: return "ALLOCATED";
        case ResidencyState::RESIDENT: return "RESIDENT";
        case ResidencyState::MIGRATING: return "MIGRATING";
        case ResidencyState::PREFETCHED: return "PREFETCHED";
        case ResidencyState::EVICTING: return "EVICTING";
        case ResidencyState::PINNED: return "PINNED";
        case ResidencyState::COMPRESSED: return "COMPRESSED";
        default: return "UNKNOWN";
    }
}

const char* OperationTypeToString(OperationType op) {
    switch (op) {
        case OperationType::INFERENCE: return "INFERENCE";
        case OperationType::ATTENTION: return "ATTENTION";
        case OperationType::FEEDFORWARD: return "FEEDFORWARD";
        case OperationType::EMBEDDING: return "EMBEDDING";
        case OperationType::SAMPLING: return "SAMPLING";
        case OperationType::KV_CACHE: return "KV_CACHE";
        case OperationType::WEIGHT_LOAD: return "WEIGHT_LOAD";
        case OperationType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// PERFORMANCE ESTIMATES
// =============================================================================

uint64_t GetDeviceBandwidthEstimate(ComputeTargetType type) {
    switch (type) {
        case ComputeTargetType::GPU_VRAM:
            return 800ULL * 1024 * 1024 * 1024;  // 800 GB/s (HBM/GDDR6)
        case ComputeTargetType::CPU_RAM:
            return 50ULL * 1024 * 1024 * 1024;   // 50 GB/s (DDR5)
        case ComputeTargetType::NVME_STORE:
            return 7ULL * 1024 * 1024 * 1024;    // 7 GB/s (PCIe 4.0 NVMe)
        case ComputeTargetType::SATA_SSD:
            return 550ULL * 1024 * 1024;         // 550 MB/s
        case ComputeTargetType::HDD_STORE:
            return 200ULL * 1024 * 1024;         // 200 MB/s
        case ComputeTargetType::CXL_MEMORY:
            return 25ULL * 1024 * 1024 * 1024;  // 25 GB/s (CXL 2.0)
        default:
            return 100ULL * 1024 * 1024;         // 100 MB/s fallback
    }
}

uint64_t GetDeviceLatencyEstimate(ComputeTargetType type) {
    switch (type) {
        case ComputeTargetType::GPU_VRAM:
            return 100;                            // 100 ns
        case ComputeTargetType::CPU_RAM:
            return 80;                             // 80 ns
        case ComputeTargetType::NVME_STORE:
            return 10000;                          // 10 us
        case ComputeTargetType::SATA_SSD:
            return 100000;                         // 100 us
        case ComputeTargetType::HDD_STORE:
            return 10000000;                       // 10 ms
        case ComputeTargetType::CXL_MEMORY:
            return 200;                            // 200 ns
        default:
            return 1000000;                        // 1 ms fallback
    }
}

float CalculateMigrationCost(ComputeTarget* src, ComputeTarget* dst, uint64_t bytes) {
    if (!src || !dst) return 1.0f;
    if (src == dst) return 0.0f;
    
    // Calculate transfer time
    uint64_t bandwidth = std::min(src->bandwidthBps, dst->bandwidthBps);
    if (bandwidth == 0) bandwidth = GetDeviceBandwidthEstimate(src->type);
    
    double seconds = (double)bytes / (double)bandwidth;
    double ms = seconds * 1000.0;
    
    // Normalize to 0-1 scale (assuming max 10s transfer)
    float cost = std::min(1.0f, (float)(ms / 10000.0));
    
    // Add latency penalty
    uint64_t latency = src->latencyNs + dst->latencyNs;
    cost += (float)latency / 1000000000.0f;  // Convert to seconds fraction
    
    return std::min(1.0f, cost);
}

float CalculateAccessCost(ComputeTarget* device, OperationType op, uint64_t bytes) {
    if (!device) return 1.0f;
    
    // Base cost from latency
    float latencyCost = (float)device->latencyNs / 1000000000.0f;
    
    // Bandwidth cost
    uint64_t bandwidth = device->bandwidthBps;
    if (bandwidth == 0) bandwidth = GetDeviceBandwidthEstimate(device->type);
    float bandwidthCost = (float)bytes / (float)bandwidth;
    
    // Operation-specific multipliers
    float opMultiplier = 1.0f;
    switch (op) {
        case OperationType::ATTENTION:
            opMultiplier = HasCapability(device->capabilities, CapabilityFlags::COMPUTE) ? 0.5f : 2.0f;
            break;
        case OperationType::KV_CACHE:
            opMultiplier = 0.8f;
            break;
        case OperationType::WEIGHT_LOAD:
            opMultiplier = 1.5f;
            break;
        default:
            opMultiplier = 1.0f;
    }
    
    return std::min(1.0f, (latencyCost + bandwidthCost) * opMultiplier);
}

// =============================================================================
// GPU FABRIC ENUMERATOR
// =============================================================================

std::vector<GPUFabricEnumerator::GPUInfo> GPUFabricEnumerator::EnumerateGPUs() {
    std::vector<GPUInfo> gpus;
    
#ifdef _WIN32
    IDXGIFactory6* factory = nullptr;
    if (SUCCEEDED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) {
        UINT adapterIndex = 0;
        IDXGIAdapter4* adapter = nullptr;
        
        while (factory->EnumAdapterByGpuPreference(adapterIndex, 
                                                   DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                                                   IID_PPV_ARGS(&adapter)) != DXGI_ERROR_NOT_FOUND) {
            DXGI_ADAPTER_DESC3 desc;
            if (SUCCEEDED(adapter->GetDesc3(&desc))) {
                // Skip software adapters
                if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
                    adapter->Release();
                    adapterIndex++;
                    continue;
                }
                
                GPUInfo info;
                info.deviceId = adapterIndex;
                
                // Convert wide string to UTF-8
                char name[256];
                WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, 256, nullptr, nullptr);
                info.name = name;
                
                info.dedicatedVRAM = desc.DedicatedVideoMemory;
                info.sharedMemory = desc.SharedSystemMemory;
                info.nodeMask = 1 << adapterIndex;
                info.supportsPeerAccess = (adapterIndex > 0);  // Simplified
                
                gpus.push_back(info);
            }
            
            adapter->Release();
            adapterIndex++;
        }
        
        factory->Release();
    }
#endif
    
    return gpus;
}

bool GPUFabricEnumerator::CheckPeerAccess(uint32_t gpu1, uint32_t gpu2) {
    // Simplified - in production, query D3D12 for peer access support
    return gpu1 != gpu2;
}

uint64_t GPUFabricEnumerator::GetOptimalTransferChunk(uint64_t totalSize) {
    // Use 64MB chunks for large transfers
    if (totalSize > 256 * 1024 * 1024) {
        return 64 * 1024 * 1024;
    }
    // Use 16MB chunks for medium transfers
    if (totalSize > 64 * 1024 * 1024) {
        return 16 * 1024 * 1024;
    }
    // Use 4MB chunks for small transfers
    return 4 * 1024 * 1024;
}

// =============================================================================
// FABRIC MANAGER IMPLEMENTATION
// =============================================================================

class FabricManager::Impl {
public:
    Impl() : nextHandle_(1), stats_{} {}
    
    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Enumerate GPUs
        auto gpus = GPUFabricEnumerator::EnumerateGPUs();
        
        for (const auto& gpu : gpus) {
            auto device = std::make_unique<ComputeTarget>();
            device->id = gpu.deviceId;
            device->type = ComputeTargetType::GPU_VRAM;
            device->name = gpu.name;
            device->capacityBytes = gpu.dedicatedVRAM;
            device->allocatedBytes = 0;
            device->residentBytes = 0;
            device->bandwidthBps = GetDeviceBandwidthEstimate(ComputeTargetType::GPU_VRAM);
            device->latencyNs = GetDeviceLatencyEstimate(ComputeTargetType::GPU_VRAM);
            device->computeScore = 1.0f;
            device->migrationCost = 0.3f;
            device->capabilities = CapabilityFlags::COMPUTE | 
                                   CapabilityFlags::DMA_SOURCE | 
                                   CapabilityFlags::DMA_TARGET |
                                   CapabilityFlags::ZERO_COPY |
                                   CapabilityFlags::MIGRATION;
            device->state = ResidencyState::FREE;
            device->isHealthy = true;
            device->isActive = true;
            
            devices_[device->id] = std::move(device);
        }
        
        // Register CPU RAM as compute tier
        {
            MEMORYSTATUSEX memStatus;
            memStatus.dwLength = sizeof(memStatus);
            GlobalMemoryStatusEx(&memStatus);
            
            auto device = std::make_unique<ComputeTarget>();
            device->id = 100;  // CPU device ID
            device->type = ComputeTargetType::CPU_RAM;
            device->name = "System RAM";
            device->capacityBytes = memStatus.ullTotalPhys;
            device->allocatedBytes = 0;
            device->residentBytes = 0;
            device->bandwidthBps = GetDeviceBandwidthEstimate(ComputeTargetType::CPU_RAM);
            device->latencyNs = GetDeviceLatencyEstimate(ComputeTargetType::CPU_RAM);
            device->computeScore = 0.3f;
            device->migrationCost = 0.1f;
            device->capabilities = CapabilityFlags::DMA_SOURCE | 
                                   CapabilityFlags::DMA_TARGET |
                                   CapabilityFlags::ZERO_COPY |
                                   CapabilityFlags::PREFETCH |
                                   CapabilityFlags::MIGRATION;
            device->state = ResidencyState::FREE;
            device->isHealthy = true;
            device->isActive = true;
            
            devices_[device->id] = std::move(device);
        }
        
        // Register NVMe as streaming tier
        {
            auto device = std::make_unique<ComputeTarget>();
            device->id = 200;  // NVMe device ID
            device->type = ComputeTargetType::NVME_STORE;
            device->name = "NVMe Storage";
            device->capacityBytes = 2ULL * 1024 * 1024 * 1024 * 1024;  // 2TB placeholder
            device->allocatedBytes = 0;
            device->residentBytes = 0;
            device->bandwidthBps = GetDeviceBandwidthEstimate(ComputeTargetType::NVME_STORE);
            device->latencyNs = GetDeviceLatencyEstimate(ComputeTargetType::NVME_STORE);
            device->computeScore = 0.0f;
            device->migrationCost = 0.8f;
            device->capabilities = CapabilityFlags::DMA_SOURCE | 
                                   CapabilityFlags::PREFETCH |
                                   CapabilityFlags::MIGRATION;
            device->state = ResidencyState::FREE;
            device->isHealthy = true;
            device->isActive = true;
            
            devices_[device->id] = std::move(device);
        }
        
        initialized_ = true;
        return true;
    }
    
    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Free all tensors
        for (auto& [handle, tensor] : tensors_) {
            FreeTensorInternal(handle);
        }
        tensors_.clear();
        
        // Unregister devices
        devices_.clear();
        
        initialized_ = false;
    }
    
    bool RegisterComputeTarget(std::unique_ptr<ComputeTarget> device) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (devices_.count(device->id)) {
            return false;
        }
        
        devices_[device->id] = std::move(device);
        return true;
    }
    
    bool UnregisterComputeTarget(uint32_t deviceId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Migrate any resident tensors first
        auto it = devices_.find(deviceId);
        if (it == devices_.end()) {
            return false;
        }
        
        devices_.erase(it);
        return true;
    }
    
    ComputeTarget* GetDevice(uint32_t deviceId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = devices_.find(deviceId);
        if (it != devices_.end()) {
            return it->second.get();
        }
        return nullptr;
    }
    
    ComputeTarget* GetDeviceByType(ComputeTargetType type) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& [id, device] : devices_) {
            if (device->type == type && device->isActive && device->isHealthy) {
                return device.get();
            }
        }
        return nullptr;
    }
    
    std::vector<ComputeTarget*> GetAllDevices() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<ComputeTarget*> result;
        for (auto& [id, device] : devices_) {
            result.push_back(device.get());
        }
        return result;
    }
    
    std::vector<ComputeTarget*> GetDevicesByCapability(CapabilityFlags cap) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<ComputeTarget*> result;
        for (auto& [id, device] : devices_) {
            if (HasCapability(device->capabilities, cap) && 
                device->isActive && device->isHealthy) {
                result.push_back(device.get());
            }
        }
        return result;
    }
    
    TensorHandle AllocateTensor(uint64_t size, uint64_t alignment, const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!initialized_) {
            return INVALID_HANDLE;
        }
        
        TensorHandle handle = nextHandle_++;
        
        auto tensor = std::make_unique<TensorResidency>();
        tensor->handle = handle;
        tensor->name = name;
        tensor->sizeBytes = size;
        tensor->alignment = alignment;
        tensor->currentDevice = nullptr;
        tensor->preferredDevice = nullptr;
        tensor->state = ResidencyState::ALLOCATED;
        tensor->primaryOperation = OperationType::UNKNOWN;
        tensor->heat = {0, 0, 0, 0, 0.0f};
        tensor->migration = {false, nullptr, nullptr, 0, 0, 0.0f};
        tensor->backing = {nullptr, 0, -1, 0};
        
        tensors_[handle] = std::move(tensor);
        
        stats_.totalAllocations++;
        return handle;
    }
    
    bool FreeTensor(TensorHandle handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        return FreeTensorInternal(handle);
    }
    
    bool FreeTensorInternal(TensorHandle handle) {
        auto it = tensors_.find(handle);
        if (it == tensors_.end()) {
            return false;
        }
        
        auto& tensor = it->second;
        
        // Unmap if resident
        if (tensor->state == ResidencyState::RESIDENT || 
            tensor->state == ResidencyState::PINNED) {
            // Platform-specific cleanup
#ifdef _WIN32
            if (tensor->backing.cpuPtr) {
                VirtualFree(tensor->backing.cpuPtr, 0, MEM_RELEASE);
            }
#endif
        }
        
        tensors_.erase(it);
        return true;
    }
    
    TensorResidency* GetTensor(TensorHandle handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = tensors_.find(handle);
        if (it != tensors_.end()) {
            return it->second.get();
        }
        return nullptr;
    }
    
    bool EnsureResident(TensorHandle handle, OperationType operation) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto tensor = GetTensor(handle);
        if (!tensor) {
            return false;
        }
        
        std::lock_guard<std::mutex> tensorLock(tensor->mutex);
        
        // Already resident on a compute-capable device
        if (tensor->state == ResidencyState::RESIDENT || 
            tensor->state == ResidencyState::PINNED) {
            if (tensor->currentDevice && 
                HasCapability(tensor->currentDevice->capabilities, CapabilityFlags::COMPUTE)) {
                tensor->heat.UpdateAccess(tensor->sizeBytes, false);
                return true;
            }
        }
        
        // Need to migrate - select best device
        ScheduleRequest request;
        request.handle = handle;
        request.operation = operation;
        request.bytesRequired = tensor->sizeBytes;
        request.latencyBudgetNs = 1000000;  // 1ms default
        request.bandwidthRequiredBps = 0;
        request.strategy = PlacementStrategy::LATENCY_OPTIMIZED;
        request.allowMigration = true;
        request.allowEviction = true;
        
        auto decision = SelectPlacementInternal(request);
        if (!decision.targetDevice) {
            stats_.failedAllocations++;
            return false;
        }
        
        // Perform migration
        return MigrateInternal(handle, decision.targetDevice->id);
    }
    
    bool Migrate(TensorHandle handle, uint32_t targetDeviceId) {
        std::lock_guard<std::mutex> lock(mutex_);
        return MigrateInternal(handle, targetDeviceId);
    }
    
    bool MigrateInternal(TensorHandle handle, uint32_t targetDeviceId) {
        auto tensor = GetTensor(handle);
        if (!tensor) {
            return false;
        }
        
        auto targetDevice = GetDevice(targetDeviceId);
        if (!targetDevice) {
            return false;
        }
        
        std::lock_guard<std::mutex> tensorLock(tensor->mutex);
        
        if (!tensor->CanMigrate()) {
            return false;
        }
        
        // Check capacity
        if (tensor->sizeBytes > targetDevice->availableBytes()) {
            // Try to evict
            if (!EvictFromDevice(targetDevice, tensor->sizeBytes)) {
                return false;
            }
        }
        
        // Perform migration
        tensor->state = ResidencyState::MIGRATING;
        tensor->migration.isMigrating = true;
        tensor->migration.source = tensor->currentDevice;
        tensor->migration.destination = targetDevice;
        tensor->migration.bytesTransferred = 0;
        tensor->migration.bytesTotal = tensor->sizeBytes;
        tensor->migration.progress = 0.0f;
        
        // Platform-specific migration
        // TODO: Implement actual DMA transfer
        
        // Update device accounting
        if (tensor->currentDevice) {
            tensor->currentDevice->residentBytes -= tensor->sizeBytes;
        }
        targetDevice->residentBytes += tensor->sizeBytes;
        
        tensor->currentDevice = targetDevice;
        tensor->state = ResidencyState::RESIDENT;
        tensor->migration.isMigrating = false;
        
        stats_.totalMigrations++;
        stats_.migrationBytes += tensor->sizeBytes;
        
        return true;
    }
    
    bool Prefetch(TensorHandle handle, uint32_t targetDeviceId) {
        // Similar to migrate but marks as PREFETCHED
        auto tensor = GetTensor(handle);
        if (!tensor) return false;
        
        if (MigrateInternal(handle, targetDeviceId)) {
            std::lock_guard<std::mutex> tensorLock(tensor->mutex);
            tensor->state = ResidencyState::PREFETCHED;
            stats_.totalPrefetches++;
            return true;
        }
        return false;
    }
    
    bool Evict(TensorHandle handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto tensor = GetTensor(handle);
        if (!tensor) return false;
        
        std::lock_guard<std::mutex> tensorLock(tensor->mutex);
        
        if (tensor->IsPinned()) return false;
        
        // Find eviction target (prefer NVMe, then HDD)
        ComputeTarget* target = GetDeviceByType(ComputeTargetType::NVME_STORE);
        if (!target) {
            target = GetDeviceByType(ComputeTargetType::HDD_STORE);
        }
        
        if (!target) return false;
        
        return MigrateInternal(handle, target->id);
    }
    
    bool Pin(TensorHandle handle) {
        auto tensor = GetTensor(handle);
        if (!tensor) return false;
        
        tensor->pinCount++;
        
        std::lock_guard<std::mutex> tensorLock(tensor->mutex);
        if (tensor->state == ResidencyState::RESIDENT) {
            tensor->state = ResidencyState::PINNED;
        }
        
        return true;
    }
    
    bool Unpin(TensorHandle handle) {
        auto tensor = GetTensor(handle);
        if (!tensor) return false;
        
        auto count = tensor->pinCount.fetch_sub(1);
        if (count == 1) {
            std::lock_guard<std::mutex> tensorLock(tensor->mutex);
            if (tensor->state == ResidencyState::PINNED) {
                tensor->state = ResidencyState::RESIDENT;
            }
        }
        
        return true;
    }
    
    PlacementDecision SelectPlacement(const ScheduleRequest& request) {
        std::lock_guard<std::mutex> lock(mutex_);
        return SelectPlacementInternal(request);
    }
    
    PlacementDecision SelectPlacementInternal(const ScheduleRequest& request) {
        PlacementDecision decision;
        decision.targetDevice = nullptr;
        decision.confidence = 0.0f;
        decision.estimatedCost = 1.0f;
        
        auto tensor = GetTensor(request.handle);
        if (!tensor) return decision;
        
        // Get candidate devices
        std::vector<ComputeTarget*> candidates;
        
        if (request.strategy == PlacementStrategy::LATENCY_OPTIMIZED) {
            // Prefer GPU VRAM, then RAM
            auto gpu = GetDeviceByType(ComputeTargetType::GPU_VRAM);
            if (gpu) candidates.push_back(gpu);
            auto ram = GetDeviceByType(ComputeTargetType::CPU_RAM);
            if (ram) candidates.push_back(ram);
        } else if (request.strategy == PlacementStrategy::CAPACITY_OPTIMIZED) {
            // Prefer largest available
            candidates = GetAllDevices();
            std::sort(candidates.begin(), candidates.end(), 
                [](ComputeTarget* a, ComputeTarget* b) {
                    return a->availableBytes() > b->availableBytes();
                });
        } else {
            candidates = GetAllDevices();
        }
        
        // Score candidates
        ComputeTarget* bestDevice = nullptr;
        float bestScore = -1.0f;
        
        for (auto* device : candidates) {
            if (!device->isHealthy || !device->isActive) continue;
            if (device->availableBytes() < request.bytesRequired) continue;
            
            float score = 0.0f;
            
            // Compute capability bonus
            if (HasCapability(device->capabilities, CapabilityFlags::COMPUTE)) {
                score += device->computeScore * 0.4f;
            }
            
            // Latency score
            float latencyScore = 1.0f - ((float)device->latencyNs / 1000000000.0f);
            score += latencyScore * 0.3f;
            
            // Bandwidth score
            float bwScore = (float)device->bandwidthBps / 
                           (float)GetDeviceBandwidthEstimate(ComputeTargetType::GPU_VRAM);
            score += std::min(1.0f, bwScore) * 0.2f;
            
            // Migration cost penalty
            if (tensor->currentDevice && tensor->currentDevice != device) {
                float migrationCost = CalculateMigrationCost(tensor->currentDevice, device, 
                                                             request.bytesRequired);
                score -= migrationCost * 0.1f;
            }
            
            if (score > bestScore) {
                bestScore = score;
                bestDevice = device;
            }
        }
        
        if (bestDevice) {
            decision.targetDevice = bestDevice;
            decision.strategy = request.strategy;
            decision.confidence = bestScore;
            decision.estimatedLatencyNs = bestDevice->latencyNs;
            decision.estimatedBandwidthBps = bestDevice->bandwidthBps;
            decision.estimatedCost = 1.0f - bestScore;
        }
        
        return decision;
    }
    
    bool EvictFromDevice(ComputeTarget* device, uint64_t bytesNeeded) {
        // Find evictable tensors on this device
        std::vector<TensorResidency*> candidates;
        
        for (auto& [handle, tensor] : tensors_) {
            if (tensor->currentDevice == device && 
                tensor->CanMigrate() &&
                tensor->state == ResidencyState::RESIDENT) {
                candidates.push_back(tensor.get());
            }
        }
        
        // Sort by temperature (coldest first)
        std::sort(candidates.begin(), candidates.end(),
            [](TensorResidency* a, TensorResidency* b) {
                return a->heat.temperature < b->heat.temperature;
            });
        
        uint64_t evicted = 0;
        for (auto* tensor : candidates) {
            if (evicted >= bytesNeeded) break;
            
            if (Evict(tensor->handle)) {
                evicted += tensor->sizeBytes;
                stats_.totalEvictions++;
            }
        }
        
        return evicted >= bytesNeeded;
    }
    
    uint64_t GetTotalCapacity(ComputeTargetType type) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t total = 0;
        for (auto& [id, device] : devices_) {
            if (device->type == type) {
                total += device->capacityBytes;
            }
        }
        return total;
    }
    
    uint64_t GetAvailableCapacity(ComputeTargetType type) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t available = 0;
        for (auto& [id, device] : devices_) {
            if (device->type == type) {
                available += device->availableBytes();
            }
        }
        return available;
    }
    
    float GetFabricUtilization() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t totalCapacity = 0;
        uint64_t totalUsed = 0;
        
        for (auto& [id, device] : devices_) {
            totalCapacity += device->capacityBytes;
            totalUsed += device->residentBytes;
        }
        
        if (totalCapacity == 0) return 0.0f;
        return (float)totalUsed / (float)totalCapacity;
    }
    
    std::string GetFabricTopology() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::stringstream ss;
        ss << "RawRamXD Fabric Topology:\n";
        ss << "========================\n\n";
        
        for (auto& [id, device] : devices_) {
            ss << "Device " << device->id << ": " << device->name << "\n";
            ss << "  Type: " << ComputeTargetTypeToString(device->type) << "\n";
            ss << "  Capacity: " << (device->capacityBytes / (1024*1024*1024)) << " GB\n";
            ss << "  Used: " << (device->residentBytes / (1024*1024*1024)) << " GB\n";
            ss << "  Available: " << (device->availableBytes() / (1024*1024*1024)) << " GB\n";
            ss << "  Compute Score: " << device->computeScore << "\n";
            ss << "  Bandwidth: " << (device->bandwidthBps / (1024*1024*1024)) << " GB/s\n";
            ss << "  Latency: " << device->latencyNs << " ns\n";
            ss << "  Healthy: " << (device->isHealthy ? "Yes" : "No") << "\n";
            ss << "\n";
        }
        
        return ss.str();
    }
    
    FabricManager::Stats GetStats() const {
        return stats_;
    }

private:
    std::mutex mutex_;
    bool initialized_ = false;
    TensorHandle nextHandle_;
    
    std::unordered_map<uint32_t, std::unique_ptr<ComputeTarget>> devices_;
    std::unordered_map<TensorHandle, std::unique_ptr<TensorResidency>> tensors_;
    
    FabricManager::Stats stats_;
};

// =============================================================================
// FABRIC MANAGER PUBLIC INTERFACE
// =============================================================================

FabricManager::FabricManager() : impl_(std::make_unique<Impl>()) {}
FabricManager::~FabricManager() = default;

bool FabricManager::Initialize() { return impl_->Initialize(); }
void FabricManager::Shutdown() { impl_->Shutdown(); }

bool FabricManager::RegisterComputeTarget(std::unique_ptr<ComputeTarget> device) {
    return impl_->RegisterComputeTarget(std::move(device));
}

bool FabricManager::UnregisterComputeTarget(uint32_t deviceId) {
    return impl_->UnregisterComputeTarget(deviceId);
}

ComputeTarget* FabricManager::GetDevice(uint32_t deviceId) {
    return impl_->GetDevice(deviceId);
}

ComputeTarget* FabricManager::GetDeviceByType(ComputeTargetType type) {
    return impl_->GetDeviceByType(type);
}

std::vector<ComputeTarget*> FabricManager::GetAllDevices() {
    return impl_->GetAllDevices();
}

std::vector<ComputeTarget*> FabricManager::GetDevicesByCapability(CapabilityFlags cap) {
    return impl_->GetDevicesByCapability(cap);
}

TensorHandle FabricManager::AllocateTensor(uint64_t size, uint64_t alignment, 
                                            const std::string& name) {
    return impl_->AllocateTensor(size, alignment, name);
}

bool FabricManager::FreeTensor(TensorHandle handle) {
    return impl_->FreeTensor(handle);
}

TensorResidency* FabricManager::GetTensor(TensorHandle handle) {
    return impl_->GetTensor(handle);
}

bool FabricManager::EnsureResident(TensorHandle handle, OperationType operation) {
    return impl_->EnsureResident(handle, operation);
}

bool FabricManager::Migrate(TensorHandle handle, uint32_t targetDeviceId) {
    return impl_->Migrate(handle, targetDeviceId);
}

bool FabricManager::Prefetch(TensorHandle handle, uint32_t targetDeviceId) {
    return impl_->Prefetch(handle, targetDeviceId);
}

bool FabricManager::Evict(TensorHandle handle) {
    return impl_->Evict(handle);
}

bool FabricManager::Pin(TensorHandle handle) {
    return impl_->Pin(handle);
}

bool FabricManager::Unpin(TensorHandle handle) {
    return impl_->Unpin(handle);
}

PlacementDecision FabricManager::SelectPlacement(const ScheduleRequest& request) {
    return impl_->SelectPlacement(request);
}

uint64_t FabricManager::GetTotalCapacity(ComputeTargetType type) {
    return impl_->GetTotalCapacity(type);
}

uint64_t FabricManager::GetAvailableCapacity(ComputeTargetType type) {
    return impl_->GetAvailableCapacity(type);
}

float FabricManager::GetFabricUtilization() {
    return impl_->GetFabricUtilization();
}

std::string FabricManager::GetFabricTopology() {
    return impl_->GetFabricTopology();
}

FabricManager::Stats FabricManager::GetStats() const {
    return impl_->GetStats();
}

} // namespace Fabric
} // namespace RawRamXD
