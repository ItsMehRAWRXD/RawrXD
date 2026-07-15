// =============================================================================
// RawRamXD Phase 7B.2: Multi-GPU Fabric Federation
// Unified Heterogeneous Memory Scheduler for Multi-GPU Workloads
// =============================================================================

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <queue>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <cstring>
#include <cmath>

// Windows/DirectX headers for GPU detection
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

using Microsoft::WRL::ComPtr;

namespace RawRamXD {

// =============================================================================
// Forward Declarations
// =============================================================================
class FabricNode;
class FabricFederation;
class MultiGPUScheduler;
class PeerAccessManager;

// =============================================================================
// Enums and Types
// =============================================================================

enum class GPUVendor {
    UNKNOWN = 0,
    NVIDIA = 1,
    AMD = 2,
    INTEL = 3
};

enum class FabricNodeType {
    LOCAL = 0,
    REMOTE = 1,
    CLOUD = 2
};

enum class PeerAccessType {
    NONE = 0,
    DIRECT = 1,
    NVLINK = 2,
    INFINITY_FABRIC = 3,
    BRIDGE = 4
};

enum class MigrationPath {
    P2P_DIRECT = 0,
    P2P_BRIDGE = 1,
    BRIDGE_RAM = 2,
    NETWORK = 3
};

// =============================================================================
// GPU Device Information
// =============================================================================

struct GPUDeviceInfo {
    uint32_t deviceId;
    wchar_t name[128];
    GPUVendor vendor;
    
    // Memory
    uint64_t vramTotalBytes;
    uint64_t vramAvailableBytes;
    uint64_t vramAllocatedBytes;
    
    // Performance
    uint64_t bandwidthBytesPerSec;
    uint64_t latencyNs;
    float computeScore;
    
    // Topology
    PeerAccessType peerAccessType;
    std::vector<uint32_t> accessiblePeers;
    
    // D3D12 resources
    ComPtr<ID3D12Device> d3d12Device;
    ComPtr<ID3D12CommandQueue> copyQueue;
    ComPtr<ID3D12CommandQueue> computeQueue;
    uint32_t nodeMask;
    
    FabricNodeType nodeType;
    uint32_t nodeId;
};

// =============================================================================
// Peer Access Manager
// =============================================================================

class PeerAccessManager {
public:
    bool Initialize(const std::vector<GPUDeviceInfo*>& gpus);
    void Shutdown();
    
    bool CanAccessPeer(uint32_t srcGPU, uint32_t dstGPU);
    PeerAccessType GetPeerAccessType(uint32_t srcGPU, uint32_t dstGPU);
    MigrationPath GetOptimalMigrationPath(uint32_t srcGPU, uint32_t dstGPU, size_t size);
    
    uint64_t GetP2PBandwidth(uint32_t srcGPU, uint32_t dstGPU);
    uint64_t GetP2PLatency(uint32_t srcGPU, uint32_t dstGPU);
    
private:
    std::vector<std::vector<bool>> peerAccessMatrix_;
    std::vector<std::vector<PeerAccessType>> accessTypeMatrix_;
    bool initialized_ = false;
};

bool PeerAccessManager::Initialize(const std::vector<GPUDeviceInfo*>& gpus) {
    size_t n = gpus.size();
    peerAccessMatrix_.resize(n, std::vector<bool>(n, false));
    accessTypeMatrix_.resize(n, std::vector<PeerAccessType>(n, PeerAccessType::NONE));
    
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            if (i == j) {
                peerAccessMatrix_[i][j] = true;
                accessTypeMatrix_[i][j] = PeerAccessType::DIRECT;
            } else {
                // Check if GPUs can access each other
                // In real implementation: cudaDeviceCanAccessPeer or D3D12 check
                peerAccessMatrix_[i][j] = (gpus[i]->vendor == gpus[j]->vendor);
                
                if (gpus[i]->vendor == GPUVendor::NVIDIA && gpus[j]->vendor == GPUVendor::NVIDIA) {
                    accessTypeMatrix_[i][j] = PeerAccessType::NVLINK;
                } else if (gpus[i]->vendor == GPUVendor::AMD && gpus[j]->vendor == GPUVendor::AMD) {
                    accessTypeMatrix_[i][j] = PeerAccessType::INFINITY_FABRIC;
                } else {
                    accessTypeMatrix_[i][j] = PeerAccessType::BRIDGE;
                }
            }
        }
    }
    
    initialized_ = true;
    return true;
}

void PeerAccessManager::Shutdown() {
    initialized_ = false;
}

bool PeerAccessManager::CanAccessPeer(uint32_t srcGPU, uint32_t dstGPU) {
    if (!initialized_) return false;
    if (srcGPU >= peerAccessMatrix_.size() || dstGPU >= peerAccessMatrix_[srcGPU].size()) return false;
    return peerAccessMatrix_[srcGPU][dstGPU];
}

PeerAccessType PeerAccessManager::GetPeerAccessType(uint32_t srcGPU, uint32_t dstGPU) {
    if (!initialized_) return PeerAccessType::NONE;
    if (srcGPU >= accessTypeMatrix_.size() || dstGPU >= accessTypeMatrix_[srcGPU].size()) return PeerAccessType::NONE;
    return accessTypeMatrix_[srcGPU][dstGPU];
}

MigrationPath PeerAccessManager::GetOptimalMigrationPath(uint32_t srcGPU, uint32_t dstGPU, size_t size) {
    if (srcGPU == dstGPU) return MigrationPath::P2P_DIRECT;
    
    auto accessType = GetPeerAccessType(srcGPU, dstGPU);
    switch (accessType) {
        case PeerAccessType::NVLINK:
        case PeerAccessType::INFINITY_FABRIC:
            return MigrationPath::P2P_DIRECT;
        case PeerAccessType::DIRECT:
            return MigrationPath::P2P_BRIDGE;
        default:
            return MigrationPath::BRIDGE_RAM;
    }
}

uint64_t PeerAccessManager::GetP2PBandwidth(uint32_t srcGPU, uint32_t dstGPU) {
    auto type = GetPeerAccessType(srcGPU, dstGPU);
    switch (type) {
        case PeerAccessType::NVLINK: return 200ULL * 1024 * 1024 * 1024;  // 200 GB/s
        case PeerAccessType::INFINITY_FABRIC: return 100ULL * 1024 * 1024 * 1024; // 100 GB/s
        case PeerAccessType::DIRECT: return 32ULL * 1024 * 1024 * 1024;    // 32 GB/s (PCIe)
        default: return 16ULL * 1024 * 1024 * 1024;                        // 16 GB/s (via RAM)
    }
}

uint64_t PeerAccessManager::GetP2PLatency(uint32_t srcGPU, uint32_t dstGPU) {
    auto type = GetPeerAccessType(srcGPU, dstGPU);
    switch (type) {
        case PeerAccessType::NVLINK: return 5000;      // 5 us
        case PeerAccessType::INFINITY_FABRIC: return 10000;   // 10 us
        case PeerAccessType::DIRECT: return 50000;     // 50 us
        default: return 100000;                        // 100 us
    }
}

// =============================================================================
// Fabric Node
// =============================================================================

class FabricNode {
public:
    FabricNode(uint32_t id, FabricNodeType type) : id_(id), type_(type) {}
    
    bool Initialize();
    void Shutdown();
    
    uint32_t GetId() const { return id_; }
    FabricNodeType GetType() const { return type_; }
    
    void RegisterGPU(GPUDeviceInfo* gpu);
    void UnregisterGPU(uint32_t deviceId);
    GPUDeviceInfo* GetGPU(uint32_t deviceId);
    std::vector<GPUDeviceInfo*> GetGPUs() const;
    
    uint64_t GetTotalVRAM() const;
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalAllocated() const;
    
    uint64_t AllocateVRAM(uint32_t gpuId, size_t size);
    void FreeVRAM(uint32_t gpuId, uint64_t handle);
    
private:
    uint32_t id_;
    FabricNodeType type_;
    std::unordered_map<uint32_t, std::unique_ptr<GPUDeviceInfo>> gpus_;
    mutable std::mutex gpusMutex_;
};

bool FabricNode::Initialize() {
    return true;
}

void FabricNode::Shutdown() {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    gpus_.clear();
}

void FabricNode::RegisterGPU(GPUDeviceInfo* gpu) {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    gpus_[gpu->deviceId] = std::unique_ptr<GPUDeviceInfo>(gpu);
}

void FabricNode::UnregisterGPU(uint32_t deviceId) {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    gpus_.erase(deviceId);
}

GPUDeviceInfo* FabricNode::GetGPU(uint32_t deviceId) {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    auto it = gpus_.find(deviceId);
    return (it != gpus_.end()) ? it->second.get() : nullptr;
}

std::vector<GPUDeviceInfo*> FabricNode::GetGPUs() const {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    std::vector<GPUDeviceInfo*> result;
    for (const auto& [id, gpu] : gpus_) {
        result.push_back(gpu.get());
    }
    return result;
}

uint64_t FabricNode::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    uint64_t total = 0;
    for (const auto& [id, gpu] : gpus_) {
        total += gpu->vramTotalBytes;
    }
    return total;
}

uint64_t FabricNode::GetAvailableVRAM() const {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    uint64_t available = 0;
    for (const auto& [id, gpu] : gpus_) {
        available += gpu->vramAvailableBytes;
    }
    return available;
}

uint64_t FabricNode::GetTotalAllocated() const {
    std::lock_guard<std::mutex> lock(gpusMutex_);
    uint64_t allocated = 0;
    for (const auto& [id, gpu] : gpus_) {
        allocated += gpu->vramAllocatedBytes;
    }
    return allocated;
}

uint64_t FabricNode::AllocateVRAM(uint32_t gpuId, size_t size) {
    auto* gpu = GetGPU(gpuId);
    if (!gpu || gpu->vramAvailableBytes < size) return 0;
    
    gpu->vramAvailableBytes -= size;
    gpu->vramAllocatedBytes += size;
    
    // Return handle (simplified - in real implementation would be actual allocation)
    return gpuId * 0x100000000ULL + size;
}

void FabricNode::FreeVRAM(uint32_t gpuId, uint64_t handle) {
    auto* gpu = GetGPU(gpuId);
    if (!gpu) return;
    
    size_t size = handle & 0xFFFFFFFFULL;
    gpu->vramAvailableBytes += size;
    gpu->vramAllocatedBytes -= size;
}

// =============================================================================
// Multi-GPU Scheduler
// =============================================================================

class MultiGPUScheduler {
public:
    enum class SchedulePolicy {
        ROUND_ROBIN = 0,
        LOAD_BALANCED = 1,
        PERFORMANCE = 2,
        RESIDENCY = 3,
        COST_OPTIMIZED = 4
    };
    
    struct SchedulerStats {
        uint32_t totalTensors;
        uint32_t migrationsInitiated;
        uint32_t migrationsCompleted;
        uint32_t migrationsFailed;
        double avgMigrationTimeMs;
        uint32_t p2pTransfers;
        uint32_t bridgeTransfers;
    };
    
    bool Initialize(FabricFederation* federation);
    void Shutdown();
    
    void SetPolicy(SchedulePolicy policy);
    SchedulePolicy GetPolicy() const { return currentPolicy_; }
    
    uint32_t SelectOptimalGPU(size_t tensorSize, const std::vector<uint32_t>& candidates);
    bool ShouldMigrate(uint64_t tensorHandle, uint32_t currentGPU, uint32_t targetGPU);
    MigrationPath SelectMigrationPath(uint32_t srcGPU, uint32_t dstGPU, size_t size);
    
    void SubmitTensorOperation(uint64_t tensorHandle, uint32_t gpuId, std::function<void()> operation);
    
    SchedulerStats GetStats() const;
    
private:
    FabricFederation* federation_ = nullptr;
    SchedulePolicy currentPolicy_ = SchedulePolicy::LOAD_BALANCED;
    bool initialized_ = false;
    
    std::unordered_map<uint32_t, std::queue<std::function<void()>>> workQueues_;
    mutable std::mutex queueMutex_;
    
    std::atomic<uint32_t> migrationsInitiated_{0};
    std::atomic<uint32_t> migrationsCompleted_{0};
    std::atomic<uint32_t> migrationsFailed_{0};
    std::atomic<uint32_t> p2pTransfers_{0};
    std::atomic<uint32_t> bridgeTransfers_{0};
};

// Forward declaration for FabricFederation
class FabricFederation {
public:
    static FabricFederation& Instance();
    
    bool Initialize();
    void Shutdown();
    
    bool RegisterNode(std::unique_ptr<FabricNode> node);
    void UnregisterNode(uint32_t nodeId);
    FabricNode* GetNode(uint32_t nodeId);
    std::vector<FabricNode*> GetAllNodes();
    FabricNode* GetLocalNode();
    
    std::vector<GPUDeviceInfo*> GetAllGPUs();
    GPUDeviceInfo* GetGPU(uint32_t nodeId, uint32_t deviceId);
    
    uint64_t GetTotalVRAM() const;
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalAllocated() const;
    
    bool MigrateAcrossNodes(uint32_t srcNodeId, uint64_t srcHandle,
                            uint32_t dstNodeId, uint64_t dstHandle,
                            size_t size);
    
    uint32_t GetNodeCount() const;
    uint32_t GetGPUCount() const;
    
    MultiGPUScheduler* GetScheduler() const { return scheduler_.get(); }
    PeerAccessManager* GetPeerAccessManager() const { return peerAccessManager_.get(); }
    
private:
    FabricFederation() = default;
    ~FabricFederation() = default;
    FabricFederation(const FabricFederation&) = delete;
    FabricFederation& operator=(const FabricFederation&) = delete;
    
    std::unordered_map<uint32_t, std::unique_ptr<FabricNode>> nodes_;
    mutable std::mutex nodesMutex_;
    
    std::unique_ptr<MultiGPUScheduler> scheduler_;
    std::unique_ptr<PeerAccessManager> peerAccessManager_;
    
    bool initialized_ = false;
};

bool MultiGPUScheduler::Initialize(FabricFederation* federation) {
    federation_ = federation;
    initialized_ = true;
    
    std::cout << "[RawRamXD] Multi-GPU Scheduler initialized" << std::endl;
    std::cout << "  Policy: ";
    switch (currentPolicy_) {
        case SchedulePolicy::ROUND_ROBIN: std::cout << "Round Robin"; break;
        case SchedulePolicy::LOAD_BALANCED: std::cout << "Load Balanced"; break;
        case SchedulePolicy::PERFORMANCE: std::cout << "Performance"; break;
        case SchedulePolicy::RESIDENCY: std::cout << "Residency"; break;
        case SchedulePolicy::COST_OPTIMIZED: std::cout << "Cost Optimized"; break;
    }
    std::cout << std::endl;
    
    return true;
}

void MultiGPUScheduler::Shutdown() {
    initialized_ = false;
}

void MultiGPUScheduler::SetPolicy(SchedulePolicy policy) {
    currentPolicy_ = policy;
    std::cout << "[RawRamXD] Scheduler policy changed to ";
    switch (policy) {
        case SchedulePolicy::ROUND_ROBIN: std::cout << "Round Robin"; break;
        case SchedulePolicy::LOAD_BALANCED: std::cout << "Load Balanced"; break;
        case SchedulePolicy::PERFORMANCE: std::cout << "Performance"; break;
        case SchedulePolicy::RESIDENCY: std::cout << "Residency"; break;
        case SchedulePolicy::COST_OPTIMIZED: std::cout << "Cost Optimized"; break;
    }
    std::cout << std::endl;
}

uint32_t MultiGPUScheduler::SelectOptimalGPU(size_t tensorSize, const std::vector<uint32_t>& candidates) {
    if (!federation_) return 0;
    
    auto allGPUs = federation_->GetAllGPUs();
    std::vector<GPUDeviceInfo*> available;
    
    for (auto gpu : allGPUs) {
        if (gpu->vramAvailableBytes >= tensorSize) {
            available.push_back(gpu);
        }
    }
    
    if (available.empty()) return 0;
    
    switch (currentPolicy_) {
        case SchedulePolicy::ROUND_ROBIN: {
            static uint32_t roundRobinIndex = 0;
            if (roundRobinIndex >= available.size()) roundRobinIndex = 0;
            return available[roundRobinIndex++]->deviceId;
        }
        case SchedulePolicy::LOAD_BALANCED: {
            // Select GPU with most available VRAM
            auto* best = available[0];
            for (auto gpu : available) {
                if (gpu->vramAvailableBytes > best->vramAvailableBytes) {
                    best = gpu;
                }
            }
            return best->deviceId;
        }
        case SchedulePolicy::PERFORMANCE: {
            // Select GPU with highest compute score
            auto* best = available[0];
            for (auto gpu : available) {
                if (gpu->computeScore > best->computeScore) {
                    best = gpu;
                }
            }
            return best->deviceId;
        }
        case SchedulePolicy::COST_OPTIMIZED: {
            // Simple: use GPU with lowest latency
            auto* best = available[0];
            for (auto gpu : available) {
                if (gpu->latencyNs < best->latencyNs) {
                    best = gpu;
                }
            }
            return best->deviceId;
        }
        case SchedulePolicy::RESIDENCY:
        default: {
            // Check if tensor is already resident
            // For now, use load balanced
            auto* best = available[0];
            for (auto gpu : available) {
                if (gpu->vramAvailableBytes > best->vramAvailableBytes) {
                    best = gpu;
                }
            }
            return best->deviceId;
        }
    }
}

bool MultiGPUScheduler::ShouldMigrate(uint64_t tensorHandle, uint32_t currentGPU, uint32_t targetGPU) {
    if (currentGPU == targetGPU) return false;
    
    // Check if target has enough space
    auto* target = federation_->GetGPU(0, targetGPU);  // Node 0 for now
    if (!target) return false;
    
    // If target has >2x available, migrate
    return target->vramAvailableBytes > 2ULL * 1024 * 1024 * 1024;  // 2GB threshold
}

MigrationPath MultiGPUScheduler::SelectMigrationPath(uint32_t srcGPU, uint32_t dstGPU, size_t size) {
    auto* p2p = federation_->GetPeerAccessManager();
    if (!p2p) return MigrationPath::BRIDGE_RAM;
    
    return p2p->GetOptimalMigrationPath(srcGPU, dstGPU, size);
}

void MultiGPUScheduler::SubmitTensorOperation(uint64_t tensorHandle, uint32_t gpuId,
                                               std::function<void()> operation) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    workQueues_[gpuId].push(operation);
}

MultiGPUScheduler::SchedulerStats MultiGPUScheduler::GetStats() const {
    SchedulerStats stats;
    stats.totalTensors = 0;  // Would track in real implementation
    stats.migrationsInitiated = migrationsInitiated_.load();
    stats.migrationsCompleted = migrationsCompleted_.load();
    stats.migrationsFailed = migrationsFailed_.load();
    stats.avgMigrationTimeMs = 0.0;
    stats.p2pTransfers = p2pTransfers_.load();
    stats.bridgeTransfers = bridgeTransfers_.load();
    return stats;
}

// =============================================================================
// Fabric Federation Implementation
// =============================================================================

FabricFederation& FabricFederation::Instance() {
    static FabricFederation instance;
    return instance;
}

bool FabricFederation::Initialize() {
    if (initialized_) return true;
    
    std::cout << "\n========================================\n";
    std::cout << "RawRamXD Phase 7B.2: Multi-GPU Fabric Federation\n";
    std::cout << "========================================\n\n";
    
    // Create local node
    auto localNode = std::make_unique<FabricNode>(0, FabricNodeType::LOCAL);
    if (!localNode->Initialize()) {
        std::cerr << "[!] Failed to initialize local node\n";
        return false;
    }
    
    // Detect GPUs
    IDXGIFactory4* factory = nullptr;
    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        std::cerr << "[!] Failed to create DXGI factory\n";
        return false;
    }
    
    std::cout << "[+] Enumerating GPUs...\n";
    int gpuIndex = 0;
    for (UINT i = 0; ; i++) {
        IDXGIAdapter1* adapter1 = nullptr;
        if (factory->EnumAdapters1(i, &adapter1) == DXGI_ERROR_NOT_FOUND) break;
        
        DXGI_ADAPTER_DESC1 desc;
        adapter1->GetDesc1(&desc);
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            adapter1->Release();
            continue;
        }
        
        auto* gpu = new GPUDeviceInfo();
        gpu->deviceId = gpuIndex++;
        gpu->vramTotalBytes = desc.DedicatedVideoMemory;
        gpu->vramAvailableBytes = desc.DedicatedVideoMemory;
        gpu->vramAllocatedBytes = 0;
        gpu->nodeType = FabricNodeType::LOCAL;
        
        // Vendor detection
        if (desc.VendorId == 0x10DE) {
            gpu->vendor = GPUVendor::NVIDIA;
            gpu->bandwidthBytesPerSec = 1000ULL * 1024 * 1024 * 1024; // 1 TB/s
            gpu->latencyNs = 50;
            gpu->computeScore = 100.0f;
            gpu->peerAccessType = PeerAccessType::NVLINK;
        } else if (desc.VendorId == 0x1002) {
            gpu->vendor = GPUVendor::AMD;
            gpu->bandwidthBytesPerSec = 500ULL * 1024 * 1024 * 1024; // 500 GB/s
            gpu->latencyNs = 100;
            gpu->computeScore = 80.0f;
            gpu->peerAccessType = PeerAccessType::INFINITY_FABRIC;
        } else if (desc.VendorId == 0x8086) {
            gpu->vendor = GPUVendor::INTEL;
            gpu->bandwidthBytesPerSec = 200ULL * 1024 * 1024 * 1024; // 200 GB/s
            gpu->latencyNs = 200;
            gpu->computeScore = 50.0f;
            gpu->peerAccessType = PeerAccessType::DIRECT;
        } else {
            gpu->vendor = GPUVendor::UNKNOWN;
            gpu->bandwidthBytesPerSec = 100ULL * 1024 * 1024 * 1024;
            gpu->latencyNs = 500;
            gpu->computeScore = 30.0f;
            gpu->peerAccessType = PeerAccessType::BRIDGE;
        }
        
        // Convert name
        wcscpy_s(gpu->name, desc.Description);
        
        // Create D3D12 device
        hr = D3D12CreateDevice(adapter1, D3D_FEATURE_LEVEL_12_0, IID_PPV_ARGS(&gpu->d3d12Device));
        if (SUCCEEDED(hr) && gpu->d3d12Device) {
            gpu->nodeMask = 0;
            
            // Create queues
            D3D12_COMMAND_QUEUE_DESC queueDesc = {};
            queueDesc.Type = D3D12_COMMAND_LIST_TYPE_COPY;
            gpu->d3d12Device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&gpu->copyQueue));
            queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
            gpu->d3d12Device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&gpu->computeQueue));
        }
        
        localNode->RegisterGPU(gpu);
        
        std::wcout << L"  GPU " << gpu->deviceId << L": " << gpu->name << L" ("
                   << (gpu->vramTotalBytes / (1024ULL * 1024 * 1024)) << L" GB)";
        switch (gpu->vendor) {
            case GPUVendor::AMD: std::wcout << L" [AMD]"; break;
            case GPUVendor::NVIDIA: std::wcout << L" [NVIDIA]"; break;
            case GPUVendor::INTEL: std::wcout << L" [Intel]"; break;
            default: break;
        }
        std::wcout << std::endl;
        
        adapter1->Release();
    }
    
    factory->Release();
    
    // Register local node
    RegisterNode(std::move(localNode));
    
    // Initialize peer access manager
    auto allGPUs = GetAllGPUs();
    peerAccessManager_ = std::make_unique<PeerAccessManager>();
    if (!peerAccessManager_->Initialize(allGPUs)) {
        std::cerr << "[!] Failed to initialize peer access manager\n";
        return false;
    }
    
    // Initialize scheduler
    scheduler_ = std::make_unique<MultiGPUScheduler>();
    if (!scheduler_->Initialize(this)) {
        std::cerr << "[!] Failed to initialize scheduler\n";
        return false;
    }
    
    initialized_ = true;
    
    std::cout << "\n[+] Fabric Federation initialized: " << GetGPUCount() << " GPUs across " 
              << GetNodeCount() << " nodes\n";
    std::cout << "[+] Total VRAM: " << (GetTotalVRAM() / (1024ULL * 1024 * 1024)) << " GB\n\n";
    
    return true;
}

void FabricFederation::Shutdown() {
    if (!initialized_) return;
    
    if (scheduler_) scheduler_->Shutdown();
    if (peerAccessManager_) peerAccessManager_->Shutdown();
    
    std::lock_guard<std::mutex> lock(nodesMutex_);
    nodes_.clear();
    
    initialized_ = false;
}

bool FabricFederation::RegisterNode(std::unique_ptr<FabricNode> node) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    nodes_[node->GetId()] = std::move(node);
    return true;
}

void FabricFederation::UnregisterNode(uint32_t nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    nodes_.erase(nodeId);
}

FabricNode* FabricFederation::GetNode(uint32_t nodeId) {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    auto it = nodes_.find(nodeId);
    return (it != nodes_.end()) ? it->second.get() : nullptr;
}

std::vector<FabricNode*> FabricFederation::GetAllNodes() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    std::vector<FabricNode*> result;
    for (auto& [id, node] : nodes_) {
        result.push_back(node.get());
    }
    return result;
}

FabricNode* FabricFederation::GetLocalNode() {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    auto it = nodes_.find(0);
    return (it != nodes_.end()) ? it->second.get() : nullptr;
}

std::vector<GPUDeviceInfo*> FabricFederation::GetAllGPUs() {
    std::vector<GPUDeviceInfo*> all;
    std::lock_guard<std::mutex> lock(nodesMutex_);
    for (auto& [id, node] : nodes_) {
        auto gpus = node->GetGPUs();
        all.insert(all.end(), gpus.begin(), gpus.end());
    }
    return all;
}

GPUDeviceInfo* FabricFederation::GetGPU(uint32_t nodeId, uint32_t deviceId) {
    auto* node = GetNode(nodeId);
    return node ? node->GetGPU(deviceId) : nullptr;
}

uint64_t FabricFederation::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    uint64_t total = 0;
    for (const auto& [id, node] : nodes_) {
        total += node->GetTotalVRAM();
    }
    return total;
}

uint64_t FabricFederation::GetAvailableVRAM() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    uint64_t available = 0;
    for (const auto& [id, node] : nodes_) {
        available += node->GetAvailableVRAM();
    }
    return available;
}

uint64_t FabricFederation::GetTotalAllocated() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    uint64_t allocated = 0;
    for (const auto& [id, node] : nodes_) {
        allocated += node->GetTotalAllocated();
    }
    return allocated;
}

bool FabricFederation::MigrateAcrossNodes(uint32_t srcNodeId, uint64_t srcHandle,
                                           uint32_t dstNodeId, uint64_t dstHandle,
                                           size_t size) {
    auto* srcNode = GetNode(srcNodeId);
    auto* dstNode = GetNode(dstNodeId);
    if (!srcNode || !dstNode) return false;
    
    // Cross-node migration via network fabric
    // In real implementation: RDMA or TCP/IP transfer
    
    // For now, simulate
    std::cout << "[RawRamXD] Cross-node migration: " << srcNodeId << " -> " << dstNodeId
              << " (" << (size / (1024*1024)) << " MB)" << std::endl;
    
    return true;
}

uint32_t FabricFederation::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    return static_cast<uint32_t>(nodes_.size());
}

uint32_t FabricFederation::GetGPUCount() const {
    std::lock_guard<std::mutex> lock(nodesMutex_);
    uint32_t count = 0;
    for (const auto& [id, node] : nodes_) {
        count += static_cast<uint32_t>(node->GetGPUs().size());
    }
    return count;
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

bool RawRamXD_Federation_Initialize() {
    return FabricFederation::Instance().Initialize();
}

void RawRamXD_Federation_Shutdown() {
    FabricFederation::Instance().Shutdown();
}

uint32_t RawRamXD_Federation_GetNodeCount() {
    return FabricFederation::Instance().GetNodeCount();
}

uint32_t RawRamXD_Federation_GetGPUCount() {
    return FabricFederation::Instance().GetGPUCount();
}

bool RawRamXD_Node_GetInfo(uint32_t nodeId, wchar_t* name, size_t nameLen,
                            uint64_t* vramTotal, uint64_t* vramAvailable) {
    auto* node = FabricFederation::Instance().GetNode(nodeId);
    if (!node) return false;
    
    if (name) {
        swprintf_s(name, nameLen, L"Node %u", nodeId);
    }
    if (vramTotal) *vramTotal = node->GetTotalVRAM();
    if (vramAvailable) *vramAvailable = node->GetAvailableVRAM();
    return true;
}

bool RawRamXD_GPU_GetInfo(uint32_t gpuId, wchar_t* name, size_t nameLen,
                           GPUVendor* vendor, uint64_t* vramTotal,
                           uint64_t* vramAvailable) {
    // Search all nodes for GPU
    auto allGPUs = FabricFederation::Instance().GetAllGPUs();
    for (auto* gpu : allGPUs) {
        if (gpu->deviceId == gpuId) {
            if (name) wcscpy_s(name, nameLen, gpu->name);
            if (vendor) *vendor = gpu->vendor;
            if (vramTotal) *vramTotal = gpu->vramTotalBytes;
            if (vramAvailable) *vramAvailable = gpu->vramAvailableBytes;
            return true;
        }
    }
    return false;
}

uint64_t RawRamXD_Allocate(uint32_t preferredGPU, size_t size) {
    auto* local = FabricFederation::Instance().GetLocalNode();
    if (!local) return 0;
    
    // Use scheduler to select optimal GPU
    auto* scheduler = FabricFederation::Instance().GetScheduler();
    uint32_t selectedGPU = preferredGPU;
    
    if (scheduler) {
        std::vector<uint32_t> candidates;
        for (auto* gpu : local->GetGPUs()) {
            if (gpu->vramAvailableBytes >= size) {
                candidates.push_back(gpu->deviceId);
            }
        }
        if (!candidates.empty()) {
            selectedGPU = scheduler->SelectOptimalGPU(size, candidates);
        }
    }
    
    return local->AllocateVRAM(selectedGPU, size);
}

void RawRamXD_Free(uint64_t handle) {
    // In real implementation would track and free
}

bool RawRamXD_Migrate(uint64_t handle, uint32_t targetGPU) {
    return true;
}

bool RawRamXD_MigratePeerToPeer(uint64_t handle, uint32_t srcGPU, uint32_t dstGPU) {
    return true;
}

uint32_t RawRamXD_Scheduler_SelectGPU(size_t size) {
    auto* local = FabricFederation::Instance().GetLocalNode();
    if (!local) return 0;
    
    auto* scheduler = FabricFederation::Instance().GetScheduler();
    if (!scheduler) return 0;
    
    std::vector<uint32_t> candidates;
    for (auto* gpu : local->GetGPUs()) {
        if (gpu->vramAvailableBytes >= size) {
            candidates.push_back(gpu->deviceId);
        }
    }
    
    return scheduler->SelectOptimalGPU(size, candidates);
}

void RawRamXD_Scheduler_SetPolicy(int policy) {
    auto* scheduler = FabricFederation::Instance().GetScheduler();
    if (scheduler) {
        scheduler->SetPolicy(static_cast<MultiGPUScheduler::SchedulePolicy>(policy));
    }
}

uint64_t RawRamXD_Stats_GetTotalVRAM() {
    return FabricFederation::Instance().GetTotalVRAM();
}

uint64_t RawRamXD_Stats_GetAvailableVRAM() {
    return FabricFederation::Instance().GetAvailableVRAM();
}

uint64_t RawRamXD_Stats_GetTotalAllocated() {
    return FabricFederation::Instance().GetTotalAllocated();
}

} // extern "C"

} // namespace RawRamXD

// =============================================================================
// Main Test
// =============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "RawRamXD Phase 7B.2: Multi-GPU Fabric Federation\n";
    std::cout << "Unified Heterogeneous Memory Scheduler\n";
    std::cout << "========================================\n\n";
    
    if (!RawRamXD::RawRamXD_Federation_Initialize()) {
        std::cerr << "[!] Federation initialization failed\n";
        return 1;
    }
    
    std::cout << "\n[+] Federation initialized successfully\n";
    std::cout << "    Nodes: " << RawRamXD::RawRamXD_Federation_GetNodeCount() << "\n";
    std::cout << "    GPUs: " << RawRamXD::RawRamXD_Federation_GetGPUCount() << "\n";
    
    std::cout << "    Total VRAM: " << (RawRamXD::RawRamXD_Stats_GetTotalVRAM() / (1024ULL * 1024 * 1024)) << " GB\n";
    std::cout << "    Available VRAM: " << (RawRamXD::RawRamXD_Stats_GetAvailableVRAM() / (1024ULL * 1024 * 1024)) << " GB\n\n";
    
    // Test allocation
    std::cout << "[+] Testing allocation...\n";
    size_t testSize = 100 * 1024 * 1024;  // 100 MB
    uint32_t gpu = RawRamXD::RawRamXD_Scheduler_SelectGPU(testSize);
    uint64_t handle = RawRamXD::RawRamXD_Allocate(gpu, testSize);
    
    if (handle) {
        std::cout << "    Allocated " << (testSize / (1024*1024)) << " MB on GPU " << gpu << "\n";
    }
    
    // Print stats
    auto* scheduler = RawRamXD::FabricFederation::Instance().GetScheduler();
    if (scheduler) {
        auto stats = scheduler->GetStats();
        std::cout << "\n[+] Scheduler Stats:\n";
        std::cout << "    Migrations Initiated: " << stats.migrationsInitiated << "\n";
        std::cout << "    Migrations Completed: " << stats.migrationsCompleted << "\n";
        std::cout << "    P2P Transfers: " << stats.p2pTransfers << "\n";
        std::cout << "    Bridge Transfers: " << stats.bridgeTransfers << "\n";
    }
    
    std::cout << "\n[+] Shutting down...\n";
    RawRamXD::RawRamXD_Federation_Shutdown();
    
    std::cout << "\n========================================\n";
    std::cout << "Phase 7B.2 Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
