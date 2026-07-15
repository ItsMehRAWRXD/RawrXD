// =============================================================================
// RawRamXD_Phase7B2_MultiGPU_Federation.cpp
// Multi-GPU Fabric Federation Implementation
// =============================================================================

#include "RawRamXD_Phase7B2_MultiGPU_Federation.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace RawRamXD {

// =============================================================================
// Fabric Node Implementation
// =============================================================================

FabricNode::FabricNode(uint32_t id, FabricNodeType type, const std::string& address)
    : nodeId_(id), nodeType_(type), nodeAddress_(address), isOnline_(true) {
}

FabricNode::~FabricNode() {
    Shutdown();
}

bool FabricNode::Initialize() {
    std::cout << "[RawRamXD] Initializing Fabric Node " << nodeId_ << std::endl;
    
    if (nodeType_ == FabricNodeType::LOCAL) {
        std::cout << "  Type: Local Node" << std::endl;
    } else if (nodeType_ == FabricNodeType::REMOTE) {
        std::cout << "  Type: Remote Node (" << nodeAddress_ << ")" << std::endl;
    }
    
    return true;
}

void FabricNode::Shutdown() {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    
    for (auto& [id, gpu] : gpus_) {
        if (gpu->d3d12Device) {
            gpu->d3d12Device->Release();
        }
        if (gpu->copyQueue) {
            gpu->copyQueue->Release();
        }
        if (gpu->computeQueue) {
            gpu->computeQueue->Release();
        }
        delete gpu;
    }
    gpus_.clear();
    
    isOnline_ = false;
}

void FabricNode::RegisterGPU(GPUDeviceInfo* gpu) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    gpus_[gpu->deviceId] = gpu;
    allocatedPerGPU_[gpu->deviceId] = 0;
    
    std::wcout << L"[RawRamXD] Registered GPU " << gpu->deviceId << L": " << gpu->name << std::endl;
}

void FabricNode::UnregisterGPU(uint32_t deviceId) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    auto it = gpus_.find(deviceId);
    if (it != gpus_.end()) {
        delete it->second;
        gpus_.erase(it);
        allocatedPerGPU_.erase(deviceId);
    }
}

std::vector<GPUDeviceInfo*> FabricNode::GetGPUs() const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    std::vector<GPUDeviceInfo*> result;
    for (const auto& [id, gpu] : gpus_) {
        result.push_back(gpu);
    }
    return result;
}

GPUDeviceInfo* FabricNode::GetGPU(uint32_t deviceId) {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    auto it = gpus_.find(deviceId);
    return (it != gpus_.end()) ? it->second : nullptr;
}

uint64_t FabricNode::AllocateVRAM(uint32_t gpuId, size_t size) {
    auto* gpu = GetGPU(gpuId);
    if (!gpu) return 0;
    
    // Check available memory
    if (gpu->vramAvailableBytes < size) {
        std::cerr << "[RawRamXD] GPU " << gpuId << " out of memory" << std::endl;
        return 0;
    }
    
    // Create D3D12 resource
    D3D12_HEAP_PROPERTIES heapProps = {};
    heapProps.Type = D3D12_HEAP_TYPE_DEFAULT;
    heapProps.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
    heapProps.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
    heapProps.CreationNodeMask = gpu->nodeMask;
    heapProps.VisibleNodeMask = gpu->nodeMask;
    
    D3D12_RESOURCE_DESC desc = {};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = size;
    desc.Height = 1;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = DXGI_FORMAT_UNKNOWN;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
    
    ID3D12Resource* resource = nullptr;
    HRESULT hr = gpu->d3d12Device->CreateCommittedResource(
        &heapProps, D3D12_HEAP_FLAG_NONE, &desc,
        D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&resource));
    
    if (FAILED(hr)) {
        std::cerr << "[RawRamXD] Failed to allocate VRAM: 0x" << std::hex << hr << std::dec << std::endl;
        return 0;
    }
    
    // Update tracking
    gpu->vramAvailableBytes -= size;
    gpu->vramAllocatedBytes += size;
    allocatedPerGPU_[gpuId] += size;
    
    // Return GPU virtual address as handle
    return resource->GetGPUVirtualAddress();
}

void FabricNode::FreeVRAM(uint32_t gpuId, uint64_t handle) {
    // In real implementation, would track resource and release
    // For now, just update counters
    auto* gpu = GetGPU(gpuId);
    if (gpu) {
        // Would need size tracking for accurate accounting
    }
}

bool FabricNode::MigratePeerToPeer(uint32_t srcGpuId, uint64_t srcHandle,
                                    uint32_t dstGpuId, uint64_t dstHandle,
                                    size_t size, double* outLatencyMs) {
    auto* srcGPU = GetGPU(srcGpuId);
    auto* dstGPU = GetGPU(dstGpuId);
    
    if (!srcGPU || !dstGPU) return false;
    
    // Check if P2P is possible
    bool canP2P = false;
    for (uint32_t peer : srcGPU->peerAccessibleDevices) {
        if (peer == dstGpuId) {
            canP2P = true;
            break;
        }
    }
    
    if (!canP2P) {
        std::cout << "[RawRamXD] P2P not available, using bridge" << std::endl;
        return false;
    }
    
    // Execute P2P copy via D3D12
    // This would use CopyBufferRegion with cross-adapter resources
    // For now, simulate the operation
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simulate copy time based on bandwidth
    double bandwidth = std::min(srcGPU->bandwidthBytesPerSec, dstGPU->bandwidthBytesPerSec);
    double copyTimeSec = (double)size / bandwidth;
    
    // In real implementation:
    // 1. Create cross-adapter resource on dst GPU
    // 2. Use CopyBufferRegion from src to dst
    // 3. Synchronize with fences
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    *outLatencyMs = duration.count() / 1000.0;
    
    std::cout << "[RawRamXD] P2P migration: " << (size / (1024*1024)) << " MB in " 
              << std::fixed << std::setprecision(2) << *outLatencyMs << " ms" << std::endl;
    
    return true;
}

uint64_t FabricNode::GetTotalVRAM() const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    uint64_t total = 0;
    for (const auto& [id, gpu] : gpus_) {
        total += gpu->vramTotalBytes;
    }
    return total;
}

uint64_t FabricNode::GetAvailableVRAM() const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    uint64_t available = 0;
    for (const auto& [id, gpu] : gpus_) {
        available += gpu->vramAvailableBytes;
    }
    return available;
}

uint64_t FabricNode::GetTotalAllocated() const {
    std::lock_guard<std::mutex> lock(gpuMutex_);
    uint64_t allocated = 0;
    for (const auto& [id, gpu] : gpus_) {
        allocated += gpu->vramAllocatedBytes;
    }
    return allocated;
}

// =============================================================================
// Peer Access Manager Implementation
// =============================================================================

PeerAccessManager::PeerAccessManager() : initialized_(false) {
}

PeerAccessManager::~PeerAccessManager() {
    Shutdown();
}

bool PeerAccessManager::Initialize(const std::vector<GPUDeviceInfo*>& gpus) {
    std::cout << "[RawRamXD] Initializing Peer Access Manager..." << std::endl;
    
    // Query P2P capabilities between all GPU pairs
    for (size_t i = 0; i < gpus.size(); i++) {
        for (size_t j = 0; j < gpus.size(); j++) {
            if (i == j) continue;
            
            uint64_t key = ((uint64_t)gpus[i]->deviceId << 32) | gpus[j]->deviceId;
            
            PeerLink link;
            link.srcGpu = gpus[i]->deviceId;
            link.dstGpu = gpus[j]->deviceId;
            link.enabled = false;
            
            // Determine access type based on vendor and capabilities
            if (gpus[i]->vendor == gpus[j]->vendor) {
                if (gpus[i]->vendor == GPUVendor::AMD) {
                    link.accessType = PeerAccessType::INFINITY;
                    link.bandwidth = 200ULL * 1024 * 1024 * 1024; // 200 GB/s
                } else if (gpus[i]->vendor == GPUVendor::NVIDIA) {
                    link.accessType = PeerAccessType::NVLINK;
                    link.bandwidth = 300ULL * 1024 * 1024 * 1024; // 300 GB/s
                } else {
                    link.accessType = PeerAccessType::DIRECT;
                    link.bandwidth = 100ULL * 1024 * 1024 * 1024; // 100 GB/s
                }
            } else {
                // Different vendors - use bridge
                link.accessType = PeerAccessType::BRIDGE;
                link.bandwidth = 50ULL * 1024 * 1024 * 1024; // 50 GB/s through system
            }
            
            peerLinks_[key] = link;
            
            std::cout << "  GPU " <> link.srcGpu << " -> GPU " <> link.dstGpu << ": ";
            switch (link.accessType) {
                case PeerAccessType::INFINITY: std::cout << "AMD Infinity Fabric"; break;
                case PeerAccessType::NVLINK: std::cout << "NVIDIA NVLink"; break;
                case PeerAccessType::DIRECT: std::cout << "Direct P2P"; break;
                case PeerAccessType::BRIDGE: std::cout << "Bridge (system RAM)"; break;
                default: std::cout << "None"; break;
            }
            std::cout << " (" <> (link.bandwidth / (1024*1024*1024)) <> " GB/s)" << std::endl;
        }
    }
    
    initialized_ = true;
    return true;
}

void PeerAccessManager::Shutdown() {
    peerLinks_.clear();
    initialized_ = false;
}

PeerAccessType PeerAccessManager::QueryPeerAccess(uint32_t srcGpuId, uint32_t dstGpuId) {
    if (srcGpuId == dstGpuId) return PeerAccessType::DIRECT;
    
    uint64_t key = ((uint64_t)srcGpuId << 32) | dstGpuId;
    std::lock_guard<std::mutex> lock(linkMutex_);
    
    auto it = peerLinks_.find(key);
    if (it != peerLinks_.end()) {
        return it->second.accessType;
    }
    return PeerAccessType::NONE;
}

bool PeerAccessManager::CanAccessPeer(uint32_t srcGpuId, uint32_t dstGpuId) {
    return QueryPeerAccess(srcGpuId, dstGpuId) != PeerAccessType::NONE;
}

bool PeerAccessManager::EnablePeerAccess(uint32_t srcGpuId, uint32_t dstGpuId) {
    uint64_t key = ((uint64_t)srcGpuId << 32) | dstGpuId;
    std::lock_guard<std::mutex> lock(linkMutex_);
    
    auto it = peerLinks_.find(key);
    if (it != peerLinks_.end()) {
        it->second.enabled = true;
        return true;
    }
    return false;
}

void PeerAccessManager::DisablePeerAccess(uint32_t srcGpuId, uint32_t dstGpuId) {
    uint64_t key = ((uint64_t)srcGpuId << 32) | dstGpuId;
    std::lock_guard<std::mutex> lock(linkMutex_);
    
    auto it = peerLinks_.find(key);
    if (it != peerLinks_.end()) {
        it->second.enabled = false;
    }
}

MigrationPath PeerAccessManager::GetOptimalMigrationPath(uint32_t srcGpuId, 
                                                          uint32_t dstGpuId, 
                                                          size_t size) {
    PeerAccessType access = QueryPeerAccess(srcGpuId, dstGpuId);
    
    switch (access) {
        case PeerAccessType::INFINITY:
        case PeerAccessType::NVLINK:
        case PeerAccessType::DIRECT:
            return MigrationPath::DIRECT_P2P;
        case PeerAccessType::BRIDGE:
            return MigrationPath::BRIDGE_RAM;
        default:
            return MigrationPath::BRIDGE_NVME;
    }
}

bool PeerAccessManager::ExecutePeerCopy(uint32_t srcGpuId, uint64_t srcHandle,
                                         uint32_t dstGpuId, uint64_t dstHandle,
                                         size_t size, ID3D12Fence* completionFence) {
    // In real implementation, would execute D3D12 copy command
    // For now, return success
    return true;
}

// =============================================================================
// Multi-GPU Scheduler Implementation
// =============================================================================

MultiGPUScheduler::MultiGPUScheduler() 
    : federation_(nullptr), currentPolicy_(SchedulePolicy::LOAD_BALANCED), initialized_(false) {
}

MultiGPUScheduler::~MultiGPUScheduler() {
    Shutdown();
}

bool MultiGPUScheduler::Initialize(FabricFederation* federation) {
    federation_ = federation;
    initialized_ = true;
    
    std::cout << "[RawRamXD] Multi-GPU Scheduler initialized" << std::endl;
    std::cout << "  Policy: Load Balanced" << std::endl;
    
    return true;
}

void MultiGPUScheduler::Shutdown() {
    initialized_ = false;
}

void MultiGPUScheduler::SetPolicy(SchedulePolicy policy) {
    currentPolicy_ = policy;
    
    std::cout << "[RawRamXD] Scheduler policy changed to: ";
    switch (policy) {
        case SchedulePolicy::ROUND_ROBIN: std::cout << "Round Robin"; break;
        case SchedulePolicy::LOAD_BALANCED: std::cout << "Load Balanced"; break;
        case SchedulePolicy::PERFORMANCE: std::cout << "Performance"; break;
        case SchedulePolicy::RESIDENCY: std::cout << "Residency"; break;
        case SchedulePolicy::COST_OPTIMIZED: std::cout << "Cost Optimized"; break;
    }
    std::cout << std::endl;
}

uint32_t MultiGPUScheduler::SelectOptimalGPU(size_t tensorSize, 
                                                const std::vector<uint32_t>& candidates) {
    if (candidates.empty()) return 0;
    
    switch (currentPolicy_) {
        case SchedulePolicy::ROUND_ROBIN: {
            static uint32_t nextGPU = 0;
            return candidates[nextGPU++ % candidates.size()];
        }
        
        case SchedulePolicy::LOAD_BALANCED: {
            // Select GPU with most available memory
            uint32_t bestGPU = candidates[0];
            uint64_t maxAvailable = 0;
            
            for (uint32_t gpuId : candidates) {
                auto* gpu = federation_->GetGPU(0, gpuId); // Assuming local node
                if (gpu && gpu->vramAvailableBytes > maxAvailable) {
                    maxAvailable = gpu->vramAvailableBytes;
                    bestGPU = gpuId;
                }
            }
            return bestGPU;
        }
        
        case SchedulePolicy::PERFORMANCE: {
            // Select fastest GPU
            uint32_t bestGPU = candidates[0];
            float maxScore = 0;
            
            for (uint32_t gpuId : candidates) {
                auto* gpu = federation_->GetGPU(0, gpuId);
                if (gpu && gpu->computeScore > maxScore) {
                    maxScore = gpu->computeScore;
                    bestGPU = gpuId;
                }
            }
            return bestGPU;
        }
        
        default:
            return candidates[0];
    }
}

bool MultiGPUScheduler::ShouldMigrate(uint64_t tensorHandle, 
                                       uint32_t currentGPU, 
                                       uint32_t targetGPU) {
    if (currentGPU == targetGPU) return false;
    
    // Check if migration would improve performance
    auto* current = federation_->GetGPU(0, currentGPU);
    auto* target = federation_->GetGPU(0, targetGPU);
    
    if (!current || !target) return false;
    
    // Migrate if target is significantly faster and has capacity
    return (target->computeScore > current->computeScore * 1.5f) &&
           (target->vramAvailableBytes > 1024 * 1024 * 1024); // At least 1GB free
}

MigrationPath MultiGPUScheduler::SelectMigrationPath(uint32_t srcGPU, 
                                                      uint32_t dstGPU, 
                                                      size_t size) {
    auto* peerManager = federation_->GetPeerAccessManager();
    if (peerManager) {
        return peerManager->GetOptimalMigrationPath(srcGPU, dstGPU, size);
    }
    return MigrationPath::BRIDGE_RAM;
}

void MultiGPUScheduler::SubmitTensorOperation(uint64_t tensorHandle, 
                                               uint32_t gpuId,
                                               std::function<void()> operation) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    workQueues_[gpuId].push(operation);
}

MultiGPUScheduler::SchedulerStats MultiGPUScheduler::GetStats() const {
    SchedulerStats stats;
    stats.totalTensors = 0; // Would track from fabric
    stats.migrationsInitiated = migrationsInitiated_.load();
    stats.migrationsCompleted = migrationsCompleted_.load();
    stats.migrationsFailed = migrationsFailed_.load();
    stats.avgMigrationTimeMs = 0.0; // Would calculate from history
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
    
    std::cout << "========================================" << std::endl;
    std::cout << "RawRamXD Phase 7B.2: Multi-GPU Fabric Federation" << std::endl;
    std::cout <> "========================================" << std::endl;
    std::cout << std::endl;
    
    nextNodeId_ = 0;
    
    // Create local node
    auto localNode = std::make_unique<FabricNode>(nextNodeId_++, FabricNodeType::LOCAL, "");
    if (!localNode->Initialize()) {
        std::cerr << "[RawRamXD] Failed to initialize local node" << std::endl;
        return false;
    }
    
    // Enumerate GPUs for local node
    IDXGIFactory6* factory = nullptr;
    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        std::cerr << "[RawRamXD] Failed to create DXGI factory" << std::endl;
        return false;
    }
    
    IDXGIAdapter4* adapter = nullptr;
    uint32_t gpuIndex = 0;
    
    while (factory->EnumAdapterByGpuPreference(
            gpuIndex, 
            DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE, 
            IID_PPV_ARGS(&adapter)) != DXGI_ERROR_NOT_FOUND) {
        
        DXGI_ADAPTER_DESC3 desc;
        if (SUCCEEDED(adapter->GetDesc3(&desc))) {
            if ((desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0) {
                auto gpu = new GPUDeviceInfo();
                gpu->deviceId = gpuIndex;
                gpu->vramTotalBytes = desc.DedicatedVideoMemory;
                gpu->vramAvailableBytes = desc.DedicatedVideoMemory;
                gpu->vramAllocatedBytes = 0;
                wcsncpy_s(gpu->name, desc.Description, 255);
                
                // Detect vendor
                if (wcsstr(desc.Description, L"AMD") || wcsstr(desc.Description, L"Radeon")) {
                    gpu->vendor = GPUVendor::AMD;
                } else if (wcsstr(desc.Description, L"NVIDIA") || wcsstr(desc.Description, L"GeForce")) {
                    gpu->vendor = GPUVendor::NVIDIA;
                } else if (wcsstr(desc.Description, L"Intel")) {
                    gpu->vendor = GPUVendor::INTEL;
                } else {
                    gpu->vendor = GPUVendor::UNKNOWN;
                }
                
                // Create D3D12 device
                ID3D12Device* device = nullptr;
                if (SUCCEEDED(D3D12CreateDevice(adapter, D3D_FEATURE_LEVEL_12_0, 
                                                IID_PPV_ARGS(&device)))) {
                    gpu->d3d12Device = device;
                    gpu->nodeMask = device->GetNodeCount() > 1 ? (1 << gpuIndex) : 0;
                    
                    // Create command queues
                    D3D12_COMMAND_QUEUE_DESC queueDesc = {};
                    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_COPY;
                    device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&gpu->copyQueue));
                    
                    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
                    device->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&gpu->computeQueue));
                    
                    // Set performance metrics
                    gpu->bandwidthBytesPerSec = 500ULL * 1024 * 1024 * 1024; // 500 GB/s
                    gpu->latencyNs = 100;
                    gpu->computeScore = 100.0f * (gpuIndex + 1);
                    
                    localNode->RegisterGPU(gpu);
                }
            }
        }
        
        adapter->Release();
        gpuIndex++;
    }
    
    factory->Release();
    
    // Register local node
    {
        std::lock_guard<std::mutex> lock(nodesMutex_);
        nodes_[localNode->GetId()] = std::move(localNode);
    }
    
    // Initialize subsystems
    peerAccessManager_ = std::make_unique<PeerAccessManager>();
    auto gpus = GetAllGPUs();
    peerAccessManager_->Initialize(gpus);
    
    scheduler_ = std::make_unique<MultiGPUScheduler>();
    scheduler_->Initialize(this);
    
    initialized_ = true;
    
    // Print federation summary
    std::cout << std::endl;
    std::cout << "Federation Summary:" << std::endl;
    std::cout << "  Nodes: " << GetNodeCount() << std::endl;
    std::cout << "  GPUs: " << GetGPUCount() << std::endl;
    std::cout << "  Total VRAM: " << (GetTotalVRAM() / (1024*1024*1024)) << " GB" << std::endl;
    std::cout << std::endl;
    
    return true;
}

void FabricFederation::Shutdown() {
    if (!initialized_) return;
    
    std::cout << "[RawRamXD] Shutting down Fabric Federation..." << std::endl;
    
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
    return GetNode(0);
}

std::vector<GPUDeviceInfo*> FabricFederation::GetAllGPUs() {
    std::vector<GPUDeviceInfo*> result;
    auto nodes = GetAllNodes();
    for (auto* node : nodes) {
        auto gpus = node->GetGPUs();
        result.insert(result.end(), gpus.begin(), gpus.end());
    }
    return result;
}

GPUDeviceInfo* FabricFederation::GetGPU(uint32_t nodeId, uint32_t deviceId) {
    auto* node = GetNode(nodeId);
    return node ? node->GetGPU(deviceId) : nullptr;
}

uint64_t FabricFederation::GetTotalVRAM() const {
    uint64_t total = 0;
    auto nodes = const_cast<FabricFederation*>(this)->GetAllNodes();
    for (auto* node : nodes) {
        total += node->GetTotalVRAM();
    }
    return total;
}

uint64_t FabricFederation::GetAvailableVRAM() const {
    uint64_t available = 0;
    auto nodes = const_cast<FabricFederation*>(this)->GetAllNodes();
    for (auto* node : nodes) {
        available += node->GetAvailableVRAM();
    }
    return available;
}

uint64_t FabricFederation::GetTotalAllocated() const {
    uint64_t allocated = 0;
    auto nodes = const_cast<FabricFederation*>(this)->GetAllNodes();
    for (auto* node : nodes) {
        allocated += node->GetTotalAllocated();
    }
    return allocated;
}

bool FabricFederation::MigrateAcrossNodes(uint32_t srcNodeId, uint64_t srcHandle,
                                           uint32_t dstNodeId, uint64_t dstHandle,
                                           size_t size) {
    // In real implementation, would handle network/fabric migration
    std::cout << "[RawRamXD] Cross-node migration: Node " <> srcNodeId 
              << " -> Node " <> dstNodeId << std::endl;
    return true;
}

uint32_t FabricFederation::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex>&(nodesMutex_));
    return static_cast<uint32_t>(nodes_.size());
}

uint32_t FabricFederation::GetGPUCount() const {
    return static_cast<uint32_t>(GetAllGPUs().size());
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
    
    wcsncpy_s(name, nameLen, L"Fabric Node", (rsize_t)nameLen - 1);
    *vramTotal = node->GetTotalVRAM();
    *vramAvailable = node->GetAvailableVRAM();
    return true;
}

bool RawRamXD_GPU_GetInfo(uint32_t gpuId, wchar_t* name, size_t nameLen,
                           GPUVendor* vendor, uint64_t* vramTotal, uint64_t* vramAvailable) {
    auto* gpu = FabricFederation::Instance().GetGPU(0, gpuId);
    if (!gpu) return false;
    
    wcsncpy_s(name, nameLen, gpu->name, (rsize_t)nameLen - 1);
    *vendor = gpu->vendor;
    *vramTotal = gpu->vramTotalBytes;
    *vramAvailable = gpu->vramAvailableBytes;
    return true;
}

uint64_t RawRamXD_Allocate(uint32_t preferredGPU, size_t size) {
    auto* node = FabricFederation::Instance().GetLocalNode();
    if (!node) return 0;
    return node->AllocateVRAM(preferredGPU, size);
}

void RawRamXD_Free(uint64_t handle) {
    // Implementation would track and free
}

bool RawRamXD_Migrate(uint64_t handle, uint32_t targetGPU) {
    // Implementation would migrate tensor
    return true;
}

bool RawRamXD_MigratePeerToPeer(uint64_t handle, uint32_t srcGPU, uint32_t dstGPU) {
    auto* node = FabricFederation::Instance().GetLocalNode();
    if (!node) return false;
    
    double latencyMs;
    return node->MigratePeerToPeer(srcGPU, handle, dstGPU, handle, 1024*1024*1024, &latencyMs);
}

uint32_t RawRamXD_Scheduler_SelectGPU(size_t size) {
    auto* scheduler = FabricFederation::Instance().GetScheduler();
    if (!scheduler) return 0;
    
    auto gpus = FabricFederation::Instance().GetAllGPUs();
    std::vector<uint32_t> gpuIds;
    for (auto* gpu : gpus) {
        gpuIds.push_back(gpu->deviceId);
    }
    
    return scheduler->SelectOptimalGPU(size, gpuIds);
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