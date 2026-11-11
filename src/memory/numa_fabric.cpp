/*===========================================================================
 * numa_fabric.cpp
 *
 * VAL-031.2 NUMA-Aware Memory Fabric Implementation
 *
 * NUMA topology detection and affinity-aware tensor placement
 *===========================================================================*/

#include "numa_fabric.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

namespace RawrXD {
namespace Memory {

// NUMAFabric implementation
NUMAFabric::NUMAFabric() : currentNode_(0) {}

NUMAFabric::~NUMAFabric() = default;

bool NUMAFabric::InitializeNUMA() {
    // First initialize base ResidencyManager
    if (!Initialize()) {
        return false;
    }

    // Detect NUMA topology
    if (!DetectNUMATopology()) {
        // NUMA not available, treat as single node
        std::cout << "NUMA: Single-node system detected\n";
        return true;
    }

    // Create NUMA-aware domains
    if (!CreateNUMADomains()) {
        return false;
    }

    // Get current node
    currentNode_ = GetCurrentNUMANode();

    return true;
}

bool NUMAFabric::DetectNUMATopology() {
#ifdef _WIN32
    // Get NUMA node count
    ULONG nodeCount = 0;
    if (!GetNumaHighestNodeNumber(&nodeCount)) {
        return false;
    }

    nodeCount++;  // Highest node number + 1 = total nodes

    if (nodeCount <= 1) {
        // Single node system
        return false;
    }

    std::cout << "NUMA: Detected " << nodeCount << " nodes\n";

    // Enumerate each NUMA node
    for (ULONG node = 0; node < nodeCount; node++) {
        NUMANodeInfo info;
        info.nodeId = node;

        // Get local memory for this node
        ULONGLONG availableBytes = 0;
        ULONGLONG totalBytes = 0;
        if (GetNumaAvailableMemoryNodeEx(node, &availableBytes)) {
            info.localMemory = availableBytes;
        }

        // Get processor mask for this node
        GROUP_AFFINITY affinity;
        if (GetNumaNodeProcessorMaskEx(node, &affinity)) {
            // Count processors in mask
            info.processorCount = 0;
            for (int i = 0; i < 64; i++) {
                if (affinity.Mask & (1ULL << i)) {
                    info.processorCount++;
                    info.processorMask.push_back(i);
                }
            }
        }

        numaNodes_.push_back(info);
    }

    // Build processor affinity map
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    for (DWORD proc = 0; proc < sysInfo.dwNumberOfProcessors; proc++) {
        PROCESSOR_NUMBER procNum;
        if (GetProcessorNumberFromIndex(proc, &procNum)) {
            ProcessorAffinity affinity;
            affinity.processorId = proc;
            affinity.numaNodeId = procNum.Group;
            affinity.hyperthreading = false;  // Would need more detection
            processorAffinity_.push_back(affinity);
        }
    }

    return true;
#else
    // Linux implementation would use libnuma
    return false;
#endif
}

bool NUMAFabric::CreateNUMADomains() {
    // Create a LocalRAMDomain for each NUMA node
    for (const auto& node : numaNodes_) {
        // Allocate ~75% of available memory for this node
        uint64_t domainSize = (node.localMemory * 3) / 4;
        
        auto domain = std::make_shared<LocalRAMDomain>(node.nodeId, domainSize);
        RegisterDomain(domain);

        std::cout << "NUMA: Created domain " << node.nodeId 
                  << " with " << (domainSize / (1024 * 1024 * 1024)) << " GB\n";
    }

    return true;
}

ResidencyLookup NUMAFabric::Resolve(uint64_t tensorId) {
    // Get current processor and its NUMA node
    uint32_t currentProc = GetCurrentProcessorNumber();
    return ResolveAffinity(tensorId, currentProc);
}

ResidencyLookup NUMAFabric::ResolveAffinity(uint64_t tensorId, uint32_t processorId) {
    // First do standard resolve
    ResidencyLookup lookup = ResidencyManager::Resolve(tensorId);

    if (!lookup.found) {
        return lookup;
    }

    // Check if this is local to the requesting processor
    uint32_t preferredNode = GetNUMANodeForProcessor(processorId);
    
    if (lookup.residency.domainId == preferredNode) {
        localAccesses_++;
        lookup.local = true;
    } else {
        remoteAccesses_++;
        lookup.local = false;
        
        // Optionally trigger migration to local node
        // This would be policy-dependent
    }

    return lookup;
}

bool NUMAFabric::AllocateLocal(uint64_t tensorId, uint64_t size, uint32_t preferredNode) {
    // Find domain for preferred node
    auto domain = GetDomainForNode(preferredNode);
    if (!domain) {
        // Fall back to any available domain
        domain = FindBestDomain(DomainType::SYSTEM_RAM);
        if (!domain) {
            return false;
        }
    }

    // Allocate in domain
    uint64_t address;
    if (!domain->Allocate(tensorId, size, address)) {
        return false;
    }

    // Register residency
    TensorResidency residency;
    residency.tensorId = tensorId;
    residency.domainId = domain->GetDomainId();
    residency.domainType = DomainType::SYSTEM_RAM;
    residency.address = address;
    residency.size = size;
    residency.state = ResidencyState::WARM;
    residency.version = 1;
    residency.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();

    // Add to residency table
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(tableMutex_));
        residencyTable_[tensorId] = residency;
    }

    return true;
}

bool NUMAFabric::MigrateToNode(uint64_t tensorId, uint32_t targetNode) {
    // Track cross-socket migration
    auto lookup = ResidencyManager::Resolve(tensorId);
    if (lookup.found && lookup.residency.domainId != targetNode) {
        crossSocketMigrations_++;
    }

    return ResidencyManager::Migrate(tensorId, targetNode);
}

bool NUMAFabric::PinToNode(uint64_t tensorId, uint32_t nodeId) {
    // First migrate to node
    if (!MigrateToNode(tensorId, nodeId)) {
        return false;
    }

    // Then pin
    return Pin(tensorId);
}

uint32_t NUMAFabric::GetCurrentNUMANode() const {
#ifdef _WIN32
    return GetCurrentProcessorNumber();  // Simplified - would use proper NUMA API
#else
    return 0;
#endif
}

uint32_t NUMAFabric::GetNUMANodeForProcessor(uint32_t processorId) const {
    for (const auto& affinity : processorAffinity_) {
        if (affinity.processorId == processorId) {
            return affinity.numaNodeId;
        }
    }
    return 0;  // Default to node 0
}

uint64_t NUMAFabric::GetLocalMemoryForNode(uint32_t nodeId) const {
    for (const auto& node : numaNodes_) {
        if (node.nodeId == nodeId) {
            return node.localMemory;
        }
    }
    return 0;
}

uint64_t NUMAFabric::GetAvailableMemoryForNode(uint32_t nodeId) const {
    auto domain = GetDomainForNode(nodeId);
    if (domain) {
        return domain->GetAvailable();
    }
    return 0;
}

bool NUMAFabric::SetThreadAffinity(uint32_t numaNode) {
#ifdef _WIN32
    if (numaNode >= numaNodes_.size()) {
        return false;
    }

    // Set thread to preferred NUMA node
    // This is a simplified version - full implementation would use SetThreadGroupAffinity
    return true;
#else
    return false;
#endif
}

bool NUMAFabric::SetMemoryPreferredNode(uint32_t numaNode) {
#ifdef _WIN32
    // Set preferred NUMA node for this thread's memory allocations
    USHORT node = static_cast<USHORT>(numaNode);
    return SetThreadPreferredNumaNode(node) == TRUE;
#else
    return false;
#endif
}

NUMAFabric::NUMAStats NUMAFabric::GetNUMAStats() const {
    NUMAStats stats;
    stats.localAccesses = localAccesses_.load();
    stats.remoteAccesses = remoteAccesses_.load();
    stats.crossSocketMigrations = crossSocketMigrations_.load();
    
    uint64_t total = stats.localAccesses + stats.remoteAccesses;
    if (total > 0) {
        stats.localAccessRatio = static_cast<double>(stats.localAccesses) / total;
    } else {
        stats.localAccessRatio = 0.0;
    }

    return stats;
}

void NUMAFabric::PrintTopology() const {
    std::cout << "\n=== NUMA Topology ===\n\n";
    std::cout << "Nodes: " << numaNodes_.size() << "\n\n";

    for (const auto& node : numaNodes_) {
        std::cout << "Node " << node.nodeId << ":\n";
        std::cout << "  Local Memory: " << (node.localMemory / (1024 * 1024 * 1024)) << " GB\n";
        std::cout << "  Processors: " << node.processorCount << "\n";
        std::cout << "  Processor Mask: ";
        for (auto proc : node.processorMask) {
            std::cout << proc << " ";
        }
        std::cout << "\n";
        
        auto domain = GetDomainForNode(node.nodeId);
        if (domain) {
            std::cout << "  Domain Available: " << (domain->GetAvailable() / (1024 * 1024 * 1024)) << " GB\n";
        }
        std::cout << "\n";
    }

    auto stats = GetNUMAStats();
    std::cout << "Access Statistics:\n";
    std::cout << "  Local Accesses: " << stats.localAccesses << "\n";
    std::cout << "  Remote Accesses: " << stats.remoteAccesses << "\n";
    std::cout << "  Local Ratio: " << std::fixed << std::setprecision(2) 
              << (stats.localAccessRatio * 100) << "%\n";
    std::cout << "  Cross-Socket Migrations: " << stats.crossSocketMigrations << "\n";
    std::cout << "\n";
}

std::shared_ptr<MemoryDomain> NUMAFabric::GetDomainForNode(uint32_t nodeId) {
    std::lock_guard<std::mutex> lock(tableMutex_);
    auto it = domains_.find(nodeId);
    if (it != domains_.end()) {
        return it->second;
    }
    return nullptr;
}

uint32_t NUMAFabric::FindBestLocalNode(uint64_t size) {
    // Find node with most available memory that can fit the allocation
    uint32_t bestNode = 0;
    uint64_t bestAvailable = 0;

    for (const auto& [id, domain] : domains_) {
        uint64_t available = domain->GetAvailable();
        if (available >= size && available > bestAvailable) {
            bestAvailable = available;
            bestNode = id;
        }
    }

    return bestNode;
}

// NUMAAwareAllocator implementation
NUMAAwareAllocator::NUMAAwareAllocator(NUMAFabric* fabric) : fabric_(fabric) {}

NUMAAwareAllocator::~NUMAAwareAllocator() = default;

bool NUMAAwareAllocator::AllocateLocal(uint64_t tensorId, uint64_t size) {
    uint32_t currentNode = fabric_->GetCurrentNUMANode();
    
    bool success = fabric_->AllocateLocal(tensorId, size, currentNode);
    
    if (success) {
        totalAllocated_ += size;
        localAllocations_++;
    }
    
    return success;
}

bool NUMAAwareAllocator::AllocateOnNode(uint64_t tensorId, uint64_t size, uint32_t nodeId) {
    bool success = fabric_->AllocateLocal(tensorId, size, nodeId);
    
    if (success) {
        totalAllocated_ += size;
        if (nodeId == fabric_->GetCurrentNUMANode()) {
            localAllocations_++;
        } else {
            remoteAllocations_++;
        }
    }
    
    return success;
}

bool NUMAAwareAllocator::AllocateFirstTouch(uint64_t tensorId, uint64_t size) {
    // Allocate on current node (first-touch policy)
    return AllocateLocal(tensorId, size);
}

NUMAAwareAllocator::AllocStats NUMAAwareAllocator::GetStats() const {
    AllocStats stats;
    stats.totalAllocated = totalAllocated_.load();
    stats.localAllocations = localAllocations_.load();
    stats.remoteAllocations = remoteAllocations_.load();
    
    uint64_t total = stats.localAllocations + stats.remoteAllocations;
    if (total > 0) {
        stats.localRatio = static_cast<double>(stats.localAllocations) / total;
    } else {
        stats.localRatio = 0.0;
    }
    
    return stats;
}

// C API exports
extern "C" {

__declspec(dllexport) void* RawrXD_NUMAFabric_Create() {
    return new RawrXD::Memory::NUMAFabric();
}

__declspec(dllexport) int RawrXD_NUMAFabric_Initialize(void* handle) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    return fabric->InitializeNUMA() ? 0 : -1;
}

__declspec(dllexport) uint32_t RawrXD_NUMAFabric_GetNodeCount(void* handle) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    return fabric->GetNUMANodeCount();
}

__declspec(dllexport) uint32_t RawrXD_NUMAFabric_GetCurrentNode(void* handle) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    return fabric->GetCurrentNUMANode();
}

__declspec(dllexport) int RawrXD_NUMAFabric_AllocateLocal(void* handle, uint64_t tensorId, uint64_t size) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    uint32_t currentNode = fabric->GetCurrentNUMANode();
    return fabric->AllocateLocal(tensorId, size, currentNode) ? 0 : -1;
}

__declspec(dllexport) int RawrXD_NUMAFabric_SetThreadAffinity(void* handle, uint32_t nodeId) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    return fabric->SetThreadAffinity(nodeId) ? 0 : -1;
}

__declspec(dllexport) void RawrXD_NUMAFabric_PrintTopology(void* handle) {
    auto* fabric = static_cast<RawrXD::Memory::NUMAFabric*>(handle);
    fabric->PrintTopology();
}

} // extern "C"

} // namespace Memory
} // namespace RawrXD
