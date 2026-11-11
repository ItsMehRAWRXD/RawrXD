/*===========================================================================
 * numa_fabric.hpp
 *
 * VAL-031.2 NUMA-Aware Memory Fabric
 *
 * NUMA topology detection and affinity-aware tensor placement
 *
 * Key insight: Tensors requested by CPU core N should be pinned to
 * NUMA node N's local memory, avoiding cross-socket traffic
 *
 * Target: 2x memory latency reduction on Threadripper/EPYC systems
 *===========================================================================*/

#pragma once

#include "tensor_residency.hpp"
#include <vector>
#include <memory>
#include <windows.h>

namespace RawrXD {
namespace Memory {

// NUMA node information
struct NUMANodeInfo {
    uint32_t nodeId;
    uint64_t localMemory;      // Bytes of local memory
    uint32_t processorCount;   // Cores in this node
    std::vector<uint32_t> processorMask;  // Which logical processors
    bool isLocal;              // Is this the current node's memory?
};

// Processor to NUMA node mapping
struct ProcessorAffinity {
    uint32_t processorId;
    uint32_t numaNodeId;
    bool hyperthreading;         // Is this a logical or physical core?
};

// NUMA-aware residency manager
class NUMAFabric : public ResidencyManager {
public:
    NUMAFabric();
    ~NUMAFabric() override;

    // Initialize with NUMA topology detection
    bool InitializeNUMA();

    // Override Resolve to be NUMA-aware
    ResidencyLookup Resolve(uint64_t tensorId) override;
    ResidencyLookup ResolveAffinity(uint64_t tensorId, uint32_t processorId);

    // NUMA-specific operations
    bool AllocateLocal(uint64_t tensorId, uint64_t size, uint32_t preferredNode);
    bool MigrateToNode(uint64_t tensorId, uint32_t targetNode);
    bool PinToNode(uint64_t tensorId, uint32_t nodeId);

    // Topology queries
    uint32_t GetNUMANodeCount() const { return static_cast<uint32_t>(numaNodes_.size()); }
    uint32_t GetCurrentNUMANode() const;
    uint32_t GetNUMANodeForProcessor(uint32_t processorId) const;
    uint64_t GetLocalMemoryForNode(uint32_t nodeId) const;
    uint64_t GetAvailableMemoryForNode(uint32_t nodeId) const;

    // Performance optimization
    bool SetThreadAffinity(uint32_t numaNode);
    bool SetMemoryPreferredNode(uint32_t numaNode);

    // Statistics
    struct NUMAStats {
        uint64_t localAccesses;
        uint64_t remoteAccesses;
        uint64_t crossSocketMigrations;
        double localAccessRatio;
    };
    NUMAStats GetNUMAStats() const;

    // Print topology
    void PrintTopology() const;

private:
    std::vector<NUMANodeInfo> numaNodes_;
    std::vector<ProcessorAffinity> processorAffinity_;
    uint32_t currentNode_;

    // NUMA statistics
    mutable std::atomic<uint64_t> localAccesses_{0};
    mutable std::atomic<uint64_t> remoteAccesses_{0};
    mutable std::atomic<uint64_t> crossSocketMigrations_{0};

    // Internal helpers
    bool DetectNUMATopology();
    bool CreateNUMADomains();
    std::shared_ptr<MemoryDomain> GetDomainForNode(uint32_t nodeId);
    uint32_t FindBestLocalNode(uint64_t size);
};

// NUMA-aware tensor allocator
class NUMAAwareAllocator {
public:
    explicit NUMAAwareAllocator(NUMAFabric* fabric);
    ~NUMAAwareAllocator();

    // Allocate tensor on local NUMA node
    bool AllocateLocal(uint64_t tensorId, uint64_t size);

    // Allocate tensor on specific NUMA node
    bool AllocateOnNode(uint64_t tensorId, uint64_t size, uint32_t nodeId);

    // Allocate with first-touch policy (allocate where first accessed)
    bool AllocateFirstTouch(uint64_t tensorId, uint64_t size);

    // Get allocation statistics
    struct AllocStats {
        uint64_t totalAllocated;
        uint64_t localAllocations;
        uint64_t remoteAllocations;
        double localRatio;
    };
    AllocStats GetStats() const;

private:
    NUMAFabric* fabric_;
    std::atomic<uint64_t> totalAllocated_{0};
    std::atomic<uint64_t> localAllocations_{0};
    std::atomic<uint64_t> remoteAllocations_{0};
};

// C API exports
extern "C" {
    __declspec(dllexport) void* RawrXD_NUMAFabric_Create();
    __declspec(dllexport) int RawrXD_NUMAFabric_Initialize(void* handle);
    __declspec(dllexport) uint32_t RawrXD_NUMAFabric_GetNodeCount(void* handle);
    __declspec(dllexport) uint32_t RawrXD_NUMAFabric_GetCurrentNode(void* handle);
    __declspec(dllexport) int RawrXD_NUMAFabric_AllocateLocal(void* handle, uint64_t tensorId, uint64_t size);
    __declspec(dllexport) int RawrXD_NUMAFabric_SetThreadAffinity(void* handle, uint32_t nodeId);
    __declspec(dllexport) void RawrXD_NUMAFabric_PrintTopology(void* handle);
}

} // namespace Memory
} // namespace RawrXD
