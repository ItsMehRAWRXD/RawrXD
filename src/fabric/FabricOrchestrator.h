#pragma once

#include "FabricTransport.h"
#include "TensorResidency.h"
#include "FabricMessages.h"
#include <memory>
#include <atomic>
#include <thread>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Fabric Orchestrator - Central Memory Fabric Controller
// 
// Integrates with WeightPager to provide distributed tensor resolution.
// The WeightPager no longer cares WHERE the tensor is - only that it gets
// a valid pointer.
// ============================================================================

class FabricOrchestrator {
public:
    FabricOrchestrator();
    ~FabricOrchestrator();
    
    // Initialization
    bool Initialize(uint32_t nodeId, FabricTransport* transport);
    void Shutdown();
    
    // Tensor Resolution (called by WeightPager)
    // Returns pointer to tensor data, or nullptr if not available
    void* ResolveTensor(uint64_t tensorId);
    
    // Async prefetch (non-blocking)
    bool PrefetchTensor(uint64_t tensorId, uint32_t priority);
    
    // Lease Management
    bool AcquireTensorLease(uint64_t tensorId, uint32_t durationMs);
    void ReleaseTensorLease(uint64_t tensorId);
    
    // Registration (called during model load)
    bool RegisterLocalTensor(uint64_t tensorId, void* ptr, uint32_t size);
    bool UnregisterTensor(uint64_t tensorId);
    
    // Residency Management
    bool MigrateTensor(uint64_t tensorId, uint32_t targetNodeId);
    bool EvictTensor(uint64_t tensorId);
    bool PromoteTensor(uint64_t tensorId);
    
    // Statistics
    struct Stats {
        uint64_t localHits;
        uint64_t remoteLookups;
        uint64_t remoteHits;
        uint64_t misses;
        uint64_t prefetches;
        uint64_t migrations;
        uint64_t evictions;
        double avgLookupLatencyUs;
    };
    Stats GetStats() const;
    
    // Health
    bool IsHealthy() const;
    uint32_t GetConnectedNodeCount() const;
    
private:
    uint32_t nodeId_;
    FabricTransport* transport_;
    std::unique_ptr<ResidencyTable> residencyTable_;
    
    // Local tensor storage (tensorId -> local pointer)
    std::unordered_map<uint64_t, void*> localTensors_;
    mutable std::shared_mutex localTensorsMutex_;
    
    // Active leases
    std::unordered_map<uint64_t, TensorLease> activeLeases_;
    mutable std::shared_mutex leasesMutex_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> localHits_{0};
    alignas(64) std::atomic<uint64_t> remoteLookups_{0};
    alignas(64) std::atomic<uint64_t> remoteHits_{0};
    alignas(64) std::atomic<uint64_t> misses_{0};
    alignas(64) std::atomic<uint64_t> prefetches_{0};
    alignas(64) std::atomic<uint64_t> migrations_{0};
    alignas(64) std::atomic<uint64_t> evictions_{0};
    alignas(64) std::atomic<uint64_t> totalLookupLatencyUs_{0};
    alignas(64) std::atomic<uint64_t> lookupCount_{0};
    
    // Message handling
    void OnFabricMessage(const FabricMessage& msg, uint32_t fromNode);
    void OnTransportError(uint32_t nodeId, const char* error);
    
    // Request handlers
    void HandleLookupRequest(const LookupTensorRequest& req, uint32_t fromNode);
    void HandleLookupResponse(const LookupTensorResponse& resp);
    void HandleAcquireLeaseRequest(const AcquireLeaseRequest& req, uint32_t fromNode);
    void HandleAcquireLeaseResponse(const AcquireLeaseResponse& resp);
    void HandleInvalidate(const InvalidateMessage& msg);
    void HandleMigrateRequest(const MigrateRequest& req, uint32_t fromNode);
    void HandleHeartbeat(const HeartbeatMessage& msg);
    void HandleFlowControl(const FlowControlMessage& msg);
    
    // Helper
    uint64_t GetTimestampUs() const;
    void SendLookupRequest(uint64_t tensorId, uint32_t priority);
};

// Global accessor (singleton pattern for integration)
FabricOrchestrator* GetFabricOrchestrator();
void SetFabricOrchestrator(FabricOrchestrator* orchestrator);

} // namespace Fabric
} // namespace RawrXD
