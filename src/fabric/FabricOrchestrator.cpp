#include "FabricOrchestrator.h"
#include <Windows.h>

namespace RawrXD {
namespace Fabric {

// Global singleton
static FabricOrchestrator* g_orchestrator = nullptr;

FabricOrchestrator* GetFabricOrchestrator() {
    return g_orchestrator;
}

void SetFabricOrchestrator(FabricOrchestrator* orchestrator) {
    g_orchestrator = orchestrator;
}

// ============================================================================
// FabricOrchestrator Implementation
// ============================================================================

FabricOrchestrator::FabricOrchestrator()
    : nodeId_(0)
    , transport_(nullptr) {
}

FabricOrchestrator::~FabricOrchestrator() {
    Shutdown();
}

bool FabricOrchestrator::Initialize(uint32_t nodeId, FabricTransport* transport) {
    nodeId_ = nodeId;
    transport_ = transport;
    
    residencyTable_ = std::make_unique<ResidencyTable>();
    
    // Set up message handlers
    if (transport_) {
        transport_->SetMessageHandler(
            [this](const FabricMessage& msg, uint32_t fromNode) {
                OnFabricMessage(msg, fromNode);
            }
        );
        
        transport_->SetErrorHandler(
            [this](uint32_t nodeId, const char* error) {
                OnTransportError(nodeId, error);
            }
        );
    }
    
    SetFabricOrchestrator(this);
    return true;
}

void FabricOrchestrator::Shutdown() {
    if (g_orchestrator == this) {
        SetFabricOrchestrator(nullptr);
    }
    
    transport_ = nullptr;
    residencyTable_.reset();
}

void* FabricOrchestrator::ResolveTensor(uint64_t tensorId) {
    auto startTime = GetTimestampUs();
    
    // Check local storage first
    {
        std::shared_lock<std::shared_mutex> lock(localTensorsMutex_);
        auto it = localTensors_.find(tensorId);
        if (it != localTensors_.end()) {
            localHits_.fetch_add(1, std::memory_order_relaxed);
            
            // Update residency table
            residencyTable_->UpdateAccess(tensorId, startTime);
            
            // Update stats
            auto endTime = GetTimestampUs();
            totalLookupLatencyUs_.fetch_add(endTime - startTime, std::memory_order_relaxed);
            lookupCount_.fetch_add(1, std::memory_order_relaxed);
            
            return it->second;
        }
    }
    
    // Check residency table
    ResidencyEntry entry;
    if (residencyTable_->Lookup(tensorId, entry)) {
        if (entry.state == ResidencyState::RAM_HOT || 
            entry.state == ResidencyState::RAM_WARM) {
            // Should be local but pointer not found - inconsistency
            misses_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        
        if (entry.nodeId != 0 && entry.nodeId != nodeId_) {
            // Remote tensor - initiate lookup
            remoteLookups_.fetch_add(1, std::memory_order_relaxed);
            SendLookupRequest(tensorId, 255);  // High priority
            
            // For now, return nullptr (async will complete later)
            // In production, this would block or return a future
            return nullptr;
        }
    }
    
    // Not found anywhere
    misses_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
}

bool FabricOrchestrator::PrefetchTensor(uint64_t tensorId, uint32_t priority) {
    // Check if already resident
    ResidencyEntry entry;
    if (residencyTable_->Lookup(tensorId, entry)) {
        if (entry.state == ResidencyState::RAM_HOT || 
            entry.state == ResidencyState::RAM_WARM) {
            return true;  // Already resident
        }
    }
    
    prefetches_.fetch_add(1, std::memory_order_relaxed);
    
    // Send prefetch request
    SendLookupRequest(tensorId, priority);
    return true;
}

bool FabricOrchestrator::AcquireTensorLease(uint64_t tensorId, uint32_t durationMs) {
    std::unique_lock<std::shared_mutex> lock(leasesMutex_);
    
    // Check if already have lease
    auto it = activeLeases_.find(tensorId);
    if (it != activeLeases_.end()) {
        if (it->second.IsValid(GetTimestampUs())) {
            return true;  // Already have valid lease
        }
    }
    
    // Try to acquire from residency table
    TensorLease lease;
    if (!residencyTable_->AcquireLease(tensorId, durationMs, lease)) {
        return false;
    }
    
    activeLeases_[tensorId] = lease;
    return true;
}

void FabricOrchestrator::ReleaseTensorLease(uint64_t tensorId) {
    std::unique_lock<std::shared_mutex> lock(leasesMutex_);
    
    auto it = activeLeases_.find(tensorId);
    if (it != activeLeases_.end()) {
        residencyTable_->ReleaseLease(it->second);
        activeLeases_.erase(it);
    }
}

bool FabricOrchestrator::RegisterLocalTensor(uint64_t tensorId, void* ptr, uint32_t size) {
    // Add to local storage
    {
        std::unique_lock<std::shared_mutex> lock(localTensorsMutex_);
        localTensors_[tensorId] = ptr;
    }
    
    // Register in residency table
    ResidencyEntry entry;
    entry.tensorId = tensorId;
    entry.offset = reinterpret_cast<uint64_t>(ptr);
    entry.size = size;
    entry.nodeId = nodeId_;
    entry.state = ResidencyState::RAM_HOT;
    entry.version = 1;
    entry.lastAccess = GetTimestampUs();
    entry.accessCount = 0;
    
    return residencyTable_->RegisterTensor(tensorId, entry);
}

bool FabricOrchestrator::UnregisterTensor(uint64_t tensorId) {
    // Remove from local storage
    {
        std::unique_lock<std::shared_mutex> lock(localTensorsMutex_);
        localTensors_.erase(tensorId);
    }
    
    // Remove from residency table
    return residencyTable_->UnregisterTensor(tensorId);
}

bool FabricOrchestrator::MigrateTensor(uint64_t tensorId, uint32_t targetNodeId) {
    if (!transport_ || !transport_->IsConnected(targetNodeId)) {
        return false;
    }
    
    migrations_.fetch_add(1, std::memory_order_relaxed);
    
    // Send migrate request
    FabricMessage msg;
    msg.header.op = FabricOp::MIGRATE_REQUEST;
    msg.header.payloadSize = sizeof(MigrateRequest);
    msg.payload.migrateReq.tensorId = tensorId;
    msg.payload.migrateReq.targetNodeId = targetNodeId;
    msg.payload.migrateReq.priority = 128;
    
    return transport_->Send(targetNodeId, msg);
}

bool FabricOrchestrator::EvictTensor(uint64_t tensorId) {
    evictions_.fetch_add(1, std::memory_order_relaxed);
    return residencyTable_->UpdateState(tensorId, ResidencyState::EVICTING);
}

bool FabricOrchestrator::PromoteTensor(uint64_t tensorId) {
    return residencyTable_->UpdateState(tensorId, ResidencyState::RAM_HOT);
}

FabricOrchestrator::Stats FabricOrchestrator::GetStats() const {
    Stats stats;
    stats.localHits = localHits_.load(std::memory_order_relaxed);
    stats.remoteLookups = remoteLookups_.load(std::memory_order_relaxed);
    stats.remoteHits = remoteHits_.load(std::memory_order_relaxed);
    stats.misses = misses_.load(std::memory_order_relaxed);
    stats.prefetches = prefetches_.load(std::memory_order_relaxed);
    stats.migrations = migrations_.load(std::memory_order_relaxed);
    stats.evictions = evictions_.load(std::memory_order_relaxed);
    
    auto totalLatency = totalLookupLatencyUs_.load(std::memory_order_relaxed);
    auto count = lookupCount_.load(std::memory_order_relaxed);
    stats.avgLookupLatencyUs = count > 0 ? static_cast<double>(totalLatency) / count : 0.0;
    
    return stats;
}

bool FabricOrchestrator::IsHealthy() const {
    return transport_ != nullptr;
}

uint32_t FabricOrchestrator::GetConnectedNodeCount() const {
    if (!transport_) return 0;
    
    // This is a simplification - in production would track actual connections
    return 0;
}

void FabricOrchestrator::OnFabricMessage(const FabricMessage& msg, uint32_t fromNode) {
    switch (msg.header.op) {
        case FabricOp::LOOKUP_TENSOR:
            HandleLookupRequest(msg.payload.lookupReq, fromNode);
            break;
        case FabricOp::ACQUIRE_LEASE:
            HandleAcquireLeaseRequest(msg.payload.leaseReq, fromNode);
            break;
        case FabricOp::INVALIDATE:
            HandleInvalidate(msg.payload.invalidate);
            break;
        case FabricOp::MIGRATE_REQUEST:
            HandleMigrateRequest(msg.payload.migrateReq, fromNode);
            break;
        case FabricOp::HEARTBEAT:
            HandleHeartbeat(msg.payload.heartbeat);
            break;
        case FabricOp::FLOW_CONTROL:
            HandleFlowControl(msg.payload.flowControl);
            break;
        default:
            // Unknown op
            break;
    }
}

void FabricOrchestrator::OnTransportError(uint32_t nodeId, const char* error) {
    // Log error, potentially mark node as unhealthy
    // In production, would trigger reconnection or failover
}

void FabricOrchestrator::HandleLookupRequest(const LookupTensorRequest& req, uint32_t fromNode) {
    ResidencyEntry entry;
    bool found = residencyTable_->Lookup(req.tensorId, entry);
    
    // Send response
    FabricMessage resp;
    resp.header.op = FabricOp::LOOKUP_TENSOR;
    resp.header.payloadSize = sizeof(LookupTensorResponse);
    resp.payload.lookupResp.tensorId = req.tensorId;
    
    if (found && entry.nodeId == nodeId_) {
        resp.payload.lookupResp.status = 0;  // FOUND
        resp.payload.lookupResp.offset = entry.offset;
        resp.payload.lookupResp.size = entry.size;
        resp.payload.lookupResp.nodeId = nodeId_;
        resp.payload.lookupResp.residency = static_cast<uint32_t>(entry.state);
        resp.payload.lookupResp.version = entry.version;
        resp.payload.lookupResp.latencyUs = 10;  // Local access
    } else {
        resp.payload.lookupResp.status = 1;  // NOT_FOUND
    }
    
    if (transport_) {
        transport_->Send(fromNode, resp);
    }
}

void FabricOrchestrator::HandleLookupResponse(const LookupTensorResponse& resp) {
    if (resp.status == 0) {
        remoteHits_.fetch_add(1, std::memory_order_relaxed);
        
        // Update residency table with remote location
        ResidencyEntry entry;
        entry.tensorId = resp.tensorId;
        entry.offset = resp.offset;
        entry.size = resp.size;
        entry.nodeId = resp.nodeId;
        entry.state = static_cast<ResidencyState>(resp.residency);
        entry.version = resp.version;
        entry.lastAccess = GetTimestampUs();
        
        residencyTable_->RegisterTensor(resp.tensorId, entry);
    }
}

void FabricOrchestrator::HandleAcquireLeaseRequest(const AcquireLeaseRequest& req, uint32_t fromNode) {
    // Try to acquire lease locally
    TensorLease lease;
    bool success = residencyTable_->AcquireLease(req.tensorId, req.durationMs, lease);
    
    // Send response
    FabricMessage resp;
    resp.header.op = FabricOp::ACQUIRE_LEASE;
    resp.header.payloadSize = sizeof(AcquireLeaseResponse);
    resp.payload.leaseResp.tensorId = req.tensorId;
    resp.payload.leaseResp.version = lease.version;
    resp.payload.leaseResp.expiryUs = lease.expiryUs;
    resp.payload.leaseResp.status = success ? 0 : 1;
    
    if (transport_) {
        transport_->Send(fromNode, resp);
    }
}

void FabricOrchestrator::HandleAcquireLeaseResponse(const AcquireLeaseResponse& resp) {
    // Store lease in active leases
    if (resp.status == 0) {
        std::unique_lock<std::shared_mutex> lock(leasesMutex_);
        
        TensorLease lease;
        lease.tensorId = resp.tensorId;
        lease.version = resp.version;
        lease.expiryUs = resp.expiryUs;
        lease.ownerNode = nodeId_;
        
        activeLeases_[resp.tensorId] = lease;
    }
}

void FabricOrchestrator::HandleInvalidate(const InvalidateMessage& msg) {
    // Invalidate our cached entry
    ResidencyEntry entry;
    if (residencyTable_->Lookup(msg.tensorId, entry)) {
        if (entry.version == msg.version) {
            residencyTable_->UpdateState(msg.tensorId, ResidencyState::INVALID);
        }
    }
}

void FabricOrchestrator::HandleMigrateRequest(const MigrateRequest& req, uint32_t fromNode) {
    // Check if we own this tensor
    ResidencyEntry entry;
    if (!residencyTable_->Lookup(req.tensorId, entry) || entry.nodeId != nodeId_) {
        // Send rejection
        FabricMessage resp;
        resp.header.op = FabricOp::MIGRATE_REQUEST;
        resp.header.payloadSize = sizeof(MigrateResponse);
        resp.payload.migrateResp.tensorId = req.tensorId;
        resp.payload.migrateResp.status = 1;  // REJECTED
        
        if (transport_) {
            transport_->Send(fromNode, resp);
        }
        return;
    }
    
    // Mark as migrating
    residencyTable_->UpdateState(req.tensorId, ResidencyState::EVICTING);
    
    // In production: actually transfer data here
    
    // Send acceptance
    FabricMessage resp;
    resp.header.op = FabricOp::MIGRATE_REQUEST;
    resp.header.payloadSize = sizeof(MigrateResponse);
    resp.payload.migrateResp.tensorId = req.tensorId;
    resp.payload.migrateResp.status = 0;  // ACCEPTED
    
    if (transport_) {
        transport_->Send(fromNode, resp);
    }
}

void FabricOrchestrator::HandleHeartbeat(const HeartbeatMessage& msg) {
    // Update node health tracking
    // In production: would track last seen, detect failures
}

void FabricOrchestrator::HandleFlowControl(const FlowControlMessage& msg) {
    // Adjust sending rate based on backpressure
    // In production: would throttle prefetches
}

uint64_t FabricOrchestrator::GetTimestampUs() const {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart;
}

void FabricOrchestrator::SendLookupRequest(uint64_t tensorId, uint32_t priority) {
    if (!transport_) return;
    
    // Broadcast to all connected nodes
    FabricMessage msg;
    msg.header.op = FabricOp::LOOKUP_TENSOR;
    msg.header.payloadSize = sizeof(LookupTensorRequest);
    msg.payload.lookupReq.tensorId = tensorId;
    msg.payload.lookupReq.priority = priority;
    
    transport_->Broadcast(msg);
}

} // namespace Fabric
} // namespace RawrXD
