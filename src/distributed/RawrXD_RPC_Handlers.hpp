// RawrXD RPC Handler Framework - Layer 2.0
// Dispatch registry and handler definitions for distributed runtime
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "RawrXD_RPC.hpp"
#include "SovereignNodeDiscovery.hpp"
#include <functional>
#include <unordered_map>
#include <chrono>
#include <atomic>

// Forward declaration for InferenceRuntime (in global namespace)
namespace RawrXD {
namespace Distributed {
    class InferenceRuntime;
}
}

namespace RawrXD {
namespace RPC {

// ============================================================================
// Forward Declarations
// ============================================================================

class RPCHandlerRegistry;
struct NodeContext;
struct HandlerResult;

// Import types from Distributed namespace
using RawrXD::Distributed::RawrPacket;
using RawrXD::Distributed::RawrCommand;
using RawrXD::Distributed::HeartbeatPayload;
using RawrXD::Distributed::NodeDiscoverPayload;
using RawrXD::Distributed::PanicAbortPayload;
using RawrXD::Distributed::BarrierPayload;
using RawrXD::Distributed::InferenceRequestPayload;
using RawrXD::Distributed::KVCacheSyncPayload;

// ============================================================================
// Handler Types
// ============================================================================

using HandlerFunction = std::function<HandlerResult(const RawrXD::Distributed::RawrPacket&, NodeContext&)>;

enum class HandlerStatus {
    SUCCESS = 0,           // Handler executed successfully
    ERROR_INVALID_PACKET,  // Packet malformed or corrupted
    ERROR_UNKNOWN_COMMAND, // Command not registered
    ERROR_NODE_UNHEALTHY,  // Target node not healthy
    ERROR_TIMEOUT,         // Handler timed out
    ERROR_INTERNAL         // Internal handler error
};

struct HandlerResult {
    HandlerStatus status;
    std::string error_message;
    std::chrono::microseconds processing_time;
    
    static HandlerResult Success(std::chrono::microseconds time = std::chrono::microseconds(0)) {
        return {HandlerStatus::SUCCESS, "", time};
    }
    
    static HandlerResult Error(HandlerStatus s, const std::string& msg) {
        return {s, msg, std::chrono::microseconds(0)};
    }
};

// ============================================================================
// Node Context
// ============================================================================

struct NodeContext {
    // Node identity
    std::string self_node_id;
    std::string peer_node_id;
    
    // Discovery layer reference
    Sovereign::Distributed::NodeDiscovery* discovery;
    
    // Timing
    std::chrono::steady_clock::time_point request_time;
    std::chrono::steady_clock::time_point response_time;
    
    // Connection metadata
    uint32_t connection_id;
    bool is_authorized;
    
    // Response builder helper
    RawrXD::Distributed::RawrPacket BuildResponse(RawrXD::Distributed::RawrCommand cmd) const {
        return RawrXD::Distributed::build_packet(
            static_cast<uint32_t>(cmd), 0, 0, 0);
    }
};

// ============================================================================
// Handler Registry
// ============================================================================

class RPCHandlerRegistry {
public:
    RPCHandlerRegistry();
    ~RPCHandlerRegistry();
    
    // Non-copyable, non-movable
    RPCHandlerRegistry(const RPCHandlerRegistry&) = delete;
    RPCHandlerRegistry& operator=(const RPCHandlerRegistry&) = delete;
    
    // Registration
    bool Register(RawrXD::Distributed::RawrCommand command, HandlerFunction handler);
    bool Unregister(RawrXD::Distributed::RawrCommand command);
    bool IsRegistered(RawrXD::Distributed::RawrCommand command) const;
    
    // Dispatch
    HandlerResult Dispatch(const RawrXD::Distributed::RawrPacket& packet, NodeContext& context);
    
    // Statistics
    size_t GetRegisteredCount() const;
    uint64_t GetDispatchCount() const { return dispatch_count_.load(); }
    uint64_t GetErrorCount() const { return error_count_.load(); }
    void ResetStatistics();
    
    // Batch registration helpers
    void RegisterCoreHandlers();      // Batch 2.1
    void RegisterInferenceHandlers(); // Batch 2.2
    void RegisterTensorHandlers();    // Batch 2.3
    void RegisterAdminHandlers();     // Batch 2.4

private:
    std::unordered_map<uint16_t, HandlerFunction> handlers_;
    mutable std::mutex mutex_;
    
    std::atomic<uint64_t> dispatch_count_{0};
    std::atomic<uint64_t> error_count_{0};
};

// ============================================================================
// Batch 2.1: Core Communication Handlers
// ============================================================================

// CMD_HEARTBEAT_PING
HandlerResult HandleHeartbeatPing(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// CMD_HEARTBEAT_PONG
HandlerResult HandleHeartbeatPong(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// CMD_NODE_DISCOVER
HandlerResult HandleNodeDiscover(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// CMD_NODE_ANNOUNCE
HandlerResult HandleNodeAnnounce(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// CMD_TOPOLOGY_SYNC
HandlerResult HandleTopologySync(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// ============================================================================
// Batch 2.2: Inference Pipeline Handlers (declarations)
// ============================================================================

HandlerResult HandleInferenceRequest(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleInferenceResponse(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleInferenceStream(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleInferenceCancel(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleLoadBalance(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// ============================================================================
// Batch 2.3: Tensor Operations Handlers (declarations)
// ============================================================================

HandlerResult HandleTensorShard(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleKVCacheOffload(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleKVCacheFetch(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleAllGather(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleAllReduce(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// ============================================================================
// Batch 2.4: Admin & Control Handlers (declarations)
// ============================================================================

HandlerResult HandleCheckpointSave(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleCheckpointLoad(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleConfigUpdate(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandleMetricsReport(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);
HandlerResult HandlePanicAbort(const RawrXD::Distributed::RawrPacket& packet, NodeContext& ctx);

// ============================================================================
// Utility Functions
// ============================================================================

const char* HandlerStatusToString(HandlerStatus status);
bool ValidatePacketForCommand(const RawrPacket& packet, RawrCommand expected);

// ============================================================================
// Inference Runtime Integration
// ============================================================================

void InitializeInferenceRuntime();
RawrXD::Distributed::InferenceRuntime* GetInferenceRuntime();
void ShutdownInferenceRuntime();

} // namespace RPC
} // namespace RawrXD
