// RawrXD RPC Handler Framework - Layer 2.0 Implementation
// Batch 2.1: Core Communication Handlers
// Copyright (c) 2026 RawrXD Team

#include "RawrXD_RPC_Handlers.hpp"
#include <iostream>
#include <cstring>

namespace RawrXD {
namespace RPC {

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
// RPCHandlerRegistry Implementation
// ============================================================================

RPCHandlerRegistry::RPCHandlerRegistry() = default;
RPCHandlerRegistry::~RPCHandlerRegistry() = default;

bool RPCHandlerRegistry::Register(RawrCommand command, HandlerFunction handler) {
    if (handler == nullptr) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    uint16_t cmd_id = static_cast<uint16_t>(command);
    
    auto result = handlers_.emplace(cmd_id, std::move(handler));
    return result.second;
}

bool RPCHandlerRegistry::Unregister(RawrCommand command) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint16_t cmd_id = static_cast<uint16_t>(command);
    return handlers_.erase(cmd_id) > 0;
}

bool RPCHandlerRegistry::IsRegistered(RawrCommand command) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint16_t cmd_id = static_cast<uint16_t>(command);
    return handlers_.find(cmd_id) != handlers_.end();
}

HandlerResult RPCHandlerRegistry::Dispatch(const RawrPacket& packet, NodeContext& context) {
    auto start_time = std::chrono::steady_clock::now();
    
    dispatch_count_++;
    
    if (!packet.validate()) {
        error_count_++;
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET, 
            "Packet validation failed");
    }
    
    HandlerFunction handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = handlers_.find(static_cast<uint16_t>(packet.cmd()));
        if (it == handlers_.end()) {
            error_count_++;
            return HandlerResult::Error(HandlerStatus::ERROR_UNKNOWN_COMMAND,
                "Command not registered");
        }
        handler = it->second;
    }
    
    context.request_time = start_time;
    HandlerResult result = handler(packet, context);
    context.response_time = std::chrono::steady_clock::now();
    
    result.processing_time = std::chrono::duration_cast<std::chrono::microseconds>(
        context.response_time - start_time);
    
    if (result.status != HandlerStatus::SUCCESS) {
        error_count_++;
    }
    
    return result;
}

size_t RPCHandlerRegistry::GetRegisteredCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return handlers_.size();
}

void RPCHandlerRegistry::ResetStatistics() {
    dispatch_count_.store(0);
    error_count_.store(0);
}

void RPCHandlerRegistry::RegisterCoreHandlers() {
    Register(RawrCommand::CMD_HEARTBEAT_PING, HandleHeartbeatPing);
    Register(RawrCommand::CMD_HEARTBEAT_PONG, HandleHeartbeatPong);
    Register(RawrCommand::CMD_NODE_DISCOVER, HandleNodeDiscover);
    Register(RawrCommand::CMD_NODE_ANNOUNCE, HandleNodeAnnounce);
    Register(RawrCommand::CMD_TOPOLOGY_SYNC, HandleTopologySync);
}

void RPCHandlerRegistry::RegisterInferenceHandlers() {
    Register(RawrCommand::CMD_INFERENCE_REQUEST, HandleInferenceRequest);
    Register(RawrCommand::CMD_INFERENCE_RESPONSE, HandleInferenceResponse);
    Register(RawrCommand::CMD_INFERENCE_STREAM, HandleInferenceStream);
    Register(RawrCommand::CMD_INFERENCE_CANCEL, HandleInferenceCancel);
    Register(RawrCommand::CMD_LOAD_BALANCE, HandleLoadBalance);
}

void RPCHandlerRegistry::RegisterTensorHandlers() {
    Register(RawrCommand::CMD_TENSOR_SHARD, HandleTensorShard);
    Register(RawrCommand::CMD_KVCACHE_OFFLOAD, HandleKVCacheOffload);
    Register(RawrCommand::CMD_KVCACHE_FETCH, HandleKVCacheFetch);
    Register(RawrCommand::CMD_ALLGATHER_TENSORS, HandleAllGather);
    Register(RawrCommand::CMD_ALLREDUCE_GRADIENTS, HandleAllReduce);
}

void RPCHandlerRegistry::RegisterAdminHandlers() {
    Register(RawrCommand::CMD_CHECKPOINT_SAVE, HandleCheckpointSave);
    Register(RawrCommand::CMD_CHECKPOINT_LOAD, HandleCheckpointLoad);
    Register(RawrCommand::CMD_CONFIG_UPDATE, HandleConfigUpdate);
    Register(RawrCommand::CMD_METRICS_REPORT, HandleMetricsReport);
    Register(RawrCommand::CMD_PANIC_ABORT, HandlePanicAbort);
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* HandlerStatusToString(HandlerStatus status) {
    switch (status) {
        case HandlerStatus::SUCCESS: return "SUCCESS";
        case HandlerStatus::ERROR_INVALID_PACKET: return "INVALID_PACKET";
        case HandlerStatus::ERROR_UNKNOWN_COMMAND: return "UNKNOWN_COMMAND";
        case HandlerStatus::ERROR_NODE_UNHEALTHY: return "NODE_UNHEALTHY";
        case HandlerStatus::ERROR_TIMEOUT: return "TIMEOUT";
        case HandlerStatus::ERROR_INTERNAL: return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

bool ValidatePacketForCommand(const RawrPacket& packet, RawrCommand expected) {
    return packet.validate() && packet.cmd() == static_cast<uint32_t>(expected);
}

// ============================================================================
// Batch 2.1: Core Communication Handlers
// ============================================================================

HandlerResult HandleHeartbeatPing(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_HEARTBEAT_PING)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid HEARTBEAT_PING packet");
    }
    
    // Get peer node ID from packet header
    ctx.peer_node_id = std::to_string(packet.node_id());
    
    if (packet.payload.size() >= sizeof(uint64_t)) {
        const auto* payload = reinterpret_cast<const HeartbeatPayload*>(packet.payload.data());
        (void)payload; // Could extract timestamp/queue_depth if needed
        
        if (ctx.discovery) {
            // Discovery interface doesn't have UpdateHeartbeat - skip for now
            (void)ctx.discovery;
        }
    }
    
    return HandlerResult::Success();
}

HandlerResult HandleHeartbeatPong(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_HEARTBEAT_PONG)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid HEARTBEAT_PONG packet");
    }
    
    if (packet.len() < sizeof(HeartbeatPayload)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "HEARTBEAT_PONG payload too small");
    }
    
    const auto* payload = reinterpret_cast<const HeartbeatPayload*>(packet.payload.data());
    
    auto now = std::chrono::steady_clock::now();
    auto sent_time = std::chrono::steady_clock::time_point(
        std::chrono::nanoseconds(payload->timestamp));
    auto rtt = std::chrono::duration_cast<std::chrono::microseconds>(now - sent_time);
    
    if (ctx.discovery) {
        // Discovery interface doesn't have RecordRTT/UpdateHeartbeat - skip for now
        (void)rtt;
        (void)ctx.discovery;
    }
    
    return HandlerResult::Success();
}

HandlerResult HandleNodeDiscover(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_NODE_DISCOVER)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid NODE_DISCOVER packet");
    }
    
    if (!ctx.discovery) {
        return HandlerResult::Error(HandlerStatus::ERROR_INTERNAL,
            "Discovery layer not available");
    }
    
    auto healthy_nodes = ctx.discovery->GetAllNodes();
    (void)healthy_nodes; // Used for response building
    
    return HandlerResult::Success();
}

HandlerResult HandleNodeAnnounce(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_NODE_ANNOUNCE)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid NODE_ANNOUNCE packet");
    }
    
    if (packet.len() < sizeof(NodeDiscoverPayload)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "NODE_ANNOUNCE payload too small");
    }
    
    const auto* payload = reinterpret_cast<const NodeDiscoverPayload*>(packet.payload.data());
    
    if (!ctx.discovery) {
        return HandlerResult::Error(HandlerStatus::ERROR_INTERNAL,
            "Discovery layer not available");
    }
    
    Sovereign::Distributed::NodeIdentity node;
    node.node_id = std::to_string(payload->node_info.node_id);
    node.ip_address = "127.0.0.1"; // Placeholder
    node.port = payload->node_info.data_port;
    // NodeDiscoverPayload doesn't have datacenter/rack/version - use defaults
    node.datacenter = "default";
    node.rack = "default";
    node.version = "1.0.0";
    
    if (ctx.discovery->AddNode(node)) {
        return HandlerResult::Success();
    } else {
        return HandlerResult::Error(HandlerStatus::ERROR_NODE_UNHEALTHY,
            "Failed to add announced node");
    }
}

HandlerResult HandleTopologySync(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_TOPOLOGY_SYNC)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid TOPOLOGY_SYNC packet");
    }
    
    if (!ctx.discovery) {
        return HandlerResult::Error(HandlerStatus::ERROR_INTERNAL,
            "Discovery layer not available");
    }
    
    auto topology = ctx.discovery->GetTopology();
    if (!topology) {
        return HandlerResult::Error(HandlerStatus::ERROR_INTERNAL,
            "Topology not available");
    }
    
    if (!topology->HasQuorum()) {
        return HandlerResult::Error(HandlerStatus::ERROR_NODE_UNHEALTHY,
            "Local node does not have quorum");
    }
    
    return HandlerResult::Success();
}

// ============================================================================
// Batch 2.2: Inference Pipeline Handlers
// ============================================================================

// CMD_INFERENCE_REQUEST Handler
// Processes inference requests from clients/other nodes
HandlerResult HandleInferenceRequest(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_INFERENCE_REQUEST)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid INFERENCE_REQUEST packet");
    }
    
    if (packet.len() < sizeof(InferenceRequestPayload)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "INFERENCE_REQUEST payload too small");
    }
    
    const auto* payload = reinterpret_cast<const InferenceRequestPayload*>(packet.payload.data());
    
    // Validate request parameters
    if (payload->batch_size == 0 || payload->seq_length == 0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid batch_size or seq_length");
    }
    
    // Check if node can accept more work
    if (ctx.discovery) {
        auto topology = ctx.discovery->GetTopology();
        if (topology && !topology->HasQuorum()) {
            return HandlerResult::Error(HandlerStatus::ERROR_NODE_UNHEALTHY,
                "Node does not have quorum, cannot accept inference");
        }
    }
    
    // In production: Queue request, allocate resources, start inference
    // For now: Acknowledge receipt
    (void)payload; // Request details would be used here
    
    return HandlerResult::Success();
}

// CMD_INFERENCE_RESPONSE Handler
// Processes inference results from worker nodes
HandlerResult HandleInferenceResponse(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_INFERENCE_RESPONSE)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid INFERENCE_RESPONSE packet");
    }
    
    // Response payload varies based on model output
    // Minimum: request_id + status code
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "INFERENCE_RESPONSE payload too small");
    }
    
    // Extract request_id from payload
    uint64_t request_id = *reinterpret_cast<const uint64_t*>(packet.payload.data());
    (void)request_id; // Would correlate with pending request
    (void)ctx;
    
    // In production: Match to pending request, deliver to client
    return HandlerResult::Success();
}

// CMD_INFERENCE_STREAM Handler
// Handles streaming inference responses (token-by-token)
HandlerResult HandleInferenceStream(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_INFERENCE_STREAM)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid INFERENCE_STREAM packet");
    }
    
    // Stream packet format: request_id + sequence_num + token_data
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "INFERENCE_STREAM payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t request_id = *reinterpret_cast<const uint64_t*>(data);
    uint32_t seq_num = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t));
    
    (void)request_id;
    (void)seq_num;
    (void)ctx;
    
    // In production: Forward to streaming client, update sequence tracking
    return HandlerResult::Success();
}

// CMD_INFERENCE_CANCEL Handler
// Cancels in-flight inference requests
HandlerResult HandleInferenceCancel(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_INFERENCE_CANCEL)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid INFERENCE_CANCEL packet");
    }
    
    if (packet.len() < sizeof(uint64_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "INFERENCE_CANCEL payload too small");
    }
    
    uint64_t request_id = *reinterpret_cast<const uint64_t*>(packet.payload.data());
    (void)request_id;
    (void)ctx;
    
    // In production: Signal cancellation to inference engine, cleanup resources
    return HandlerResult::Success();
}

// CMD_LOAD_BALANCE Handler
// Receives load balancing directives from coordinator
HandlerResult HandleLoadBalance(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_LOAD_BALANCE)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid LOAD_BALANCE packet");
    }
    
    // Load balance payload: target_load_percent + rebalance_flags
    if (packet.len() < sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "LOAD_BALANCE payload too small");
    }
    
    uint32_t target_load = *reinterpret_cast<const uint32_t*>(packet.payload.data());
    
    // Validate target load (0-100%)
    if (target_load > 100) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid target load percentage");
    }
    
    (void)target_load;
    (void)ctx;
    
    // In production: Adjust acceptance thresholds, migrate work if needed
    return HandlerResult::Success();
}

// ============================================================================
// Batch 2.3: Tensor Operations Handlers
// ============================================================================

// CMD_TENSOR_SHARD Handler
// Initiates tensor transfer to target node
HandlerResult HandleTensorShard(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_TENSOR_SHARD)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid TENSOR_SHARD packet");
    }
    
    // Minimum payload: tensor_id + target_node
    if (packet.len() < sizeof(uint64_t) + sizeof(uint16_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "TENSOR_SHARD payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t tensor_id = *reinterpret_cast<const uint64_t*>(data);
    uint16_t target_node = *reinterpret_cast<const uint16_t*>(data + sizeof(uint64_t));
    
    (void)tensor_id;
    (void)target_node;
    (void)ctx;
    
    // In production: Initiate tensor transfer, track shard placement
    return HandlerResult::Success();
}

// CMD_KVCACHE_OFFLOAD Handler
// Offloads KV cache to remote node
HandlerResult HandleKVCacheOffload(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_KVCACHE_OFFLOAD)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid KVCACHE_OFFLOAD packet");
    }
    
    if (packet.len() < sizeof(KVCacheSyncPayload)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "KVCACHE_OFFLOAD payload too small");
    }
    
    const auto* payload = reinterpret_cast<const KVCacheSyncPayload*>(packet.payload.data());
    
    // Validate cache parameters
    if (payload->layer_count == 0 || payload->byte_size == 0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid KV cache parameters");
    }
    
    (void)payload;
    (void)ctx;
    
    // In production: Serialize KV cache, transfer to target_node
    return HandlerResult::Success();
}

// CMD_KVCACHE_FETCH Handler
// Fetches KV cache from remote node
HandlerResult HandleKVCacheFetch(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_KVCACHE_FETCH)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid KVCACHE_FETCH packet");
    }
    
    if (packet.len() < sizeof(KVCacheSyncPayload)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "KVCACHE_FETCH payload too small");
    }
    
    const auto* payload = reinterpret_cast<const KVCacheSyncPayload*>(packet.payload.data());
    
    if (payload->cache_id == 0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid cache_id");
    }
    
    (void)payload;
    (void)ctx;
    
    // In production: Retrieve KV cache, serialize and send
    return HandlerResult::Success();
}

// CMD_ALLGATHER_TENSORS Handler
// Collective operation: gather tensors from all nodes
HandlerResult HandleAllGather(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_ALLGATHER_TENSORS)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid ALLGATHER_TENSORS packet");
    }
    
    // Payload: gather_id + element_count + data_type
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "ALLGATHER_TENSORS payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t gather_id = *reinterpret_cast<const uint64_t*>(data);
    uint32_t element_count = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t));
    
    if (element_count == 0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid element_count");
    }
    
    (void)gather_id;
    (void)ctx;
    
    // In production: Participate in ring all-gather, accumulate tensors
    return HandlerResult::Success();
}

// CMD_ALLREDUCE_GRADIENTS Handler
// Collective operation: reduce gradients across all nodes
HandlerResult HandleAllReduce(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_ALLREDUCE_GRADIENTS)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid ALLREDUCE_GRADIENTS packet");
    }
    
    // Payload: reduce_id + step + element_count
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "ALLREDUCE_GRADIENTS payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t reduce_id = *reinterpret_cast<const uint64_t*>(data);
    uint32_t step = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t));
    uint32_t element_count = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t) + sizeof(uint32_t));
    
    if (element_count == 0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid element_count");
    }
    
    (void)reduce_id;
    (void)step;
    (void)ctx;
    
    // In production: Participate in ring all-reduce, sum gradients
    return HandlerResult::Success();
}

// ============================================================================
// Batch 2.4: Admin & Control Handlers
// ============================================================================

// CMD_CHECKPOINT_SAVE Handler
// Saves model checkpoint to storage
HandlerResult HandleCheckpointSave(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_CHECKPOINT_SAVE)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid CHECKPOINT_SAVE packet");
    }
    
    // Minimum payload: checkpoint_id + path_length
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "CHECKPOINT_SAVE payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t checkpoint_id = *reinterpret_cast<const uint64_t*>(data);
    uint32_t path_len = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t));
    
    if (path_len == 0 || path_len > 1024) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid checkpoint path length");
    }
    
    (void)checkpoint_id;
    (void)ctx;
    
    // In production: Serialize model state, write to checkpoint path
    return HandlerResult::Success();
}

// CMD_CHECKPOINT_LOAD Handler
// Loads model checkpoint from storage
HandlerResult HandleCheckpointLoad(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_CHECKPOINT_LOAD)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid CHECKPOINT_LOAD packet");
    }
    
    if (packet.len() < sizeof(uint64_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "CHECKPOINT_LOAD payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t checkpoint_id = *reinterpret_cast<const uint64_t*>(data);
    uint32_t path_len = *reinterpret_cast<const uint32_t*>(data + sizeof(uint64_t));
    
    if (path_len == 0 || path_len > 1024) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid checkpoint path length");
    }
    
    (void)checkpoint_id;
    (void)ctx;
    
    // In production: Load checkpoint, restore model state
    return HandlerResult::Success();
}

// CMD_CONFIG_UPDATE Handler
// Updates runtime configuration
HandlerResult HandleConfigUpdate(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_CONFIG_UPDATE)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid CONFIG_UPDATE packet");
    }
    
    // Config update payload: config_key + config_value
    if (packet.len() < sizeof(uint32_t) + sizeof(uint32_t)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "CONFIG_UPDATE payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint32_t key_len = *reinterpret_cast<const uint32_t*>(data);
    uint32_t value_len = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));
    
    if (key_len == 0 || key_len > 256 || value_len > 4096) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid config key/value length");
    }
    
    (void)ctx;
    
    // In production: Parse config update, apply to runtime
    return HandlerResult::Success();
}

// CMD_METRICS_REPORT Handler
// Reports node metrics to coordinator
HandlerResult HandleMetricsReport(const RawrPacket& packet, NodeContext& ctx) {
    if (!ValidatePacketForCommand(packet, RawrCommand::CMD_METRICS_REPORT)) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid METRICS_REPORT packet");
    }
    
    // Metrics payload: timestamp + cpu_percent + memory_gb + tps
    if (packet.len() < sizeof(uint64_t) + sizeof(double) * 3) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "METRICS_REPORT payload too small");
    }
    
    const uint8_t* data = packet.payload.data();
    uint64_t timestamp = *reinterpret_cast<const uint64_t*>(data);
    double cpu_percent = *reinterpret_cast<const double*>(data + sizeof(uint64_t));
    
    if (cpu_percent < 0.0 || cpu_percent > 100.0) {
        return HandlerResult::Error(HandlerStatus::ERROR_INVALID_PACKET,
            "Invalid CPU percentage");
    }
    
    (void)timestamp;
    (void)ctx;
    
    // In production: Store metrics, forward to monitoring system
    return HandlerResult::Success();
}

HandlerResult HandlePanicAbort(const RawrPacket& packet, NodeContext& ctx) {
    if (packet.len() >= sizeof(PanicAbortPayload)) {
        const auto* payload = reinterpret_cast<const PanicAbortPayload*>(packet.payload.data());
        std::cerr << "[PANIC] Node " << payload->source_node 
                  << " aborted: " << payload->message << std::endl;
        
        if (ctx.discovery) {
            ctx.discovery->RemoveNode(std::to_string(payload->source_node));
        }
    }
    
    return HandlerResult::Success();
}

} // namespace RPC
} // namespace RawrXD
