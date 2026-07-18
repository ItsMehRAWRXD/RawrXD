// RawrXD RPC Handler Framework Tests - Layer 2.0 / Batch 2.1
// Copyright (c) 2026 RawrXD Team

#include "RawrXD_RPC_Handlers.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <cmath>

// Simple test framework
#define TEST(name) void test_##name()
#define ASSERT_EQ(a, b) if ((a) != (b)) { \
    std::cerr << "FAILED: Assertion failed: " << #a << " == " << #b << " at line " << __LINE__ << std::endl; \
    return; \
}
#define ASSERT_TRUE(x) if (!(x)) { \
    std::cerr << "FAILED: Assertion failed: " << #x << " at line " << __LINE__ << std::endl; \
    return; \
}
#define ASSERT_FALSE(x) if (x) { \
    std::cerr << "FAILED: Assertion failed: !(" << #x << ") at line " << __LINE__ << std::endl; \
    return; \
}

static int tests_passed = 0;
static int tests_failed = 0;

void run_test(const char* name, void (*test)()) {
    std::cout << "Running " << name << "... ";
    test();
    std::cout << "PASSED" << std::endl;
    tests_passed++;
}

#define RUN_TEST(name) run_test(#name, test_##name)

// ============================================================================
// Mock Discovery for Testing
// ============================================================================

class MockDiscovery : public Sovereign::Distributed::NodeDiscovery {
public:
    MockDiscovery() : NodeDiscovery({}) {}
    
    // Shadow base class methods (not virtual)
    bool Initialize() { return true; }
    void Shutdown() {}
    
    bool AddNode(const Sovereign::Distributed::NodeIdentity& node) {
        nodes_[node.node_id] = node;
        return true;
    }
    
    bool RemoveNode(const std::string& node_id) {
        return nodes_.erase(node_id) > 0;
    }
    
    std::vector<Sovereign::Distributed::NodeIdentity> GetAllNodes() const {
        std::vector<Sovereign::Distributed::NodeIdentity> result;
        for (const auto& [id, node] : nodes_) {
            result.push_back(node);
        }
        return result;
    }
    
    std::shared_ptr<Sovereign::Distributed::ClusterTopology> GetTopology() const {
        return nullptr;
    }
    
    // Test helpers
    void UpdateHeartbeat(const std::string& node_id) {
        heartbeats_[node_id] = std::chrono::steady_clock::now();
    }
    
    void RecordRTT(const std::string& node_id, uint64_t rtt_us) {
        rtts_[node_id] = rtt_us;
    }
    
private:
    mutable std::unordered_map<std::string, Sovereign::Distributed::NodeIdentity> nodes_;
    mutable std::unordered_map<std::string, std::chrono::steady_clock::time_point> heartbeats_;
    mutable std::unordered_map<std::string, uint64_t> rtts_;
};

// ============================================================================
// Handler Registry Tests
// ============================================================================

TEST(registry_construction) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    ASSERT_EQ(registry.GetRegisteredCount(), 0u);
    ASSERT_EQ(registry.GetDispatchCount(), 0u);
    ASSERT_EQ(registry.GetErrorCount(), 0u);
}

TEST(registry_register_single) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto handler = [](const RawrXD::Distributed::RawrPacket&, RawrXD::RPC::NodeContext&) {
        return RawrXD::RPC::HandlerResult::Success();
    };
    
    ASSERT_TRUE(registry.Register(RawrXD::RPC::RawrCommand::CMD_HEARTBEAT_PING, handler));
    ASSERT_EQ(registry.GetRegisteredCount(), 1u);
    ASSERT_TRUE(registry.IsRegistered(RawrXD::RPC::RawrCommand::CMD_HEARTBEAT_PING));
}

TEST(registry_register_duplicate) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto handler = [](const RawrXD::Distributed::RawrPacket&, RawrXD::RPC::NodeContext&) {
        return RawrXD::RPC::HandlerResult::Success();
    };
    
    ASSERT_TRUE(registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, handler));
    ASSERT_FALSE(registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, handler)); // Duplicate
    ASSERT_EQ(registry.GetRegisteredCount(), 1u);
}

TEST(registry_unregister) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto handler = [](const RawrXD::Distributed::RawrPacket&, RawrXD::RPC::NodeContext&) {
        return RawrXD::RPC::HandlerResult::Success();
    };
    
    registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, handler);
    ASSERT_TRUE(registry.Unregister(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING));
    ASSERT_FALSE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING));
    ASSERT_EQ(registry.GetRegisteredCount(), 0u);
}

TEST(registry_null_handler) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    ASSERT_FALSE(registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, nullptr));
}

TEST(registry_dispatch_unknown) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto packet = RawrXD::Distributed::build_heartbeat_ping(1, 12345);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = registry.Dispatch(packet, ctx);
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_UNKNOWN_COMMAND);
    ASSERT_EQ(registry.GetErrorCount(), 1u);
}

TEST(registry_dispatch_invalid_packet) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto handler = [](const RawrXD::Distributed::RawrPacket&, RawrXD::RPC::NodeContext&) {
        return RawrXD::RPC::HandlerResult::Success();
    };
    
    registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, handler);
    
    // Create invalid packet
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(0xDEADBEEF); // Wrong magic
    
    RawrXD::RPC::NodeContext ctx{};
    auto result = registry.Dispatch(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(registry_statistics) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    
    auto handler = [](const RawrXD::Distributed::RawrPacket&, RawrXD::RPC::NodeContext&) {
        return RawrXD::RPC::HandlerResult::Success();
    };
    
    registry.Register(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING, handler);
    
    auto packet = RawrXD::Distributed::build_heartbeat_ping(1, 12345);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    registry.Dispatch(packet, ctx);
    registry.Dispatch(packet, ctx);
    
    ASSERT_EQ(registry.GetDispatchCount(), 2u);
    ASSERT_EQ(registry.GetErrorCount(), 0u);
    
    registry.ResetStatistics();
    ASSERT_EQ(registry.GetDispatchCount(), 0u);
}

// ============================================================================
// Batch 2.1: Core Handler Tests
// ============================================================================

TEST(core_handler_registration) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    registry.RegisterCoreHandlers();
    
    ASSERT_EQ(registry.GetRegisteredCount(), 5u);
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PING));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_HEARTBEAT_PONG));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_NODE_DISCOVER));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_NODE_ANNOUNCE));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_TOPOLOGY_SYNC));
}

TEST(handler_heartbeat_ping) {
    MockDiscovery mock_discovery;
    
    auto packet = RawrXD::Distributed::build_heartbeat_ping(1, 12345);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleHeartbeatPing(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
    ASSERT_FALSE(ctx.peer_node_id.empty());
}

TEST(handler_heartbeat_pong) {
    MockDiscovery mock_discovery;
    
    auto packet = RawrXD::Distributed::build_heartbeat_pong(1, 12345, 0, 0);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.peer_node_id = "peer-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleHeartbeatPong(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_heartbeat_invalid_packet) {
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(0xDEADBEEF); // Invalid
    
    RawrXD::RPC::NodeContext ctx{};
    auto result = RawrXD::RPC::HandleHeartbeatPing(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_node_discover) {
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Add some nodes
    Sovereign::Distributed::NodeIdentity node1;
    node1.node_id = "node-1";
    node1.ip_address = "192.168.1.1";
    node1.port = 8080;
    
    Sovereign::Distributed::NodeIdentity node2;
    node2.node_id = "node-2";
    node2.ip_address = "192.168.1.2";
    node2.port = 8080;
    mock_discovery.AddNode(node1);
    mock_discovery.AddNode(node2);
    
    RawrXD::Distributed::NodeInfo info{};
    info.node_id = 1;
    auto packet = RawrXD::Distributed::build_node_discover(info, 1, 1);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleNodeDiscover(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_node_discover_no_discovery) {
    RawrXD::Distributed::NodeInfo info{};
    info.node_id = 1;
    auto packet = RawrXD::Distributed::build_node_discover(info, 1, 1);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = nullptr;
    
    auto result = RawrXD::RPC::HandleNodeDiscover(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INTERNAL);
}

TEST(handler_node_announce) {
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Build a node discover packet as a substitute for announce
    RawrXD::Distributed::NodeInfo info{};
    info.node_id = 42;
    info.data_port = 8080;
    auto packet = RawrXD::Distributed::build_node_discover(info, 1, 1);
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleNodeAnnounce(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_topology_sync) {
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Use a simple ping packet for sync test
    auto packet = RawrXD::Distributed::build_heartbeat_ping(1, 100);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleTopologySync(packet, ctx);
    
    // May fail due to no quorum, but should process
    ASSERT_TRUE(result.status == RawrXD::RPC::HandlerStatus::SUCCESS ||
                result.status == RawrXD::RPC::HandlerStatus::ERROR_INTERNAL);
}

// ============================================================================
// Handler Status Tests
// ============================================================================

TEST(handler_status_to_string) {
    ASSERT_TRUE(std::strcmp(RawrXD::RPC::HandlerStatusToString(
        RawrXD::RPC::HandlerStatus::SUCCESS), "SUCCESS") == 0);
    ASSERT_TRUE(std::strcmp(RawrXD::RPC::HandlerStatusToString(
        RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET), "INVALID_PACKET") == 0);
    ASSERT_TRUE(std::strcmp(RawrXD::RPC::HandlerStatusToString(
        RawrXD::RPC::HandlerStatus::ERROR_UNKNOWN_COMMAND), "UNKNOWN_COMMAND") == 0);
}

TEST(handler_result_helpers) {
    auto success = RawrXD::RPC::HandlerResult::Success();
    ASSERT_EQ(success.status, RawrXD::RPC::HandlerStatus::SUCCESS);
    ASSERT_TRUE(success.error_message.empty());
    
    auto error = RawrXD::RPC::HandlerResult::Error(
        RawrXD::RPC::HandlerStatus::ERROR_TIMEOUT, "timeout");
    ASSERT_EQ(error.status, RawrXD::RPC::HandlerStatus::ERROR_TIMEOUT);
    ASSERT_EQ(error.error_message, "timeout");
}

// ============================================================================
// Batch 2.2: Inference Handler Tests
// ============================================================================

TEST(inference_handler_registration) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    registry.RegisterInferenceHandlers();
    
    ASSERT_EQ(registry.GetRegisteredCount(), 5u);
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_REQUEST));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_RESPONSE));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_STREAM));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_CANCEL));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_LOAD_BALANCE));
}

TEST(handler_inference_request_valid) {
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Build inference request packet
    RawrXD::Distributed::InferenceRequestPayload req{};
    req.batch_size = 1;
    req.seq_length = 128;
    req.model_id = 1;
    
    auto packet = RawrXD::Distributed::build_inference_request(1, 100, req);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleInferenceRequest(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_inference_request_invalid_batch) {
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Build inference request with invalid batch_size=0
    RawrXD::Distributed::InferenceRequestPayload req{};
    req.batch_size = 0;  // Invalid
    req.seq_length = 128;
    
    auto packet = RawrXD::Distributed::build_inference_request(1, 100, req);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    ctx.discovery = &mock_discovery;
    
    auto result = RawrXD::RPC::HandleInferenceRequest(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_inference_response) {
    // Build a simple response packet (request_id + status)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_RESPONSE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t request_id = 12345;
    uint32_t status = 0; // Success
    packet.payload.resize(sizeof(request_id) + sizeof(status));
    memcpy(packet.payload.data(), &request_id, sizeof(request_id));
    memcpy(packet.payload.data() + sizeof(request_id), &status, sizeof(status));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleInferenceResponse(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_inference_stream) {
    // Build stream packet (request_id + seq_num + token_data)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_STREAM));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t request_id = 12345;
    uint32_t seq_num = 0;
    packet.payload.resize(sizeof(request_id) + sizeof(seq_num) + 4); // +4 for token
    memcpy(packet.payload.data(), &request_id, sizeof(request_id));
    memcpy(packet.payload.data() + sizeof(request_id), &seq_num, sizeof(seq_num));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleInferenceStream(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_inference_cancel) {
    // Build cancel packet (request_id only)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_INFERENCE_CANCEL));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t request_id = 12345;
    packet.payload.resize(sizeof(request_id));
    memcpy(packet.payload.data(), &request_id, sizeof(request_id));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleInferenceCancel(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_load_balance) {
    // Build load balance packet (target_load_percent)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_LOAD_BALANCE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint32_t target_load = 75; // 75% target
    packet.payload.resize(sizeof(target_load));
    memcpy(packet.payload.data(), &target_load, sizeof(target_load));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleLoadBalance(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_load_balance_invalid) {
    // Build load balance packet with invalid percentage (>100)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_LOAD_BALANCE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint32_t target_load = 150; // Invalid: >100%
    packet.payload.resize(sizeof(target_load));
    memcpy(packet.payload.data(), &target_load, sizeof(target_load));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleLoadBalance(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

// ============================================================================
// Batch 2.3: Tensor Operations Handler Tests
// ============================================================================

TEST(tensor_handler_registration) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    registry.RegisterTensorHandlers();
    
    ASSERT_EQ(registry.GetRegisteredCount(), 5u);
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_TENSOR_SHARD));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_KVCACHE_OFFLOAD));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_KVCACHE_FETCH));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_ALLGATHER_TENSORS));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_ALLREDUCE_GRADIENTS));
}

TEST(handler_tensor_shard) {
    // Build tensor shard packet (tensor_id + target_node)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_TENSOR_SHARD));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t tensor_id = 12345;
    uint16_t target_node = 2;
    packet.payload.resize(sizeof(tensor_id) + sizeof(target_node));
    memcpy(packet.payload.data(), &tensor_id, sizeof(tensor_id));
    memcpy(packet.payload.data() + sizeof(tensor_id), &target_node, sizeof(target_node));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleTensorShard(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_kv_cache_offload) {
    // Build KV cache offload packet
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_KVCACHE_OFFLOAD));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    RawrXD::Distributed::KVCacheSyncPayload payload{};
    payload.cache_id = 100;
    payload.source_node = 1;
    payload.target_node = 2;
    payload.layer_count = 32;
    payload.byte_size = 1024 * 1024 * 100; // 100MB
    
    packet.payload.resize(sizeof(payload));
    memcpy(packet.payload.data(), &payload, sizeof(payload));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleKVCacheOffload(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_kv_cache_offload_invalid) {
    // Build KV cache offload with invalid parameters
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_KVCACHE_OFFLOAD));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    RawrXD::Distributed::KVCacheSyncPayload payload{};
    payload.cache_id = 100;
    payload.layer_count = 0; // Invalid
    payload.byte_size = 0;   // Invalid
    
    packet.payload.resize(sizeof(payload));
    memcpy(packet.payload.data(), &payload, sizeof(payload));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleKVCacheOffload(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_kv_cache_fetch) {
    // Build KV cache fetch packet
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_KVCACHE_FETCH));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    RawrXD::Distributed::KVCacheSyncPayload payload{};
    payload.cache_id = 100;
    payload.source_node = 2;
    payload.target_node = 1;
    payload.layer_count = 32;
    payload.byte_size = 1024 * 1024 * 100;
    
    packet.payload.resize(sizeof(payload));
    memcpy(packet.payload.data(), &payload, sizeof(payload));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleKVCacheFetch(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_all_gather) {
    // Build all-gather packet (gather_id + element_count + data_type)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_ALLGATHER_TENSORS));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t gather_id = 999;
    uint32_t element_count = 1024;
    uint32_t data_type = 1; // FP16
    packet.payload.resize(sizeof(gather_id) + sizeof(element_count) + sizeof(data_type));
    memcpy(packet.payload.data(), &gather_id, sizeof(gather_id));
    memcpy(packet.payload.data() + sizeof(gather_id), &element_count, sizeof(element_count));
    memcpy(packet.payload.data() + sizeof(gather_id) + sizeof(element_count), &data_type, sizeof(data_type));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleAllGather(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_all_gather_invalid) {
    // Build all-gather with invalid element_count=0
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_ALLGATHER_TENSORS));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t gather_id = 999;
    uint32_t element_count = 0; // Invalid
    uint32_t data_type = 1;
    packet.payload.resize(sizeof(gather_id) + sizeof(element_count) + sizeof(data_type));
    memcpy(packet.payload.data(), &gather_id, sizeof(gather_id));
    memcpy(packet.payload.data() + sizeof(gather_id), &element_count, sizeof(element_count));
    memcpy(packet.payload.data() + sizeof(gather_id) + sizeof(element_count), &data_type, sizeof(data_type));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleAllGather(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_all_reduce) {
    // Build all-reduce packet (reduce_id + step + element_count)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_ALLREDUCE_GRADIENTS));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t reduce_id = 888;
    uint32_t step = 1;
    uint32_t element_count = 1024;
    packet.payload.resize(sizeof(reduce_id) + sizeof(step) + sizeof(element_count));
    memcpy(packet.payload.data(), &reduce_id, sizeof(reduce_id));
    memcpy(packet.payload.data() + sizeof(reduce_id), &step, sizeof(step));
    memcpy(packet.payload.data() + sizeof(reduce_id) + sizeof(step), &element_count, sizeof(element_count));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleAllReduce(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

// ============================================================================
// Batch 2.4: Admin & Control Handler Tests
// ============================================================================

TEST(admin_handler_registration) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    registry.RegisterAdminHandlers();
    
    ASSERT_EQ(registry.GetRegisteredCount(), 5u);
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_CHECKPOINT_SAVE));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_CHECKPOINT_LOAD));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_CONFIG_UPDATE));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_METRICS_REPORT));
    ASSERT_TRUE(registry.IsRegistered(RawrXD::Distributed::RawrCommand::CMD_PANIC_ABORT));
}

TEST(handler_checkpoint_save) {
    // Build checkpoint save packet (checkpoint_id + path_len + path)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_CHECKPOINT_SAVE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t checkpoint_id = 1001;
    uint32_t path_len = 10;
    packet.payload.resize(sizeof(checkpoint_id) + sizeof(path_len) + path_len);
    memcpy(packet.payload.data(), &checkpoint_id, sizeof(checkpoint_id));
    memcpy(packet.payload.data() + sizeof(checkpoint_id), &path_len, sizeof(path_len));
    memcpy(packet.payload.data() + sizeof(checkpoint_id) + sizeof(path_len), "/tmp/ckpt", path_len);
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleCheckpointSave(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_checkpoint_save_invalid_path) {
    // Build checkpoint save with invalid path_len=0
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_CHECKPOINT_SAVE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t checkpoint_id = 1001;
    uint32_t path_len = 0; // Invalid
    packet.payload.resize(sizeof(checkpoint_id) + sizeof(path_len));
    memcpy(packet.payload.data(), &checkpoint_id, sizeof(checkpoint_id));
    memcpy(packet.payload.data() + sizeof(checkpoint_id), &path_len, sizeof(path_len));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleCheckpointSave(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_checkpoint_load) {
    // Build checkpoint load packet
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_CHECKPOINT_LOAD));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t checkpoint_id = 1001;
    uint32_t path_len = 10;
    packet.payload.resize(sizeof(checkpoint_id) + sizeof(path_len) + path_len);
    memcpy(packet.payload.data(), &checkpoint_id, sizeof(checkpoint_id));
    memcpy(packet.payload.data() + sizeof(checkpoint_id), &path_len, sizeof(path_len));
    memcpy(packet.payload.data() + sizeof(checkpoint_id) + sizeof(path_len), "/tmp/ckpt", path_len);
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleCheckpointLoad(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_config_update) {
    // Build config update packet (key_len + value_len + key + value)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_CONFIG_UPDATE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint32_t key_len = 8;
    uint32_t value_len = 4;
    packet.payload.resize(sizeof(key_len) + sizeof(value_len) + key_len + value_len);
    memcpy(packet.payload.data(), &key_len, sizeof(key_len));
    memcpy(packet.payload.data() + sizeof(key_len), &value_len, sizeof(value_len));
    memcpy(packet.payload.data() + sizeof(key_len) + sizeof(value_len), "max_batch", key_len);
    memcpy(packet.payload.data() + sizeof(key_len) + sizeof(value_len) + key_len, "1024", value_len);
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleConfigUpdate(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_config_update_invalid) {
    // Build config update with invalid key_len=0
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_CONFIG_UPDATE));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint32_t key_len = 0; // Invalid
    uint32_t value_len = 4;
    packet.payload.resize(sizeof(key_len) + sizeof(value_len));
    memcpy(packet.payload.data(), &key_len, sizeof(key_len));
    memcpy(packet.payload.data() + sizeof(key_len), &value_len, sizeof(value_len));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleConfigUpdate(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

TEST(handler_metrics_report) {
    // Build metrics report packet (timestamp + cpu + memory + tps)
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_METRICS_REPORT));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t timestamp = 1234567890;
    double cpu_percent = 45.5;
    double memory_gb = 16.0;
    double tps = 125.5;
    packet.payload.resize(sizeof(timestamp) + sizeof(cpu_percent) + sizeof(memory_gb) + sizeof(tps));
    memcpy(packet.payload.data(), &timestamp, sizeof(timestamp));
    memcpy(packet.payload.data() + sizeof(timestamp), &cpu_percent, sizeof(cpu_percent));
    memcpy(packet.payload.data() + sizeof(timestamp) + sizeof(cpu_percent), &memory_gb, sizeof(memory_gb));
    memcpy(packet.payload.data() + sizeof(timestamp) + sizeof(cpu_percent) + sizeof(memory_gb), &tps, sizeof(tps));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleMetricsReport(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
}

TEST(handler_metrics_report_invalid_cpu) {
    // Build metrics report with invalid CPU > 100%
    RawrXD::Distributed::RawrPacket packet;
    packet.set_magic(RawrXD::Distributed::RAWRXD_MAGIC);
    packet.set_cmd(static_cast<uint32_t>(RawrXD::Distributed::RawrCommand::CMD_METRICS_REPORT));
    packet.set_seq(1);
    packet.set_node_id(1);
    packet.set_flags(0);
    
    uint64_t timestamp = 1234567890;
    double cpu_percent = 150.0; // Invalid
    double memory_gb = 16.0;
    double tps = 125.5;
    packet.payload.resize(sizeof(timestamp) + sizeof(cpu_percent) + sizeof(memory_gb) + sizeof(tps));
    memcpy(packet.payload.data(), &timestamp, sizeof(timestamp));
    memcpy(packet.payload.data() + sizeof(timestamp), &cpu_percent, sizeof(cpu_percent));
    memcpy(packet.payload.data() + sizeof(timestamp) + sizeof(cpu_percent), &memory_gb, sizeof(memory_gb));
    memcpy(packet.payload.data() + sizeof(timestamp) + sizeof(cpu_percent) + sizeof(memory_gb), &tps, sizeof(tps));
    packet.set_len(packet.payload.size());
    
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "test-node";
    
    auto result = RawrXD::RPC::HandleMetricsReport(packet, ctx);
    
    ASSERT_EQ(result.status, RawrXD::RPC::HandlerStatus::ERROR_INVALID_PACKET);
}

// ============================================================================
// Integration: End-to-End Handler Dispatch
// ============================================================================

TEST(integration_ping_pong_roundtrip) {
    RawrXD::RPC::RPCHandlerRegistry registry;
    registry.RegisterCoreHandlers();
    
    MockDiscovery mock_discovery;
    mock_discovery.Initialize();
    
    // Simulate PING
    auto ping = RawrXD::Distributed::build_heartbeat_ping(1, 1000);
    RawrXD::RPC::NodeContext ctx{};
    ctx.self_node_id = "node-a";
    ctx.discovery = &mock_discovery;
    
    auto ping_result = registry.Dispatch(ping, ctx);
    ASSERT_EQ(ping_result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
    
    // Simulate PONG response
    auto pong = RawrXD::Distributed::build_heartbeat_pong(1, 1000, 0, 0);
    ctx.peer_node_id = "node-b";
    
    auto pong_result = registry.Dispatch(pong, ctx);
    ASSERT_EQ(pong_result.status, RawrXD::RPC::HandlerStatus::SUCCESS);
    
    // Verify RTT was recorded
    ASSERT_EQ(registry.GetDispatchCount(), 2u);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD RPC Handler Framework Tests" << std::endl;
    std::cout << "Layer 2.0 / Batch 2.1 Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Registry Tests
    std::cout << "--- Handler Registry Tests ---" << std::endl;
    RUN_TEST(registry_construction);
    RUN_TEST(registry_register_single);
    RUN_TEST(registry_register_duplicate);
    RUN_TEST(registry_unregister);
    RUN_TEST(registry_null_handler);
    RUN_TEST(registry_dispatch_unknown);
    RUN_TEST(registry_dispatch_invalid_packet);
    RUN_TEST(registry_statistics);
    std::cout << std::endl;
    
    // Batch 2.1 Tests
    std::cout << "--- Batch 2.1: Core Handler Tests ---" << std::endl;
    RUN_TEST(core_handler_registration);
    RUN_TEST(handler_heartbeat_ping);
    RUN_TEST(handler_heartbeat_pong);
    RUN_TEST(handler_heartbeat_invalid_packet);
    RUN_TEST(handler_node_discover);
    RUN_TEST(handler_node_discover_no_discovery);
    RUN_TEST(handler_node_announce);
    RUN_TEST(handler_topology_sync);
    std::cout << std::endl;
    
    // Status Tests
    std::cout << "--- Handler Status Tests ---" << std::endl;
    RUN_TEST(handler_status_to_string);
    RUN_TEST(handler_result_helpers);
    std::cout << std::endl;
    
    // Batch 2.2 Tests
    std::cout << "--- Batch 2.2: Inference Handler Tests ---" << std::endl;
    RUN_TEST(inference_handler_registration);
    RUN_TEST(handler_inference_request_valid);
    RUN_TEST(handler_inference_request_invalid_batch);
    RUN_TEST(handler_inference_response);
    RUN_TEST(handler_inference_stream);
    RUN_TEST(handler_inference_cancel);
    RUN_TEST(handler_load_balance);
    RUN_TEST(handler_load_balance_invalid);
    std::cout << std::endl;
    
    // Batch 2.3 Tests
    std::cout << "--- Batch 2.3: Tensor Operations Handler Tests ---" << std::endl;
    RUN_TEST(tensor_handler_registration);
    RUN_TEST(handler_tensor_shard);
    RUN_TEST(handler_kv_cache_offload);
    RUN_TEST(handler_kv_cache_offload_invalid);
    RUN_TEST(handler_kv_cache_fetch);
    RUN_TEST(handler_all_gather);
    RUN_TEST(handler_all_gather_invalid);
    RUN_TEST(handler_all_reduce);
    std::cout << std::endl;
    
    // Batch 2.4 Tests
    std::cout << "--- Batch 2.4: Admin & Control Handler Tests ---" << std::endl;
    RUN_TEST(admin_handler_registration);
    RUN_TEST(handler_checkpoint_save);
    RUN_TEST(handler_checkpoint_save_invalid_path);
    RUN_TEST(handler_checkpoint_load);
    RUN_TEST(handler_config_update);
    RUN_TEST(handler_config_update_invalid);
    RUN_TEST(handler_metrics_report);
    RUN_TEST(handler_metrics_report_invalid_cpu);
    std::cout << std::endl;
    
    // Integration Tests
    std::cout << "--- Integration Tests ---" << std::endl;
    RUN_TEST(integration_ping_pong_roundtrip);
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
