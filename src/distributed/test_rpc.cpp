// test_rpc.cpp - Unit tests for RawrXD_RPC
// Copyright (c) 2026 RawrXD Team

#include "RawrXD_RPC.hpp"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace RawrXD::Distributed;

// =============================================================================
// Test Helpers
// =============================================================================

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        tests_failed++; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        throw std::runtime_error("Assertion failed: " #a " != " #b); \
    } \
} while(0)

#define ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

// =============================================================================
// Packet Structure Tests
// =============================================================================

TEST(packet_header_size) {
    ASSERT_EQ(sizeof(RawrPacketHeader), 24u);
}

TEST(packet_default_construction) {
    RawrPacket pkt{};
    ASSERT_EQ(pkt.magic(), 0u);
    ASSERT_EQ(pkt.cmd(), 0u);
    ASSERT_EQ(pkt.seq(), 0u);
    ASSERT_EQ(pkt.len(), 0u);
    ASSERT_EQ(pkt.flags(), 0u);
    ASSERT_EQ(pkt.node_id(), 0u);
    ASSERT_TRUE(pkt.payload.empty());
}

TEST(packet_setters) {
    RawrPacket pkt{};
    pkt.set_magic(RAWRXD_MAGIC);
    pkt.set_cmd(CMD_HEARTBEAT_PING);
    pkt.set_seq(42);
    pkt.set_len(100);
    pkt.set_flags(FLAG_ASYNC);
    pkt.set_node_id(7);
    
    ASSERT_EQ(pkt.magic(), RAWRXD_MAGIC);
    ASSERT_EQ(pkt.cmd(), CMD_HEARTBEAT_PING);
    ASSERT_EQ(pkt.seq(), 42u);
    ASSERT_EQ(pkt.len(), 100u);
    ASSERT_EQ(pkt.flags(), FLAG_ASYNC);
    ASSERT_EQ(pkt.node_id(), 7u);
}

TEST(packet_validation) {
    RawrPacket pkt = build_packet(CMD_HEARTBEAT_PING, 1, 1, FLAG_ASYNC);
    ASSERT_TRUE(pkt.validate());
    
    pkt.set_magic(0xDEADBEEF);
    ASSERT_TRUE(!pkt.validate());
}

// =============================================================================
// Packet Builder Tests
// =============================================================================

TEST(build_heartbeat_ping) {
    RawrPacket pkt = build_heartbeat_ping(5, 100);
    
    ASSERT_TRUE(pkt.validate());
    ASSERT_EQ(pkt.cmd(), CMD_HEARTBEAT_PING);
    ASSERT_EQ(pkt.node_id(), 5u);
    ASSERT_EQ(pkt.seq(), 100u);
    ASSERT_EQ(pkt.flags(), FLAG_ASYNC);
    ASSERT_EQ(pkt.len(), 0u);  // No payload for ping
    ASSERT_TRUE(pkt.payload.empty());
}

TEST(build_heartbeat_pong) {
    RawrPacket pkt = build_heartbeat_pong(5, 100, 10, 1234567890ULL);
    
    ASSERT_TRUE(pkt.validate());
    ASSERT_EQ(pkt.cmd(), CMD_HEARTBEAT_PONG);
    ASSERT_EQ(pkt.len(), sizeof(HeartbeatPayload));
    ASSERT_EQ(pkt.payload.size(), sizeof(HeartbeatPayload));
    
    // Verify payload content
    HeartbeatPayload payload{};
    std::memcpy(&payload, pkt.payload.data(), sizeof(payload));
    ASSERT_EQ(payload.queue_depth, 10u);
    ASSERT_EQ(payload.timestamp, 1234567890ULL);
}

TEST(build_node_discover) {
    NodeInfo info{};
    info.node_id = 1;
    info.status = 0;
    info.ip_address = 0x0A000001;  // 10.0.0.1
    info.data_port = 9091;
    info.control_port = 9092;
    
    RawrPacket pkt = build_node_discover(info, 1, 1);
    
    ASSERT_TRUE(pkt.validate());
    ASSERT_EQ(pkt.cmd(), CMD_NODE_DISCOVER);
    ASSERT_EQ(pkt.len(), sizeof(NodeDiscoverPayload));
    ASSERT_EQ(pkt.payload.size(), sizeof(NodeDiscoverPayload));
}

TEST(build_inference_request) {
    InferenceRequestPayload req{};
    req.request_id = 12345;
    req.model_id = 1;
    req.batch_size = 4;
    req.seq_length = 100;
    
    RawrPacket pkt = build_inference_request(2, 50, req);
    
    ASSERT_TRUE(pkt.validate());
    ASSERT_EQ(pkt.cmd(), CMD_INFERENCE_REQ);
    ASSERT_EQ(pkt.node_id(), 2u);
    ASSERT_EQ(pkt.seq(), 50u);
    ASSERT_EQ(pkt.len(), sizeof(InferenceRequestPayload));
    ASSERT_EQ(pkt.payload.size(), sizeof(InferenceRequestPayload));
}

TEST(build_panic_abort) {
    RawrPacket pkt = build_panic_abort(3, 999, "Out of memory");
    
    ASSERT_TRUE(pkt.validate());
    ASSERT_EQ(pkt.cmd(), CMD_PANIC_ABORT);
    ASSERT_EQ(pkt.flags(), FLAG_URGENT | FLAG_BROADCAST);
    ASSERT_EQ(pkt.len(), sizeof(PanicAbortPayload));
    
    // Verify message was copied
    PanicAbortPayload payload{};
    std::memcpy(&payload, pkt.payload.data(), sizeof(payload));
    ASSERT_EQ(payload.source_node, 3u);
    ASSERT_EQ(payload.error_code, 0xFFFF);
    ASSERT_TRUE(std::strncmp(payload.message, "Out of memory", 13) == 0);
}

// =============================================================================
// CRC32 Tests
// =============================================================================

TEST(crc32_basic) {
    const char* data = "123456789";
    uint32_t crc = calculate_crc32(data, 9);
    // Known CRC32 for "123456789" is 0xCBF43926
    ASSERT_EQ(crc, 0xCBF43926u);
}

TEST(crc32_empty) {
    uint32_t crc = calculate_crc32("", 0);
    ASSERT_EQ(crc, 0u);
}

TEST(crc32_consistency) {
    const char* data = "RawrXD Test Data";
    uint32_t crc1 = calculate_crc32(data, 16);
    uint32_t crc2 = calculate_crc32(data, 16);
    ASSERT_EQ(crc1, crc2);
}

// =============================================================================
// Command Validation Tests
// =============================================================================

TEST(valid_commands) {
    ASSERT_TRUE(is_valid_command(CMD_NODE_DISCOVER));
    ASSERT_TRUE(is_valid_command(CMD_HEARTBEAT_PING));
    ASSERT_TRUE(is_valid_command(CMD_INFERENCE_REQ));
    ASSERT_TRUE(is_valid_command(CMD_TENSOR_XFER_CHUNK));
    ASSERT_TRUE(is_valid_command(CMD_PANIC_ABORT));
}

TEST(invalid_commands) {
    ASSERT_TRUE(!is_valid_command(0));
    ASSERT_TRUE(!is_valid_command(0x9999));
    ASSERT_TRUE(!is_valid_command(0xFFFFFFFF));
}

TEST(command_to_string) {
    ASSERT_TRUE(std::strcmp(command_to_string(CMD_NODE_DISCOVER), "NODE_DISCOVER") == 0);
    ASSERT_TRUE(std::strcmp(command_to_string(CMD_HEARTBEAT_PING), "HEARTBEAT_PING") == 0);
    ASSERT_TRUE(std::strcmp(command_to_string(CMD_PANIC_ABORT), "PANIC_ABORT") == 0);
    ASSERT_TRUE(std::strcmp(command_to_string(0x9999), "UNKNOWN") == 0);
}

// =============================================================================
// Payload Structure Size Tests
// =============================================================================

TEST(payload_sizes) {
    ASSERT_EQ(sizeof(NodeDiscoverPayload), 44u);
    ASSERT_EQ(sizeof(HeartbeatPayload), 32u);
    ASSERT_EQ(sizeof(RingReconfigurePayload), 8u);
    ASSERT_EQ(sizeof(InferenceRequestPayload), 28u);
    ASSERT_EQ(sizeof(InferenceAckPayload), 24u);
    ASSERT_EQ(sizeof(KVCacheSyncPayload), 24u);
    ASSERT_EQ(sizeof(ExpertRoutePayload), 16u);
    ASSERT_EQ(sizeof(TensorTransferStartPayload), 44u);
    ASSERT_EQ(sizeof(TensorTransferChunkPayload), 24u);
    ASSERT_EQ(sizeof(TensorTransferFinishPayload), 24u);
    ASSERT_EQ(sizeof(AllReducePartialPayload), 24u);
    ASSERT_EQ(sizeof(AllReduceCompletePayload), 24u);
    ASSERT_EQ(sizeof(AllGatherPayload), 20u);
    ASSERT_EQ(sizeof(WeightHotpatchPayload), 32u);
    ASSERT_EQ(sizeof(BarrierPayload), 32u);
    ASSERT_EQ(sizeof(PanicAbortPayload), 264u);
    ASSERT_EQ(sizeof(ErrorPayload), 264u);
}

// =============================================================================
// Main
// =============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD_RPC Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Packet structure tests
    RUN_TEST(packet_header_size);
    RUN_TEST(packet_default_construction);
    RUN_TEST(packet_setters);
    RUN_TEST(packet_validation);
    
    std::cout << std::endl;
    
    // Packet builder tests
    RUN_TEST(build_heartbeat_ping);
    RUN_TEST(build_heartbeat_pong);
    RUN_TEST(build_node_discover);
    RUN_TEST(build_inference_request);
    RUN_TEST(build_panic_abort);
    
    std::cout << std::endl;
    
    // CRC32 tests
    RUN_TEST(crc32_basic);
    RUN_TEST(crc32_empty);
    RUN_TEST(crc32_consistency);
    
    std::cout << std::endl;
    
    // Command validation tests
    RUN_TEST(valid_commands);
    RUN_TEST(invalid_commands);
    RUN_TEST(command_to_string);
    
    std::cout << std::endl;
    
    // Payload size tests
    RUN_TEST(payload_sizes);
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
