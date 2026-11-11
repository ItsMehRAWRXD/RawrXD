//=============================================================================
// Fabric Handshake Test - VAL-031.3 2-Node PoC
// Validates raw socket transport between two B008 nodes
//=============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>
#include "../src/fabric/fabric_linker.hpp"

using namespace RawrXD::Fabric;

// Test configuration
struct TestConfig {
    bool is_server;
    uint8_t node_id;
    uint16_t listen_port;
    const char* peer_address;
    uint16_t peer_port;
    int iterations;
};

// Print usage
void PrintUsage(const char* prog) {
    printf("Usage:\n");
    printf("  Server: %s server <node_id> <listen_port>\n", prog);
    printf("  Client: %s client <node_id> <peer_addr> <peer_port>\n", prog);
    printf("\nExample:\n");
    printf("  Terminal 1: %s server 0 31337\n", prog);
    printf("  Terminal 2: %s client 1 127.0.0.1 31337\n", prog);
}

// Run server test
bool RunServer(const TestConfig& config) {
    printf("\n");
    printf("========================================\n");
    printf("VAL-031.3 Fabric Handshake Test (SERVER)\n");
    printf("========================================\n");
    printf("Node ID: %u\n", config.node_id);
    printf("Listen Port: %u\n", config.listen_port);
    printf("\n");
    
    FabricConfig fabric_config;
    fabric_config.node_id = config.node_id;
    fabric_config.listen_port = config.listen_port;
    fabric_config.is_server = true;
    
    FabricLinker& linker = GetFabricLinker();
    
    // Initialize
    if (!linker.Initialize(fabric_config)) {
        printf("[TEST] FAILED: Initialize\n");
        return false;
    }
    
    // Accept connection
    printf("[TEST] Waiting for client connection...\n");
    if (!linker.AcceptPeer()) {
        printf("[TEST] FAILED: AcceptPeer\n");
        return false;
    }
    
    // Perform handshake
    if (!linker.PerformHandshake()) {
        printf("[TEST] FAILED: Handshake\n");
        return false;
    }
    
    // Run multiple ping/pong iterations
    printf("\n[TEST] Running %d ping/pong iterations...\n", config.iterations);
    
    for (int i = 0; i < config.iterations; i++) {
        // Wait for PING
        Packet ping;
        if (!linker.ReceivePacket(ping, 5000)) {
            printf("[TEST] FAILED: Iteration %d - Receive PING\n", i + 1);
            return false;
        }
        
        if (ping.header.command != static_cast<uint8_t>(PacketCmd::PING)) {
            printf("[TEST] FAILED: Iteration %d - Expected PING\n", i + 1);
            return false;
        }
        
        // Send PONG
        Packet pong;
        pong.InitPong(config.node_id, ping.header.block_id);
        if (!linker.SendPacket(pong)) {
            printf("[TEST] FAILED: Iteration %d - Send PONG\n", i + 1);
            return false;
        }
        
        printf("[TEST] Iteration %d/%d OK\r", i + 1, config.iterations);
    }
    
    printf("\n\n");
    
    // Get statistics
    FabricStats stats = linker.GetStats();
    
    printf("[TEST] Statistics:\n");
    printf("  Packets sent:     %llu\n", stats.packets_sent.load());
    printf("  Packets received: %llu\n", stats.packets_recv.load());
    printf("  Bytes sent:       %llu\n", stats.bytes_sent.load());
    printf("  Bytes received:   %llu\n", stats.bytes_recv.load());
    printf("  Errors:           %llu\n", stats.errors.load());
    printf("  Timeouts:         %llu\n", stats.timeouts.load());
    printf("  Avg latency:      %.2f us\n", stats.GetAvgLatencyUs());
    
    // Cleanup
    linker.Shutdown();
    
    printf("\n[TEST] PASSED: Server completed successfully\n");
    return true;
}

// Run client test
bool RunClient(const TestConfig& config) {
    printf("\n");
    printf("========================================\n");
    printf("VAL-031.3 Fabric Handshake Test (CLIENT)\n");
    printf("========================================\n");
    printf("Node ID: %u\n", config.node_id);
    printf("Peer: %s:%u\n", config.peer_address, config.peer_port);
    printf("\n");
    
    FabricConfig fabric_config;
    fabric_config.node_id = config.node_id;
    fabric_config.peer_address = config.peer_address;
    fabric_config.peer_port = config.peer_port;
    fabric_config.is_server = false;
    
    FabricLinker& linker = GetFabricLinker();
    
    // Initialize
    if (!linker.Initialize(fabric_config)) {
        printf("[TEST] FAILED: Initialize\n");
        return false;
    }
    
    // Connect to server
    printf("[TEST] Connecting to server...\n");
    if (!linker.ConnectToPeer()) {
        printf("[TEST] FAILED: ConnectToPeer\n");
        return false;
    }
    
    // Perform handshake
    if (!linker.PerformHandshake()) {
        printf("[TEST] FAILED: Handshake\n");
        return false;
    }
    
    // Run multiple ping/pong iterations
    printf("\n[TEST] Running %d ping/pong iterations...\n", config.iterations);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < config.iterations; i++) {
        auto iter_start = GetTickCount64();
        
        // Send PING
        Packet ping;
        ping.InitPing(config.node_id);
        if (!linker.SendPacket(ping)) {
            printf("[TEST] FAILED: Iteration %d - Send PING\n", i + 1);
            return false;
        }
        
        // Wait for PONG
        Packet pong;
        if (!linker.ReceivePacket(pong, 5000)) {
            printf("[TEST] FAILED: Iteration %d - Receive PONG\n", i + 1);
            return false;
        }
        
        if (pong.header.command != static_cast<uint8_t>(PacketCmd::PONG)) {
            printf("[TEST] FAILED: Iteration %d - Expected PONG\n", i + 1);
            return false;
        }
        
        auto latency = GetTickCount64() - iter_start;
        
        printf("[TEST] Iteration %d/%d OK (latency: %llu ms)\r", 
               i + 1, config.iterations, latency);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    printf("\n\n");
    
    // Get statistics
    FabricStats stats = linker.GetStats();
    
    printf("[TEST] Statistics:\n");
    printf("  Packets sent:     %llu\n", stats.packets_sent.load());
    printf("  Packets received: %llu\n", stats.packets_recv.load());
    printf("  Bytes sent:       %llu\n", stats.bytes_sent.load());
    printf("  Bytes received:   %llu\n", stats.bytes_recv.load());
    printf("  Errors:           %llu\n", stats.errors.load());
    printf("  Timeouts:         %llu\n", stats.timeouts.load());
    printf("  Avg latency:      %.2f us\n", stats.GetAvgLatencyUs());
    printf("  Total time:       %lld ms\n", total_ms);
    printf("  Throughput:       %.2f round-trips/sec\n", 
           (config.iterations * 1000.0) / total_ms);
    
    // Cleanup
    linker.Shutdown();
    
    printf("\n[TEST] PASSED: Client completed successfully\n");
    return true;
}

// Main entry point
int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    TestConfig config;
    config.iterations = 100;  // Default
    
    if (strcmp(argv[1], "server") == 0) {
        if (argc < 4) {
            PrintUsage(argv[0]);
            return 1;
        }
        config.is_server = true;
        config.node_id = static_cast<uint8_t>(atoi(argv[2]));
        config.listen_port = static_cast<uint16_t>(atoi(argv[3]));
        
        if (argc > 4) {
            config.iterations = atoi(argv[4]);
        }
        
        return RunServer(config) ? 0 : 1;
        
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc < 5) {
            PrintUsage(argv[0]);
            return 1;
        }
        config.is_server = false;
        config.node_id = static_cast<uint8_t>(atoi(argv[2]));
        config.peer_address = argv[3];
        config.peer_port = static_cast<uint16_t>(atoi(argv[4]));
        
        if (argc > 5) {
            config.iterations = atoi(argv[5]);
        }
        
        return RunClient(config) ? 0 : 1;
        
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        PrintUsage(argv[0]);
        return 1;
    }
}
