// ============================================================================
// VAL-029.1: Local Fabric Validation
// Tests the ResidencyTable, LoopbackTransport, and FabricOrchestrator
// without actual network - validates abstraction layer before TCP
// ============================================================================

#include "../src/fabric/TensorResidency.h"
#include "../src/fabric/FabricMessages.h"
#include "../src/fabric/LoopbackTransport.h"
#include "../src/fabric/FabricOrchestrator.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <random>

using namespace RawrXD::Fabric;

// ============================================================================
// Test Utilities
// ============================================================================

static uint64_t g_testTensorId = 1;

uint64_t GenerateTensorId(const char* name) {
    // Simple FNV-1a hash
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(name);
    uint64_t hash = 14695981039346656037ULL;
    while (*bytes) {
        hash ^= *bytes++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

void PrintResult(const char* test, bool passed) {
    std::cout << "  [" << (passed ? "PASS" : "FAIL") << "] " << test << std::endl;
}

// ============================================================================
// Gate 1: Residency Table Tests
// ============================================================================

bool TestResidencyTable_Basic() {
    ResidencyTable table;
    
    ResidencyEntry entry;
    entry.tensorId = 12345;
    entry.offset = 0x10000000;
    entry.size = 4096;
    entry.nodeId = 0;
    entry.state = ResidencyState::RAM_HOT;
    entry.version = 1;
    
    bool registered = table.RegisterTensor(12345, entry);
    if (!registered) return false;
    
    ResidencyEntry lookup;
    bool found = table.Lookup(12345, lookup);
    if (!found) return false;
    if (lookup.offset != 0x10000000) return false;
    if (lookup.state != ResidencyState::RAM_HOT) return false;
    
    return true;
}

bool TestResidencyTable_StateMachine() {
    ResidencyTable table;
    
    // Register tensor
    ResidencyEntry entry;
    entry.tensorId = 1;
    entry.state = ResidencyState::RAM_WARM;
    table.RegisterTensor(1, entry);
    
    // Test valid transition: WARM -> HOT
    if (!table.UpdateState(1, ResidencyState::RAM_HOT)) return false;
    
    // Test lock for compute
    if (!table.TryLockForCompute(1)) return false;
    
    ResidencyEntry lookup;
    table.Lookup(1, lookup);
    if (lookup.state != ResidencyState::COMPUTE_LOCKED) return false;
    
    // Test invalid transition: LOCKED -> WARM (should fail)
    if (table.UpdateState(1, ResidencyState::RAM_WARM)) return false;
    
    // Unlock
    if (!table.UnlockFromCompute(1)) return false;
    
    // Now transition should work
    if (!table.UpdateState(1, ResidencyState::RAM_WARM)) return false;
    
    return true;
}

bool TestResidencyTable_Lease() {
    ResidencyTable table;
    
    ResidencyEntry entry;
    entry.tensorId = 1;
    entry.state = ResidencyState::RAM_HOT;
    table.RegisterTensor(1, entry);
    
    // Acquire lease
    TensorLease lease;
    if (!table.AcquireLease(1, 100, lease)) return false;
    if (lease.tensorId != 1) return false;
    if (lease.version == 0) return false;
    
    // Try to acquire again (should fail - already leased)
    TensorLease lease2;
    if (table.AcquireLease(1, 100, lease2)) return false;
    
    // Release lease
    if (!table.ReleaseLease(lease)) return false;
    
    // Now should be able to acquire again
    if (!table.AcquireLease(1, 100, lease2)) return false;
    
    return true;
}

bool TestResidencyTable_ConcurrentAccess() {
    ResidencyTable table;
    
    // Register many tensors
    const int NUM_TENSORS = 1000;
    for (int i = 0; i < NUM_TENSORS; i++) {
        ResidencyEntry entry;
        entry.tensorId = i;
        entry.state = ResidencyState::RAM_WARM;
        table.RegisterTensor(i, entry);
    }
    
    // Concurrent readers and writers
    std::atomic<int> successes{0};
    std::atomic<int> failures{0};
    
    auto reader = [&]() {
        for (int i = 0; i < 1000; i++) {
            ResidencyEntry entry;
            if (table.Lookup(i % NUM_TENSORS, entry)) {
                successes++;
            } else {
                failures++;
            }
        }
    };
    
    auto writer = [&]() {
        for (int i = 0; i < 500; i++) {
            table.UpdateState(i % NUM_TENSORS, ResidencyState::RAM_HOT);
        }
    };
    
    std::thread t1(reader);
    std::thread t2(reader);
    std::thread t3(writer);
    std::thread t4(writer);
    
    t1.join();
    t2.join();
    t3.join();
    t4.join();
    
    // Should have mostly successes
    return successes > 3500;
}

// ============================================================================
// Gate 2: Loopback Transport Tests
// ============================================================================

bool TestLoopbackTransport_BasicSendReceive() {
    LoopbackTransport transport;
    if (!transport.Initialize(1)) return false;
    
    // Connect to "node 2"
    transport.ConnectToNode(2, "loopback");
    
    std::atomic<bool> received{false};
    std::atomic<uint32_t> receivedFrom{0};
    
    transport.SetMessageHandler([&](const FabricMessage& msg, uint32_t fromNode) {
        received = true;
        receivedFrom = fromNode;
    });
    
    // Send message
    FabricMessage msg;
    msg.header.op = FabricOp::LOOKUP_TENSOR;
    msg.header.payloadSize = sizeof(LookupTensorRequest);
    msg.payload.lookupReq.tensorId = 12345;
    
    bool sent = transport.Send(2, msg);
    if (!sent) return false;
    
    // Wait for receive
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (!received) return false;
    if (receivedFrom != 1) return false;  // Should be from node 1 (us)
    
    transport.Shutdown();
    return true;
}

bool TestLoopbackTransport_LatencySimulation() {
    LoopbackTransport transport;
    transport.Initialize(1);
    transport.ConnectToNode(2, "loopback");
    
    // Set 10ms simulated latency
    transport.SimulateLatency(10000);  // 10ms in microseconds
    
    std::atomic<int> count{0};
    transport.SetMessageHandler([&](const FabricMessage& msg, uint32_t fromNode) {
        count++;
    });
    
    auto start = std::chrono::high_resolution_clock::now();
    
    FabricMessage msg;
    msg.header.op = FabricOp::HEARTBEAT;
    transport.Send(2, msg);
    
    // Wait for receive
    while (count == 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    transport.Shutdown();
    
    // Should have taken at least 10ms due to simulated latency
    return elapsed >= 10;
}

bool TestLoopbackTransport_Statistics() {
    LoopbackTransport transport;
    transport.Initialize(1);
    transport.ConnectToNode(2, "loopback");
    
    transport.SetMessageHandler([](const FabricMessage& msg, uint32_t fromNode) {
        // Just receive
    });
    
    // Send 10 messages
    FabricMessage msg;
    msg.header.op = FabricOp::HEARTBEAT;
    for (int i = 0; i < 10; i++) {
        transport.Send(2, msg);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    uint64_t sent = transport.GetMessagesSent();
    uint64_t received = transport.GetMessagesReceived();
    
    transport.Shutdown();
    
    return sent == 10 && received == 10;
}

// ============================================================================
// Gate 3: Fabric Orchestrator Integration
// ============================================================================

bool TestFabricOrchestrator_LocalResolution() {
    LoopbackTransport transport;
    transport.Initialize(1);
    
    FabricOrchestrator orchestrator;
    orchestrator.Initialize(1, &transport);
    
    // Register a local tensor
    char dummyData[1024];
    uint64_t tensorId = GenerateTensorId("test_tensor");
    orchestrator.RegisterLocalTensor(tensorId, dummyData, 1024);
    
    // Resolve it
    void* ptr = orchestrator.ResolveTensor(tensorId);
    if (ptr != dummyData) return false;
    
    // Check stats
    auto stats = orchestrator.GetStats();
    if (stats.localHits != 1) return false;
    
    orchestrator.Shutdown();
    transport.Shutdown();
    return true;
}

bool TestFabricOrchestrator_Prefetch() {
    LoopbackTransport transport;
    transport.Initialize(1);
    
    FabricOrchestrator orchestrator;
    orchestrator.Initialize(1, &transport);
    
    // Prefetch a tensor
    uint64_t tensorId = GenerateTensorId("prefetch_test");
    orchestrator.PrefetchTensor(tensorId, 128);
    
    // Check stats
    auto stats = orchestrator.GetStats();
    
    orchestrator.Shutdown();
    transport.Shutdown();
    
    return stats.prefetches == 1;
}

bool TestFabricOrchestrator_LeaseManagement() {
    LoopbackTransport transport;
    transport.Initialize(1);
    
    FabricOrchestrator orchestrator;
    orchestrator.Initialize(1, &transport);
    
    // Register tensor
    char dummyData[1024];
    uint64_t tensorId = GenerateTensorId("lease_test");
    orchestrator.RegisterLocalTensor(tensorId, dummyData, 1024);
    
    // Acquire lease
    bool acquired = orchestrator.AcquireTensorLease(tensorId, 100);
    if (!acquired) return false;
    
    // Try to acquire again (should succeed - same owner)
    acquired = orchestrator.AcquireTensorLease(tensorId, 100);
    if (!acquired) return false;
    
    // Release
    orchestrator.ReleaseTensorLease(tensorId);
    
    orchestrator.Shutdown();
    transport.Shutdown();
    return true;
}

// ============================================================================
// Gate 4: Stress Test
// ============================================================================

bool TestStress_HighThroughput() {
    LoopbackTransport transport;
    transport.Initialize(1);
    transport.ConnectToNode(2, "loopback");
    
    std::atomic<int> received{0};
    transport.SetMessageHandler([&](const FabricMessage& msg, uint32_t fromNode) {
        received++;
    });
    
    // Send 10000 messages as fast as possible
    FabricMessage msg;
    msg.header.op = FabricOp::HEARTBEAT;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 10000; i++) {
        transport.Send(2, msg);
    }
    
    // Wait for all to be received
    while (received < 10000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    transport.Shutdown();
    
    // Calculate throughput
    double throughput = 10000.0 / (elapsedMs / 1000.0);
    std::cout << "    Throughput: " << throughput << " msgs/sec" << std::endl;
    
    return received == 10000;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-029.1: Local Fabric Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Gate 1: Residency Table
    std::cout << "\nGate 1: Residency Table" << std::endl;
    std::cout << "------------------------" << std::endl;
    
    if (TestResidencyTable_Basic()) { passed++; PrintResult("Basic registration/lookup", true); }
    else { failed++; PrintResult("Basic registration/lookup", false); }
    
    if (TestResidencyTable_StateMachine()) { passed++; PrintResult("State machine transitions", true); }
    else { failed++; PrintResult("State machine transitions", false); }
    
    if (TestResidencyTable_Lease()) { passed++; PrintResult("Lease acquisition/release", true); }
    else { failed++; PrintResult("Lease acquisition/release", false); }
    
    if (TestResidencyTable_ConcurrentAccess()) { passed++; PrintResult("Concurrent access", true); }
    else { failed++; PrintResult("Concurrent access", false); }
    
    // Gate 2: Loopback Transport
    std::cout << "\nGate 2: Loopback Transport" << std::endl;
    std::cout << "---------------------------" << std::endl;
    
    if (TestLoopbackTransport_BasicSendReceive()) { passed++; PrintResult("Basic send/receive", true); }
    else { failed++; PrintResult("Basic send/receive", false); }
    
    if (TestLoopbackTransport_LatencySimulation()) { passed++; PrintResult("Latency simulation", true); }
    else { failed++; PrintResult("Latency simulation", false); }
    
    if (TestLoopbackTransport_Statistics()) { passed++; PrintResult("Statistics tracking", true); }
    else { failed++; PrintResult("Statistics tracking", false); }
    
    // Gate 3: Fabric Orchestrator
    std::cout << "\nGate 3: Fabric Orchestrator" << std::endl;
    std::cout << "----------------------------" << std::endl;
    
    if (TestFabricOrchestrator_LocalResolution()) { passed++; PrintResult("Local tensor resolution", true); }
    else { failed++; PrintResult("Local tensor resolution", false); }
    
    if (TestFabricOrchestrator_Prefetch()) { passed++; PrintResult("Prefetch operation", true); }
    else { failed++; PrintResult("Prefetch operation", false); }
    
    if (TestFabricOrchestrator_LeaseManagement()) { passed++; PrintResult("Lease management", true); }
    else { failed++; PrintResult("Lease management", false); }
    
    // Gate 4: Stress
    std::cout << "\nGate 4: Stress Tests" << std::endl;
    std::cout << "---------------------" << std::endl;
    
    if (TestStress_HighThroughput()) { passed++; PrintResult("High throughput (10K msgs)", true); }
    else { failed++; PrintResult("High throughput (10K msgs)", false); }
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed == 0 ? 0 : 1;
}
