//=============================================================================
// SequentialBlowoffValve_SmokeTest.cpp - Smoke test for "Never Ending Rainbow Road"
// Tests: Initialization, allocation, access, eviction, and pressure management
//=============================================================================

#include "SequentialBlowoffValve.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace RawrXD::Memory;

bool g_testsPassed = true;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " at line " << __LINE__ << "\n"; \
            g_testsPassed = false; \
        } else { \
            std::cout << "[PASS] " << msg << "\n"; \
        } \
    } while(0)

void TestInitialization() {
    std::cout << "\n=== Test: Initialization ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap.bin";
    config.gpu0_max_bytes = 1024 * 1024 * 1024; // 1GB for testing
    config.gpu1_max_bytes = 512 * 1024 * 1024;  // 512MB
    config.ram_max_bytes = 2ULL * 1024 * 1024 * 1024; // 2GB
    
    SequentialBlowoffValve valve(config);
    
    TEST_ASSERT(!valve.IsRunning(), "Valve starts not running");
    TEST_ASSERT(valve.Initialize(), "Initialize returns true");
    TEST_ASSERT(valve.IsRunning(), "Valve is running after init");
    
    valve.Shutdown();
    TEST_ASSERT(!valve.IsRunning(), "Valve stops after shutdown");
}

void TestBlockAllocation() {
    std::cout << "\n=== Test: Block Allocation ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap2.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for allocation test");
    
    // Allocate some blocks
    uint64_t block1 = valve.AllocateBlock(1024 * 1024, true); // 1MB KV cache
    uint64_t block2 = valve.AllocateBlock(4 * 1024 * 1024, false); // 4MB weights
    uint64_t block3 = valve.AllocateBlock(2 * 1024 * 1024, true); // 2MB KV cache
    
    TEST_ASSERT(block1 != 0, "Block 1 allocated");
    TEST_ASSERT(block2 != 0, "Block 2 allocated");
    TEST_ASSERT(block3 != 0, "Block 3 allocated");
    TEST_ASSERT(block1 != block2 && block2 != block3, "Blocks have unique IDs");
    
    // Free blocks
    TEST_ASSERT(valve.FreeBlock(block1), "Block 1 freed");
    TEST_ASSERT(valve.FreeBlock(block2), "Block 2 freed");
    TEST_ASSERT(valve.FreeBlock(block3), "Block 3 freed");
    
    // Double-free should fail
    TEST_ASSERT(!valve.FreeBlock(block1), "Double-free returns false");
    
    valve.Shutdown();
}

void TestMemoryAccess() {
    std::cout << "\n=== Test: Memory Access ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap3.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for access test");
    
    // Allocate and access
    uint64_t block_id = valve.AllocateBlock(1024, true);
    TEST_ASSERT(block_id != 0, "Block allocated for access test");
    
    // Access should work (may fault from SSD)
    void* ptr = valve.Access(block_id);
    TEST_ASSERT(ptr != nullptr, "Access returns non-null pointer");
    
    // Write some data
    std::memset(ptr, 0xAB, 1024);
    
    // Access again should return same pointer
    void* ptr2 = valve.Access(block_id);
    TEST_ASSERT(ptr == ptr2, "Repeated access returns same pointer");
    
    // Verify data
    unsigned char* data = static_cast<unsigned char*>(ptr);
    TEST_ASSERT(data[0] == 0xAB, "Data persists after access");
    TEST_ASSERT(data[512] == 0xAB, "Data persists in middle");
    
    valve.FreeBlock(block_id);
    valve.Shutdown();
}

void TestPinning() {
    std::cout << "\n=== Test: Block Pinning ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap4.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for pinning test");
    
    uint64_t block_id = valve.AllocateBlock(1024, true);
    TEST_ASSERT(block_id != 0, "Block allocated for pinning test");
    
    // Pin should work
    TEST_ASSERT(valve.Pin(block_id), "Pin returns true");
    TEST_ASSERT(valve.Pin(block_id), "Double pin returns true");
    
    // Unpin should work
    TEST_ASSERT(valve.Unpin(block_id), "Unpin returns true");
    TEST_ASSERT(valve.Unpin(block_id), "Double unpin returns true");
    
    // Pin non-existent block should fail
    TEST_ASSERT(!valve.Pin(999999), "Pin non-existent returns false");
    
    valve.FreeBlock(block_id);
    valve.Shutdown();
}

void TestPressureReporting() {
    std::cout << "\n=== Test: Pressure Reporting ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap5.bin";
    config.gpu0_max_bytes = 100 * 1024 * 1024; // 100MB
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for pressure test");
    
    // Initially should be 0 pressure
    float pressure = valve.GetPressure(Tier::GPU0_R9700);
    TEST_ASSERT(pressure >= 0.0f && pressure <= 1.0f, "Pressure is valid range");
    TEST_ASSERT(pressure < 0.01f, "Initial pressure near zero");
    
    // Should not need blowoff initially
    TEST_ASSERT(!valve.ShouldBlowOff(Tier::GPU0_R9700), "No blowoff needed initially");
    
    valve.Shutdown();
}

void TestStatistics() {
    std::cout << "\n=== Test: Statistics ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap6.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for stats test");
    
    // Get initial stats
    auto stats1 = valve.GetStats();
    TEST_ASSERT(stats1.total_blocks_allocated == 0, "Initial allocated is 0");
    
    // Allocate some blocks
    valve.AllocateBlock(1024, true);
    valve.AllocateBlock(2048, false);
    
    // Get updated stats
    auto stats2 = valve.GetStats();
    TEST_ASSERT(stats2.total_blocks_allocated == 2, "Allocated count is 2");
    
    // Get report
    std::string report = valve.GetRainbowRoadReport();
    TEST_ASSERT(!report.empty(), "Report is not empty");
    TEST_ASSERT(report.find("RAINBOW ROAD") != std::string::npos, "Report contains RAINBOW ROAD");
    
    valve.Shutdown();
}

void TestEviction() {
    std::cout << "\n=== Test: Eviction ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap7.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for eviction test");
    
    // Allocate a block
    uint64_t block_id = valve.AllocateBlock(1024, true);
    TEST_ASSERT(block_id != 0, "Block allocated for eviction test");
    
    // Access to bring into RAM
    void* ptr = valve.Access(block_id);
    TEST_ASSERT(ptr != nullptr, "Access works before eviction");
    
    // Evict to SSD
    TEST_ASSERT(valve.EvictToTier(block_id, Tier::SSD_NVMe), "Evict to SSD returns true");
    
    // Access should still work (will fault from SSD)
    void* ptr2 = valve.Access(block_id);
    TEST_ASSERT(ptr2 != nullptr, "Access works after eviction");
    
    valve.FreeBlock(block_id);
    valve.Shutdown();
}

void TestConcurrentAccess() {
    std::cout << "\n=== Test: Concurrent Access ===\n";
    
    BlowoffConfig config;
    config.ssd_swap_path = "D:\\RawrXD_Cache\\test_swap8.bin";
    
    SequentialBlowoffValve valve(config);
    TEST_ASSERT(valve.Initialize(), "Initialize for concurrent test");
    
    // Allocate multiple blocks
    std::vector<uint64_t> blocks;
    for (int i = 0; i < 10; i++) {
        uint64_t id = valve.AllocateBlock(1024, true);
        TEST_ASSERT(id != 0, "Block allocated in concurrent test");
        blocks.push_back(id);
    }
    
    // Concurrent access from multiple threads
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int t = 0; t < 4; t++) {
        threads.emplace_back([&valve, &blocks, &success_count]() {
            for (int i = 0; i < 100; i++) {
                uint64_t block_id = blocks[i % blocks.size()];
                void* ptr = valve.Access(block_id);
                if (ptr) {
                    success_count++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    TEST_ASSERT(success_count == 400, "All concurrent accesses succeeded");
    
    for (auto id : blocks) {
        valve.FreeBlock(id);
    }
    valve.Shutdown();
}

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║   SequentialBlowoffValve Smoke Test - Never Ending Rainbow Road ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    // Create cache directory
    #ifdef _WIN32
    CreateDirectoryA("D:\\RawrXD_Cache", nullptr);
    #else
    mkdir("/tmp/rawrxd_cache", 0755);
    #endif
    
    auto start_time = std::chrono::steady_clock::now();
    
    TestInitialization();
    TestBlockAllocation();
    TestMemoryAccess();
    TestPinning();
    TestPressureReporting();
    TestStatistics();
    TestEviction();
    TestConcurrentAccess();
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "\n╔═══════════════════════════════════════════════════════════════╗\n";
    if (g_testsPassed) {
        std::cout << "║                    ALL TESTS PASSED ✓                         ║\n";
    } else {
        std::cout << "║                    SOME TESTS FAILED ✗                        ║\n";
    }
    std::cout << "║                    Duration: " << duration.count() << " ms                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    return g_testsPassed ? 0 : 1;
}
