//=============================================================================
// Jukebox Stream Test - VAL-030.1 Validation
// Tests the mechanical streaming layer without model complexity
//=============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include <random>
#include <chrono>

// Include Jukebox headers
#include "../src/memory/jukebox.hpp"
#include "../src/memory/b008_format.hpp"

using namespace RawrXD::Jukebox;
using namespace RawrXD::B008;

// Test configuration
struct TestConfig {
    const wchar_t* test_file;       // Path to test B008 file
    uint32_t num_blocks;            // Number of blocks in test file
    uint32_t block_size;            // Size of each block (bytes)
    uint32_t test_duration_ms;      // How long to run test
    uint32_t random_seed;           // For reproducible tests
};

// Test results
struct TestResults {
    uint64_t requests_submitted;
    uint64_t requests_completed;
    uint64_t buffer_starvations;
    double avg_queue_depth;
    double avg_io_latency_ms;
    double p50_latency_ms;
    double p99_latency_ms;
    bool passed;
    const char* failure_reason;
};

// Generate a synthetic B008 test file
bool GenerateTestFile(const TestConfig& config) {
    printf("[Test] Generating synthetic B008 file...\n");
    printf("[Test] Blocks: %u, Block size: %u MB, Total: %.2f GB\n",
           config.num_blocks,
           config.block_size / (1024 * 1024),
           (config.num_blocks * config.block_size) / (1024.0 * 1024 * 1024));
    
    HANDLE hFile = CreateFileW(
        config.test_file,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Test] ERROR: Failed to create test file\n");
        return false;
    }
    
    // Write B008 header
    Header header;
    memcpy(header.magic, "B008", 4);
    header.version = 1;
    header.tensor_count = config.num_blocks;  // 1 tensor per block for test
    header.block_count = config.num_blocks;
    header.weight_offset = sizeof(Header);
    header.index_offset = sizeof(Header) + (config.num_blocks * config.block_size);
    header.min_block_size = config.block_size;
    header.max_block_size = config.block_size;
    header.flags = 0;
    header.reserved = 0;
    
    DWORD written = 0;
    WriteFile(hFile, &header, sizeof(header), &written, nullptr);
    
    // Generate random data for each block
    std::mt19937 rng(config.random_seed);
    std::uniform_int_distribution<uint32_t> dist;
    
    uint8_t* buffer = new uint8_t[config.block_size];
    
    for (uint32_t i = 0; i < config.num_blocks; i++) {
        // Fill with random data (verifiable pattern)
        uint32_t* ptr = reinterpret_cast<uint32_t*>(buffer);
        for (size_t j = 0; j < config.block_size / 4; j++) {
            ptr[j] = dist(rng) ^ i;  // Block-specific pattern
        }
        
        WriteFile(hFile, buffer, config.block_size, &written, nullptr);
        
        if ((i + 1) % 10 == 0) {
            printf("[Test] Written %u/%u blocks...\r", i + 1, config.num_blocks);
        }
    }
    
    printf("\n[Test] Test file generated: %ls\n", config.test_file);
    
    delete[] buffer;
    CloseHandle(hFile);
    return true;
}

// Run the Jukebox stream test
TestResults RunJukeboxTest(const TestConfig& config) {
    TestResults results = {};
    results.passed = false;
    
    printf("\n[TEST] Starting Jukebox Stream Test\n");
    printf("[TEST] =============================\n\n");
    
    // Initialize Jukebox
    ControlBlock& jukebox = GetJukebox();
    
    if (!jukebox.Initialize(config.test_file, config.block_size)) {
        results.failure_reason = "Failed to initialize Jukebox";
        return results;
    }
    
    // Start worker thread
    Worker worker;
    if (!worker.Start(&jukebox)) {
        results.failure_reason = "Failed to start worker thread";
        jukebox.Shutdown();
        return results;
    }
    
    // Generate random access pattern
    std::mt19937 rng(config.random_seed);
    std::uniform_int_distribution<uint32_t> block_dist(0, config.num_blocks - 1);
    
    // Latency tracking
    std::vector<double> latencies;
    latencies.reserve(config.num_blocks);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Submit requests in a pattern that simulates transformer inference
    // Sequential with occasional jumps (attention patterns)
    uint32_t current_block = 0;
    uint32_t requests_submitted = 0;
    
    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        
        if (elapsed >= config.test_duration_ms) {
            break;
        }
        
        // Submit up to lookahead requests
        uint32_t target_queue_depth = jukebox.lookahead;
        
        while (jukebox.current_queue_depth.load() < target_queue_depth &&
               requests_submitted < config.num_blocks) {
            
            // 80% sequential, 20% random (simulates attention jumps)
            uint32_t block_id;
            if (rng() % 100 < 80) {
                block_id = current_block;
                current_block = (current_block + 1) % config.num_blocks;
            } else {
                block_id = block_dist(rng);
            }
            
            // Priority: higher for sequential (prefetch), lower for random
            uint32_t priority = (block_id == current_block - 1) ? 100 : 50;
            
            jukebox.PushRequest(block_id, priority);
            requests_submitted++;
        }
        
        // Small delay to simulate compute time
        Sleep(1);
    }
    
    // Wait for completion
    printf("[TEST] Waiting for completion...\n");
    Sleep(1000);
    
    // Stop worker
    worker.Stop();
    worker.Join();
    
    // Collect results
    auto stats = jukebox.GetStats();
    results.requests_submitted = stats.submitted;
    results.requests_completed = stats.completed;
    results.buffer_starvations = stats.starvations;
    results.avg_queue_depth = stats.queue_depth;
    
    // Calculate pass/fail
    results.passed = true;
    
    if (results.buffer_starvations > 0) {
        results.passed = false;
        results.failure_reason = "Buffer starvation detected";
    }
    
    if (results.requests_completed < results.requests_submitted * 0.95) {
        results.passed = false;
        results.failure_reason = "Completion rate below 95%";
    }
    
    // Cleanup
    jukebox.Shutdown();
    
    return results;
}

// Print test results
void PrintResults(const TestResults& results) {
    printf("\n[RESULTS] Jukebox Stream Test\n");
    printf("[RESULTS] ===================\n");
    printf("  Requests Submitted:  %llu\n", results.requests_submitted);
    printf("  Requests Completed:  %llu\n", results.requests_completed);
    printf("  Buffer Starvations:  %llu\n", results.buffer_starvations);
    printf("  Avg Queue Depth:     %.2f\n", results.avg_queue_depth);
    printf("  Completion Rate:     %.2f%%\n",
           (results.requests_completed * 100.0) / results.requests_submitted);
    printf("\n");
    
    if (results.passed) {
        printf("[PASS] VAL-030.1 Jukebox Stream Test\n");
    } else {
        printf("[FAIL] VAL-030.1 Jukebox Stream Test: %s\n", results.failure_reason);
    }
}

// Main entry point
int wmain(int argc, wchar_t* argv[]) {
    printf("RawrXD VAL-030.1 Jukebox Stream Test\n");
    printf("====================================\n\n");
    
    // Default test configuration
    TestConfig config = {
        L"test_data\\test_70b.b008",  // Test file path
        1000,                          // 1000 blocks
        256 * 1024 * 1024,            // 256MB per block
        10000,                         // 10 second test
        42                             // Random seed
    };
    
    // Parse command line
    if (argc > 1) {
        config.num_blocks = _wtoi(argv[1]);
    }
    if (argc > 2) {
        config.block_size = _wtoi(argv[2]) * 1024 * 1024;
    }
    
    // Create test directory
    CreateDirectoryW(L"test_data", nullptr);
    
    // Generate test file
    if (!GenerateTestFile(config)) {
        printf("[ERROR] Failed to generate test file\n");
        return 1;
    }
    
    // Run test
    TestResults results = RunJukeboxTest(config);
    PrintResults(results);
    
    // Cleanup test file
    DeleteFileW(config.test_file);
    
    return results.passed ? 0 : 1;
}
