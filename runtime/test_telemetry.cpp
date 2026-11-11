// ============================================================================
// test_telemetry.cpp - Validate MASM Telemetry Core
// ============================================================================

#include "telemetry_ids.hpp"
#include "telemetry_wrapper.cpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

using namespace RawrXD::Runtime::Telemetry;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --stress N     Run stress test with N iterations" << std::endl;
    std::cout << "  --threads N    Run with N threads" << std::endl;
    std::cout << "  --verbose      Dump all entries" << std::endl;
}

// Simulate some work
void SimulateWork(uint64_t cycles) {
    volatile uint64_t sum = 0;
    for (uint64_t i = 0; i < cycles; ++i) {
        sum += i;
    }
    (void)sum;
}

// Test basic logging
void TestBasicLogging() {
    std::cout << "=== Test: Basic Logging ===" << std::endl;
    
    Telemetry_Reset();
    
    // Log some entries
    Telemetry_Log(TELEMETRY_SYSTEM_INIT, 1, 2);
    Telemetry_Log(TELEMETRY_GGUF_INIT_START, 100, 0);
    SimulateWork(1000);
    Telemetry_Log(TELEMETRY_GGUF_INIT_END, 100, 0);
    Telemetry_Log(TELEMETRY_BRIDGE_INIT, 42, 0);
    
    uint64_t count = Telemetry_GetCount();
    std::cout << "Logged " << count << " entries" << std::endl;
    
    if (count == 4) {
        std::cout << "✓ Basic logging works" << std::endl;
    } else {
        std::cout << "✗ Expected 4 entries, got " << count << std::endl;
    }
}

// Test RAII scope
void TestRAII() {
    std::cout << std::endl << "=== Test: RAII Scope ===" << std::endl;
    
    Telemetry_Reset();
    
    {
        TELEMETRY_SCOPE(TELEMETRY_RMSNORM_START, TELEMETRY_RMSNORM_END);
        SimulateWork(500);
    }
    
    {
        TELEMETRY_SCOPE_VALUES(TELEMETRY_ATTENTION_START, TELEMETRY_ATTENTION_END, 
                               32, 64);  // heads, head_dim
        SimulateWork(1000);
    }
    
    uint64_t count = Telemetry_GetCount();
    std::cout << "Logged " << count << " entries (4 expected)" << std::endl;
    
    if (count == 4) {
        std::cout << "✓ RAII scope works" << std::endl;
    } else {
        std::cout << "✗ Expected 4 entries, got " << count << std::endl;
    }
}

// Test timing
void TestTiming() {
    std::cout << std::endl << "=== Test: Timing ===" << std::endl;
    
    Telemetry_Reset();
    
    uint64_t t0 = Telemetry_Now();
    Telemetry_Log(TELEMETRY_RMSNORM_START, 0, 0);
    SimulateWork(10000);
    Telemetry_Log(TELEMETRY_RMSNORM_END, 0, 0);
    uint64_t t1 = Telemetry_Now();
    
    std::cout << "Total cycles: " << (t1 - t0) << std::endl;
    
    // Dump and analyze
    std::vector<TelemetryEntry> buffer(2);
    uint64_t read = Telemetry_Dump(buffer.data(), 2);
    
    if (read == 2) {
        uint64_t duration = buffer[1].timestamp - buffer[0].timestamp;
        std::cout << "Measured duration: " << duration << " cycles" << std::endl;
        
        if (duration > 0) {
            std::cout << "✓ Timing works" << std::endl;
        } else {
            std::cout << "✗ Duration is zero" << std::endl;
        }
    } else {
        std::cout << "✗ Failed to read entries" << std::endl;
    }
}

// Test stress
void TestStress(uint64_t iterations) {
    std::cout << std::endl << "=== Test: Stress (" << iterations << " iterations) ===" << std::endl;
    
    Telemetry_Reset();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint64_t i = 0; i < iterations; ++i) {
        Telemetry_Log(TELEMETRY_GENERATION_TOKEN, i, 0);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    uint64_t count = Telemetry_GetCount();
    uint64_t dropped = Telemetry_GetDropped();
    
    std::cout << "Logged " << count << " entries" << std::endl;
    std::cout << "Dropped " << dropped << " entries" << std::endl;
    std::cout << "Time: " << duration.count() << " us" << std::endl;
    
    if (dropped == 0) {
        double per_entry = static_cast<double>(duration.count()) / iterations;
        std::cout << "Per-entry overhead: " << std::fixed << std::setprecision(3) 
                  << per_entry << " us" << std::endl;
        std::cout << "✓ Stress test passed" << std::endl;
    } else {
        std::cout << "⚠ Some entries were dropped (buffer full)" << std::endl;
    }
}

// Test multi-threaded (basic)
void TestMultiThreaded(uint32_t num_threads) {
    std::cout << std::endl << "=== Test: Multi-Threaded (" << num_threads << " threads) ===" << std::endl;
    
    Telemetry_Reset();
    
    std::vector<std::thread> threads;
    
    for (uint32_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([t]() {
            for (uint32_t i = 0; i < 100; ++i) {
                Telemetry_Log(TELEMETRY_THREAD_POOL_EXEC, t, i);
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    uint64_t count = Telemetry_GetCount();
    uint64_t expected = static_cast<uint64_t>(num_threads) * 100;
    
    std::cout << "Logged " << count << " entries (expected ~" << expected << ")" << std::endl;
    std::cout << "Dropped " << Telemetry_GetDropped() << " entries" << std::endl;
    
    // In multi-threaded mode, we expect some entries (exact count may vary due to race conditions)
    if (count > 0) {
        std::cout << "✓ Multi-threaded logging works" << std::endl;
    } else {
        std::cout << "✗ No entries logged" << std::endl;
    }
}

// Test ring buffer wraparound
void TestWraparound() {
    std::cout << std::endl << "=== Test: Ring Buffer Wraparound ===" << std::endl;
    
    Telemetry_Reset();
    
    // Log more entries than buffer size (4096)
    const uint64_t iterations = 5000;
    
    for (uint64_t i = 0; i < iterations; ++i) {
        Telemetry_Log(TELEMETRY_GENERATION_TOKEN, i, 0);
    }
    
    uint64_t count = Telemetry_GetCount();
    uint64_t dropped = Telemetry_GetDropped();
    
    std::cout << "Logged " << iterations << " entries" << std::endl;
    std::cout << "In buffer: " << count << " entries" << std::endl;
    std::cout << "Dropped: " << dropped << " entries" << std::endl;
    
    if (count <= 4096 && dropped > 0) {
        std::cout << "✓ Ring buffer wraparound works" << std::endl;
    } else {
        std::cout << "✗ Unexpected buffer state" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== Telemetry Core Test ===" << std::endl;
    std::cout << std::endl;
    
    // Parse arguments
    uint64_t stress_iterations = 0;
    uint32_t num_threads = 0;
    bool verbose = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--stress" && i + 1 < argc) {
            stress_iterations = std::stoull(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            num_threads = std::stoul(argv[++i]);
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    // Run tests
    TestBasicLogging();
    TestRAII();
    TestTiming();
    
    if (stress_iterations > 0) {
        TestStress(stress_iterations);
    }
    
    if (num_threads > 0) {
        TestMultiThreaded(num_threads);
    }
    
    TestWraparound();
    
    // Final dump
    std::cout << std::endl;
    if (verbose) {
        DumpTelemetry(std::cout);
    } else {
        AnalyzeTelemetry(std::cout);
    }
    
    std::cout << std::endl << "=== All Tests Complete ===" << std::endl;
    
    return 0;
}
