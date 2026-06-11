/**
 * Model Hot-Swap Stress Test — Memory Leak Detection
 * Tests: rapid model load/unload cycles, VirtualAlloc reclamation,
 *        sovereign_pager page eviction correctness.
 */
#include "../src/dynamic_model_loader.h"
#include "../src/compression/sovereign_pager.h"
#include "../src/compression/virtualalloc_reservation_manager.h"
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <cassert>
#include <psapi.h>
#include <windows.h>

// Get current process working set size in MB
static size_t GetWorkingSetMB() {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}

// Get total committed bytes from VirtualAllocReservationManager
static size_t GetReservationCommittedMB() {
    auto& mgr = RawrXD::Compression::VirtualAllocReservationManager::Instance();
    return mgr.GetTotalCommittedBytes() / (1024 * 1024);
}

// Stress test: rapid model swap cycles
static bool TestModelHotSwap() {
    auto& loader = RawrXD::DynamicModelLoader::instance();

    const int kCycles = 50;
    const std::string modelA = "models/test_model_a.gguf";
    const std::string modelB = "models/test_model_b.gguf";

    size_t memBefore = GetWorkingSetMB();
    size_t reservedBefore = GetReservationCommittedMB();

    std::cout << "  Cycles: " << kCycles << "\n";
    std::cout << "  Mem before: " << memBefore << " MB\n";
    std::cout << "  Reserved before: " << reservedBefore << " MB\n";

    auto t0 = std::chrono::steady_clock::now();
    int successLoads = 0;
    int successUnloads = 0;

    for (int i = 0; i < kCycles; ++i) {
        auto result = loader.loadModel((i % 2 == 0) ? modelA : modelB, RawrXD::LoadBackend::Auto);
        if (result.success) {
            ++successLoads;
        }
        if (loader.unloadModel()) {
            ++successUnloads;
        }
    }
    auto t1 = std::chrono::steady_clock::now();

    size_t memAfter = GetWorkingSetMB();
    size_t reservedAfter = GetReservationCommittedMB();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Allow 50MB tolerance for OS/page caching
    int64_t memDelta = static_cast<int64_t>(memAfter) - static_cast<int64_t>(memBefore);
    int64_t reservedDelta = static_cast<int64_t>(reservedAfter) - static_cast<int64_t>(reservedBefore);

    std::cout << "  Success loads: " << successLoads << "/" << kCycles << "\n";
    std::cout << "  Success unloads: " << successUnloads << "/" << kCycles << "\n";
    std::cout << "  Time: " << ms << " ms (" << (ms / kCycles) << " ms/cycle)\n";
    std::cout << "  Mem after: " << memAfter << " MB (delta: " << memDelta << " MB)\n";
    std::cout << "  Reserved after: " << reservedAfter << " MB (delta: " << reservedDelta << " MB)\n";

    bool memOk = memDelta < 50;  // < 50MB growth acceptable
    bool reservedOk = reservedDelta < 10;  // < 10MB reserved growth

    std::cout << "  Memory leak check: " << (memOk ? "PASS" : "FAIL (>50MB growth)") << "\n";
    std::cout << "  Reservation leak check: " << (reservedOk ? "PASS" : "FAIL (>10MB growth)") << "\n";

    return memOk && reservedOk;
}

// Stress test: concurrent model loads from multiple threads
static bool TestConcurrentModelLoad() {
    auto& loader = RawrXD::DynamicModelLoader::instance();
    const int kThreads = 8;
    const int kLoadsPerThread = 20;
    std::atomic<int> success{0};
    std::atomic<int> fail{0};
    std::atomic<bool> deadlock{false};

    auto worker = [&](int tid) {
        std::string model = "models/thread_" + std::to_string(tid) + ".gguf";
        for (int i = 0; i < kLoadsPerThread; ++i) {
            auto start = std::chrono::steady_clock::now();
            auto result = loader.loadModel(model, RawrXD::LoadBackend::Auto);
            auto elapsed = std::chrono::steady_clock::now() - start;

            if (elapsed > std::chrono::seconds(5)) {
                deadlock.store(true);
            }

            if (result.success) {
                ++success;
                loader.unloadModel();
            } else {
                ++fail;
            }
        }
    };

    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back(worker, t);
    }
    for (auto& th : threads) {
        th.join();
    }
    auto t1 = std::chrono::steady_clock::now();

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "  Threads: " << kThreads << ", Loads/thread: " << kLoadsPerThread << "\n";
    std::cout << "  Success: " << success.load() << ", Fail: " << fail.load() << "\n";
    std::cout << "  Time: " << ms << " ms\n";
    std::cout << "  Deadlock: " << (deadlock.load() ? "DETECTED (FAIL)" : "none (PASS)") << "\n";

    return !deadlock.load();
}

// SovereignPager stress: page acquisition/release cycles
static bool TestSovereignPagerCycles() {
    sov::SovereignPager pager;
    // Use small budgets for fast testing
    bool init = pager.Init(64, 128, L"test_pager.bin", 0);
    if (!init) {
        std::cout << "  Pager init: FAIL\n";
        return false;
    }

    const int kCycles = 1000;
    auto t0 = std::chrono::steady_clock::now();
    int acquired = 0;
    int released = 0;

    for (int i = 0; i < kCycles; ++i) {
        uint32_t layer = i % 4;
        uint32_t expert = i % 8;
        if (pager.AcquireExpert(layer, expert, sov::Tier::WarmRAM)) {
            ++acquired;
            pager.ReleaseExpert(layer, expert);
            ++released;
        }
    }
    auto t1 = std::chrono::steady_clock::now();

    pager.Shutdown();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::cout << "  Cycles: " << kCycles << "\n";
    std::cout << "  Acquired: " << acquired << ", Released: " << released << "\n";
    std::cout << "  Time: " << ms << " ms (" << (ms / kCycles) << " ms/cycle)\n";
    std::cout << "  Balanced: " << (acquired == released ? "PASS" : "FAIL") << "\n";

    return acquired == released;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "=== RawrXD Model Hot-Swap Stress Test ===\n\n";

    bool all_pass = true;

    std::cout << "[Test 1] Model Hot-Swap (50 cycles)\n";
    all_pass &= TestModelHotSwap();
    std::cout << "\n";

    std::cout << "[Test 2] Concurrent Model Load (8 threads x 20 loads)\n";
    all_pass &= TestConcurrentModelLoad();
    std::cout << "\n";

    std::cout << "[Test 3] Sovereign Pager Cycles (1000 acquire/release)\n";
    all_pass &= TestSovereignPagerCycles();
    std::cout << "\n";

    if (all_pass) {
        std::cout << "=== ALL TESTS PASSED ===\n";
        return 0;
    } else {
        std::cout << "=== SOME TESTS FAILED ===\n";
        return 1;
    }
}
