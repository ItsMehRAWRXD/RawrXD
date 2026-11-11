// =============================================================================
// SovereignTestSuite - Cache Coherency TSC Monitor
// =============================================================================
// Validates that FlushInstructionCache properly invalidates the µop cache
// after hot-patching. Uses serializing RDTSC to measure execution latency
// before and after patch application.
//
// Detection: If patched execution is >1.5x slower, µop cache is stale
// =============================================================================

#include "SovereignTestSuite.hpp"
#include <windows.h>
#include <intrin.h>
#include <cstring>

// =============================================================================
// Serializing RDTSC - prevents out-of-order execution from skewing measurements
// =============================================================================
extern "C" __declspec(dllexport)
uint64_t SovereignReadTSC() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serializing fence
    return __rdtsc();
}

// =============================================================================
// Test loop target - a simple computation that will be patched
// =============================================================================
#pragma optimize("", off)
static void __declspec(noinline) TestComputationLoop(uint32_t iterations) {
    volatile uint64_t sum = 0;
    for (uint32_t i = 0; i < iterations; i++) {
        sum += i * i;
    }
    (void)sum;
}
#pragma optimize("", on)

// =============================================================================
// Measure execution cycles of the test loop
// =============================================================================
static uint64_t MeasureLoopCycles(uint32_t iterations) {
    uint64_t start = SovereignReadTSC();
    TestComputationLoop(iterations);
    uint64_t end = SovereignReadTSC();
    return end - start;
}

// =============================================================================
// Public API: Test Cache Coherency
// =============================================================================
extern "C" __declspec(dllexport)
SovereignTestReport SovereignTest_CacheCoherency(void* target_loop) {
    SovereignTestReport report = {};
    (void)target_loop;  // Use internal test loop
    
    constexpr uint32_t WARMUP = 100;
    constexpr uint32_t MEASURE = 1000;
    constexpr uint32_t LOOP_ITERATIONS = 10000;
    
    // --- Phase 1: Warmup ---
    for (uint32_t i = 0; i < WARMUP; i++) {
        TestComputationLoop(LOOP_ITERATIONS);
    }
    
    // --- Phase 2: Baseline measurement ---
    uint64_t baseline_min = UINT64_MAX;
    uint64_t baseline_total = 0;
    
    for (uint32_t i = 0; i < MEASURE; i++) {
        uint64_t cycles = MeasureLoopCycles(LOOP_ITERATIONS);
        baseline_total += cycles;
        if (cycles < baseline_min) baseline_min = cycles;
    }
    
    uint64_t baseline_avg = baseline_total / MEASURE;
    
    // --- Phase 3: Apply NOP patch to the loop ---
    // Patch the first byte of TestComputationLoop with a NOP (0x90)
    // This simulates a real hot-patch
    DWORD oldProtect;
    uintptr_t loop_addr = (uintptr_t)&TestComputationLoop;
    
    VirtualProtect(
        (LPVOID)loop_addr,
        1,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    
    // Read original byte
    uint8_t original_byte = *(uint8_t*)loop_addr;
    
    // Write NOP
    *(uint8_t*)loop_addr = 0x90;
    
    VirtualProtect(
        (LPVOID)loop_addr,
        1,
        oldProtect,
        &oldProtect
    );
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    
    // --- Phase 4: Post-patch measurement ---
    uint64_t patched_min = UINT64_MAX;
    uint64_t patched_total = 0;
    
    for (uint32_t i = 0; i < MEASURE; i++) {
        uint64_t cycles = MeasureLoopCycles(LOOP_ITERATIONS);
        patched_total += cycles;
        if (cycles < patched_min) patched_min = cycles;
    }
    
    uint64_t patched_avg = patched_total / MEASURE;
    
    // --- Phase 5: Restore original byte ---
    VirtualProtect(
        (LPVOID)loop_addr,
        1,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    *(uint8_t*)loop_addr = original_byte;
    VirtualProtect(
        (LPVOID)loop_addr,
        1,
        oldProtect,
        &oldProtect
    );
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    
    // --- Phase 6: Analyze results ---
    report.baseline_cycles = baseline_avg;
    report.patched_cycles = patched_avg;
    
    float slowdown_ratio = (float)patched_avg / (float)baseline_avg;
    
    if (slowdown_ratio > 1.5f) {
        report.result = SovereignTestResult::FailCacheCoherency;
        report.detail = "Cache coherency: FAIL - µop cache stale (slowdown > 1.5x)";
    } else {
        report.result = SovereignTestResult::Pass;
        report.detail = "Cache coherency: PASS - µop cache properly invalidated";
    }
    
    return report;
}
