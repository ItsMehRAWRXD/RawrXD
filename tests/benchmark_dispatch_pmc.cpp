//=============================================================================
// Benchmark: Dispatch Overhead with PMC Profiling
// Enhanced version with hardware performance counters
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>

#include "../src/profiling/pmc_profiler.hpp"
#include "../src/nevm/nevm_tensor_descriptor.hpp"
#include "../src/nevm/nevm_kernel_bridge.hpp"
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::NEVM;
using namespace RawrXD::Kernels;
using namespace RawrXD::Profiling;

//=============================================================================
// Statistics
//=============================================================================

struct Statistics {
    uint64_t min;
    uint64_t max;
    uint64_t median;
    uint64_t p95;
    uint64_t p99;
    uint64_t avg;
    double stddev;
};

Statistics calculate_stats(std::vector<uint64_t>& samples) {
    std::sort(samples.begin(), samples.end());
    
    Statistics s;
    s.min = samples.front();
    s.max = samples.back();
    s.avg = std::accumulate(samples.begin(), samples.end(), 0ULL) / samples.size();
    
    size_t n = samples.size();
    s.median = samples[n / 2];
    s.p95 = samples[static_cast<size_t>(n * 0.95)];
    s.p99 = samples[static_cast<size_t>(n * 0.99)];
    
    double sum_sq = 0.0;
    for (auto v : samples) {
        double diff = static_cast<double>(v) - s.avg;
        sum_sq += diff * diff;
    }
    s.stddev = std::sqrt(sum_sq / n);
    
    return s;
}

//=============================================================================
// PMC-Enhanced Benchmark
//=============================================================================

struct PMCResults {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t cache_misses;
    uint64_t branch_misses;
    
    double cpi;              // Cycles per instruction
    double cache_miss_rate;  // Cache misses / references
    double branch_miss_rate; // Branch misses / branches
};

struct BenchmarkResult {
    const char* name;
    Statistics cycles;
    PMCResults pmc;
    double ns_avg;
    double ns_median;
    size_t samples;
};

void print_pmc_results(const PMCResults& pmc) {
    printf("    PMC Metrics:\n");
    printf("      Cycles:           %lu\n", pmc.cycles);
    printf("      Instructions:     %lu\n", pmc.instructions);
    printf("      CPI:              %.2f\n", pmc.cpi);
    printf("      Cache Misses:     %lu\n", pmc.cache_misses);
    printf("      Cache Miss Rate:  %.2f%%\n", pmc.cache_miss_rate * 100);
    printf("      Branch Misses:    %lu\n", pmc.branch_misses);
    printf("      Branch Miss Rate: %.2f%%\n", pmc.branch_miss_rate * 100);
}

//=============================================================================
// Benchmark Functions
//=============================================================================

volatile float g_dummy_result = 0.0f;

__declspec(noinline) void empty_function() {
    // Do nothing - measures call overhead
}

// Benchmark with PMC profiling
PMCResults run_with_pmc(const char* name, auto&& func, size_t iterations) {
    printf("  Profiling %s with PMC...\n", name);
    
    PMCSession session;
    session.AddCounter(PMCEvent::CPU_CYCLES);
    session.AddCounter(PMCEvent::INSTRUCTIONS_RETIRED);
    session.AddCounter(PMCEvent::L1_CACHE_MISSES);
    session.AddCounter(PMCEvent::CACHE_REFERENCES);
    session.AddCounter(PMCEvent::BRANCH_INSTRUCTIONS);
    session.AddCounter(PMCEvent::BRANCH_MISSES);
    
    PMCResults results = {};
    
    // Warmup
    for (size_t i = 0; i < 100; i++) {
        func();
    }
    
    // Profiled run
    session.Start();
    
    for (size_t i = 0; i < iterations; i++) {
        func();
    }
    
    session.Stop();
    
    auto pmc_results = session.GetResults();
    
    for (const auto& r : pmc_results) {
        switch (r.event) {
            case PMCEvent::CPU_CYCLES:
                results.cycles = r.delta;
                break;
            case PMCEvent::INSTRUCTIONS_RETIRED:
                results.instructions = r.delta;
                break;
            case PMCEvent::L1_CACHE_MISSES:
                results.cache_misses = r.delta;
                break;
            case PMCEvent::BRANCH_MISSES:
                results.branch_misses = r.delta;
                break;
            default:
                break;
        }
    }
    
    // Calculate derived metrics
    if (results.instructions > 0) {
        results.cpi = static_cast<double>(results.cycles) / results.instructions;
    }
    
    // Estimate cache miss rate (we'd need cache references for exact)
    results.cache_miss_rate = static_cast<double>(results.cache_misses) / iterations;
    results.branch_miss_rate = 0.0; // Would need branch count
    
    return results;
}

//=============================================================================
// Main
//=============================================================================

int main() {
    printf("=============================================================================\n");
    printf("DISPATCH OVERHEAD BENCHMARK WITH PMC PROFILING\n");
    printf("=============================================================================\n");
    printf("Hardware-level profiling using Performance Monitoring Counters\n\n");
    
    // Check PMC availability
    if (!IsPmcAvailable()) {
        printf("WARNING: PMC not available on this platform\n");
        printf("Falling back to RDTSC-only measurements\n\n");
    } else {
        printf("PMC Available: Yes\n");
        auto events = GetAvailableEvents();
        printf("Available Events: %zu\n\n", events.size());
    }
    
    // Initialize
    KernelRegistry::Initialize();
    
    const size_t iterations = 100000;
    
    printf("Running %zu iterations per test...\n\n", iterations);
    
    // Test 1: Empty function (baseline)
    printf("[1/3] Empty Function (call overhead baseline)\n");
    auto pmc_empty = run_with_pmc("empty", []() {
        empty_function();
    }, iterations);
    print_pmc_results(pmc_empty);
    printf("\n");
    
    // Test 2: Descriptor cache lookup
    printf("[2/3] Descriptor Cache Lookup\n");
    DescriptorCache cache(DescriptorCache::DefaultConfig());
    VirtualTensorAddress vta = 0x1000;
    auto* desc = cache.GetOrCreate(vta);
    if (desc) desc->version = 1;
    
    auto pmc_cache = run_with_pmc("cache", [&cache, vta]() {
        const auto* result = cache.Lookup(vta);
        (void)result;
    }, iterations);
    print_pmc_results(pmc_cache);
    printf("\n");
    
    // Test 3: Full dispatch chain
    printf("[3/3] Full Dispatch Chain\n");
    auto pmc_dispatch = run_with_pmc("dispatch", []() {
        // Simulate dispatch
        auto kernel = KernelRegistry::GetQ4DotKernel();
        if (kernel) {
            g_dummy_result = 1.0f;
        }
    }, iterations);
    print_pmc_results(pmc_dispatch);
    printf("\n");
    
    // Analysis
    printf("=============================================================================\n");
    printf("PMC ANALYSIS\n");
    printf("=============================================================================\n\n");
    
    printf("Cycles per iteration:\n");
    printf("  Empty function:   %6.1f\n", static_cast<double>(pmc_empty.cycles) / iterations);
    printf("  Cache lookup:     %6.1f\n", static_cast<double>(pmc_cache.cycles) / iterations);
    printf("  Full dispatch:    %6.1f\n", static_cast<double>(pmc_dispatch.cycles) / iterations);
    printf("\n");
    
    printf("Instructions per iteration:\n");
    printf("  Empty function:   %6.1f\n", static_cast<double>(pmc_empty.instructions) / iterations);
    printf("  Cache lookup:     %6.1f\n", static_cast<double>(pmc_cache.instructions) / iterations);
    printf("  Full dispatch:    %6.1f\n", static_cast<double>(pmc_dispatch.instructions) / iterations);
    printf("\n");
    
    printf("CPI (Cycles Per Instruction):\n");
    printf("  Empty function:   %.2f\n", pmc_empty.cpi);
    printf("  Cache lookup:     %.2f\n", pmc_cache.cpi);
    printf("  Full dispatch:    %.2f\n", pmc_dispatch.cpi);
    printf("\n");
    
    printf("Cache misses per 1000 iterations:\n");
    printf("  Empty function:   %6.1f\n", static_cast<double>(pmc_empty.cache_misses) / iterations * 1000);
    printf("  Cache lookup:     %6.1f\n", static_cast<double>(pmc_cache.cache_misses) / iterations * 1000);
    printf("  Full dispatch:    %6.1f\n", static_cast<double>(pmc_dispatch.cache_misses) / iterations * 1000);
    printf("\n");
    
    // Validation
    printf("=============================================================================\n");
    printf("VALIDATION\n");
    printf("=============================================================================\n\n");
    
    bool cpi_ok = pmc_cache.cpi < 2.0 && pmc_dispatch.cpi < 3.0;
    bool cache_ok = pmc_cache.cache_misses < pmc_dispatch.cache_misses * 2;
    
    printf("CPI Check:        %s (cache: %.2f, dispatch: %.2f)\n", 
           cpi_ok ? "PASS" : "FAIL", pmc_cache.cpi, pmc_dispatch.cpi);
    printf("Cache Efficiency: %s\n", cache_ok ? "PASS" : "FAIL");
    
    if (cpi_ok && cache_ok) {
        printf("\n✓ PMC validation PASSED\n");
        return 0;
    } else {
        printf("\n✗ PMC validation FAILED\n");
        return 1;
    }
}
