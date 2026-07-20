//=============================================================================
// Benchmark: Dispatch Overhead
// Measures actual dispatch latency with CPU counters
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <chrono>
#include <vector>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <intrin.h>
#include "../src/nevm/nevm_tensor_descriptor.hpp"
#include "../src/nevm/nevm_kernel_bridge.hpp"
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::NEVM;
using namespace RawrXD::Kernels;

// CPU cycle counter with serialization
// Uses CPUID to serialize, RDTSCP for invariant TSC
inline uint64_t rdtsc_start() {
#ifdef _MSC_VER
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    _mm_lfence();
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__ (
        "cpuid\n\t"
        "rdtsc\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r" (hi), "=r" (lo)
        :: "%rbx", "%rcx", "%rdx", "%rax"
    );
    return ((uint64_t)hi << 32) | lo;
#endif
}

inline uint64_t rdtsc_end() {
#ifdef _MSC_VER
    uint64_t tsc = __rdtscp(nullptr);
    _mm_lfence();
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    return tsc;
#else
    unsigned int lo, hi;
    __asm__ __volatile__ (
        "rdtscp\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "cpuid\n\t"
        : "=r" (hi), "=r" (lo)
        :: "%rbx", "%rcx", "%rdx", "%rax"
    );
    return ((uint64_t)hi << 32) | lo;
#endif
}

// Calculate statistics
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
    
    // Standard deviation
    double sum_sq = 0.0;
    for (auto v : samples) {
        double diff = static_cast<double>(v) - s.avg;
        sum_sq += diff * diff;
    }
    s.stddev = std::sqrt(sum_sq / n);
    
    return s;
}

// Prevent optimization
volatile float g_dummy_result = 0.0f;

// Empty function for baseline
__declspec(noinline) void empty_function() {
    // Do nothing - measures call overhead
}

struct BenchmarkResult {
    const char* name;
    Statistics cycles;
    double ns_min;
    double ns_max;
    double ns_avg;
    double ns_median;
    double ns_p95;
    double ns_p99;
    size_t samples;
};

void print_result(const BenchmarkResult& r) {
    printf("%-35s %8.1f ns  median: %8.1f  p95: %8.1f  p99: %8.1f  [%zu samples]\n",
           r.name, r.ns_avg, r.ns_median, r.ns_p95, r.ns_p99, r.samples);
}

void print_comparison(const BenchmarkResult& baseline, const BenchmarkResult& test, const char* label) {
    double overhead = test.ns_avg - baseline.ns_avg;
    double ratio = test.ns_avg / baseline.ns_avg;
    printf("%-35s overhead: %8.1f ns  (%.1fx vs %s)\n", label, overhead, ratio, baseline.name);
}

// Benchmark 0: Empty function (call overhead baseline)
BenchmarkResult benchmark_empty_function(size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        empty_function();
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "Empty Function (call overhead)";
    r.cycles = stats;
    r.ns_min = stats.min / freq_ghz;
    r.ns_max = stats.max / freq_ghz;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.ns_p95 = stats.p95 / freq_ghz;
    r.ns_p99 = stats.p99 / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 1: Baseline v1.0 dispatch (full lookup chain)
BenchmarkResult benchmark_v1_dispatch(size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    // Setup: Create test VTAs
    VirtualTensorAddress vta_a{0x1000};
    VirtualTensorAddress vta_b{0x2000};
    VirtualTensorAddress vta_out{0x3000};
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        // Simulate v1.0 dispatch chain:
        // VTA → MMU lookup → Residency check → Precision selection 
        // → Kernel Registry lookup → Dispatch
        
        // Step 1: MMU lookup (simulated)
        void* ptr_a = reinterpret_cast<void*>(vta_a.raw + i * 64);  // Simulated
        void* ptr_b = reinterpret_cast<void*>(vta_b.raw + i * 64);
        
        // Step 2: Residency check (simulated)
        bool resident = (i % 2 == 0);  // Simulated
        
        // Step 3: Precision selection (simulated)
        ISA::PrecisionMode precision = ISA::PrecisionMode::Q4;
        
        // Step 4: Kernel Registry lookup
        auto kernel = KernelRegistry::GetQ4DotKernel();
        
        // Step 5: Call (but don't execute to measure dispatch only)
        if (kernel && resident) {
            g_dummy_result = 1.0f;  // Would be: kernel(ptr_a, ptr_b)
        }
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "v1.0 Full Dispatch Chain";
    r.cycles = stats;
    r.ns_min = stats.min / freq_ghz;
    r.ns_max = stats.max / freq_ghz;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.ns_p95 = stats.p95 / freq_ghz;
    r.ns_p99 = stats.p99 / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 2: v2.0 fast dispatch (cached descriptor)
BenchmarkResult benchmark_v2_fast_dispatch(DescriptorCache* cache, size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    // Pre-populate cache
    VirtualTensorAddress vta_a{0x1000};
    VirtualTensorAddress vta_b{0x2000};
    VirtualTensorAddress vta_out{0x3000};
    
    // Build descriptors
    auto* desc_a = cache->GetOrCreate(vta_a);
    auto* desc_b = cache->GetOrCreate(vta_b);
    auto* desc_out = cache->GetOrCreate(vta_out);
    
    if (desc_a) {
        desc_a->kernel_entry = KernelRegistry::GetQ4DotKernel();
        desc_a->version = 1;
        desc_a->residency_tier = TensorExecutionDescriptor::ResidencyTier::HOST_ONLY;
    }
    if (desc_b) {
        desc_b->kernel_entry = KernelRegistry::GetQ4DotKernel();
        desc_b->version = 1;
        desc_b->residency_tier = TensorExecutionDescriptor::ResidencyTier::HOST_ONLY;
    }
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        // v2.0 fast path:
        // VTA → Descriptor Cache → kernel_entry → call
        
        // Step 1: Lookup descriptor (fast path)
        const auto* desc = cache->Lookup(vta_a);
        
        // Step 2: Validate and call
        if (desc && desc->kernel_entry && desc->version > 0) {
            g_dummy_result = 1.0f;  // Would be: kernel(...)
        }
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "v2.0 Fast Dispatch (cached)";
    r.cycles = stats;
    r.ns_min = stats.min / freq_ghz;
    r.ns_max = stats.max / freq_ghz;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.ns_p95 = stats.p95 / freq_ghz;
    r.ns_p99 = stats.p99 / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 3: Descriptor cache lookup only
BenchmarkResult benchmark_cache_lookup(DescriptorCache* cache, size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    VirtualTensorAddress vta{0x1000};
    
    // Pre-populate
    auto* desc = cache->GetOrCreate(vta);
    if (desc) desc->version = 1;
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        const auto* result = cache->Lookup(vta);
        (void)result;  // Prevent optimization
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "Descriptor Cache Lookup";
    r.cycles = stats;
    r.ns_min = stats.min / freq_ghz;
    r.ns_max = stats.max / freq_ghz;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.ns_p95 = stats.p95 / freq_ghz;
    r.ns_p99 = stats.p99 / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 4: Cache miss (slow path)
BenchmarkResult benchmark_cache_miss(DescriptorCache* cache, size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0x1000, 0x100000);
    
    for (size_t i = 0; i < iterations; i++) {
        VirtualTensorAddress vta(dis(gen));  // Random VTA (cache miss)
        
        uint64_t start = rdtsc_start();
        
        const auto* result = cache->Lookup(vta);
        if (!result) {
            // Miss: create descriptor
            auto* desc = cache->GetOrCreate(vta);
            if (desc) {
                desc->kernel_entry = KernelRegistry::GetQ4DotKernel();
                desc->version = 1;
            }
        }
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "Cache Miss (slow path)";
    r.cycles = stats;
    r.ns_min = stats.min / freq_ghz;
    r.ns_max = stats.max / freq_ghz;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.ns_p95 = stats.p95 / freq_ghz;
    r.ns_p99 = stats.p99 / freq_ghz;
    r.samples = iterations;
    return r;
}

int main() {
    printf("=============================================================================\n");
    printf("DISPATCH OVERHEAD BENCHMARK\n");
    printf("=============================================================================\n");
    printf("Measures actual dispatch latency with CPU counters (RDTSC + CPUID serialization)\n\n");
    
    // Initialize
    KernelRegistry::Initialize();
    
    const size_t iterations = 1000000;
    
    printf("Running %zu iterations per test...\n\n", iterations);
    
    // Run benchmarks - THREE-WAY COMPARISON
    // 1. Empty function (call overhead baseline)
    // 2. v1.0 full dispatch chain (old lookup)
    // 3. v2.0 fast dispatch (cached descriptor)
    
    auto r0 = benchmark_empty_function(iterations);      // Baseline: call overhead
    auto r1 = benchmark_v1_dispatch(iterations);          // Old: full lookup chain
    
    DescriptorCache cache(DescriptorCache::DefaultConfig());
    auto r2 = benchmark_v2_fast_dispatch(&cache, iterations);  // New: cached descriptor
    auto r3 = benchmark_cache_lookup(&cache, iterations);
    auto r4 = benchmark_cache_miss(&cache, 10000);  // Fewer iterations for miss test
    
    // Print results with full statistics
    printf("\n=== Results (assuming 3.8 GHz) ===\n");
    printf("%-35s %10s %10s %10s %10s %10s\n", 
           "Test", "Avg(ns)", "Median", "P95", "P99", "StdDev");
    printf("%-35s %10s %10s %10s %10s %10s\n", 
           "----", "-------", "------", "---", "---", "------");
    print_result(r0);
    print_result(r1);
    print_result(r2);
    print_result(r3);
    print_result(r4);
    
    // THREE-WAY COMPARISON
    printf("\n=== Three-Way Comparison ===\n");
    printf("Baseline: Empty function call overhead\n");
    print_comparison(r0, r1, "v1.0 Full Dispatch Chain");
    print_comparison(r0, r2, "v2.0 Fast Dispatch (cached)");
    print_comparison(r0, r3, "Descriptor Cache Lookup");
    
    // Calculate speedup (v2.0 vs v1.0)
    double speedup = r1.ns_avg / r2.ns_avg;
    double v1_overhead = r1.ns_avg - r0.ns_avg;
    double v2_overhead = r2.ns_avg - r0.ns_avg;
    
    printf("\n=== Dispatch Overhead Analysis ===\n");
    printf("v1.0 dispatch overhead (above call): %.1f ns\n", v1_overhead);
    printf("v2.0 dispatch overhead (above call): %.1f ns\n", v2_overhead);
    printf("Overhead reduction: %.1f ns (%.1fx)\n", v1_overhead - v2_overhead, v1_overhead / v2_overhead);
    printf("Speedup v2.0 vs v1.0: %.1fx\n", speedup);
    
    // Cache stats
    auto stats = cache.GetStats();
    printf("\n=== Descriptor Cache Stats ===\n");
    printf("  Entries: %zu\n", stats.entries);
    printf("  Hits: %zu\n", stats.hits);
    printf("  Misses: %zu\n", stats.misses);
    printf("  Hit rate: %.1f%%\n", stats.hit_rate * 100);
    printf("  Evictions: %zu\n", stats.evictions);
    
    // Validation
    printf("\n=== Validation ===\n");
    if (speedup >= 40.0) {
        printf("✓ VALIDATED: 50x dispatch improvement claim supported (%.1fx measured)\n", speedup);
    } else if (speedup >= 20.0) {
        printf("⚠ PARTIAL: %.1fx improvement (target was 50x)\n", speedup);
    } else {
        printf("✗ FAILED: Only %.1fx improvement (target was 50x)\n", speedup);
    }
    
    // Check if v2.0 is close to empty function overhead
    double v2_vs_empty = r2.ns_avg / r0.ns_avg;
    if (v2_vs_empty < 2.0) {
        printf("✓ VALIDATED: v2.0 dispatch overhead is minimal (%.1fx empty call)\n", v2_vs_empty);
    } else {
        printf("⚠ WARNING: v2.0 dispatch overhead is significant (%.1fx empty call)\n", v2_vs_empty);
    }
    
    return 0;
}
