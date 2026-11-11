//=============================================================================
// Benchmark: Dispatch Overhead (Simplified)
// Measures actual dispatch latency with CPU counters
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <intrin.h>

// CPU cycle counter with serialization
inline uint64_t rdtsc_start() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    _mm_lfence();
    return __rdtsc();
}

inline uint64_t rdtsc_end() {
    uint64_t tsc = __rdtscp(nullptr);
    _mm_lfence();
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    return tsc;
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

// Simulated kernel lookup
__declspec(noinline) void* GetKernel() {
    return (void*)0x12345678;  // Simulated kernel pointer
}

// Simulated cache lookup
struct CacheEntry {
    void* kernel;
    int version;
};

CacheEntry g_cache[1024];

__declspec(noinline) CacheEntry* LookupCache(int key) {
    return &g_cache[key % 1024];
}

struct BenchmarkResult {
    const char* name;
    Statistics cycles;
    double ns_avg;
    double ns_median;
    size_t samples;
};

void print_result(const BenchmarkResult& r) {
    printf("%-35s %8.1f ns  median: %8.1f  p95: %8.1f  [%zu samples]\n",
           r.name, r.ns_avg, r.ns_median, r.ns_p95, r.samples);
}

// Benchmark 0: Empty function
BenchmarkResult benchmark_empty(size_t iterations) {
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
    r.name = "Empty Function";
    r.cycles = stats;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 1: Full dispatch chain
BenchmarkResult benchmark_full_dispatch(size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        // Simulate full dispatch
        void* kernel = GetKernel();
        if (kernel) {
            g_dummy_result = 1.0f;
        }
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "Full Dispatch Chain";
    r.cycles = stats;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.samples = iterations;
    return r;
}

// Benchmark 2: Cached dispatch
BenchmarkResult benchmark_cached_dispatch(size_t iterations) {
    std::vector<uint64_t> cycles;
    cycles.reserve(iterations);
    
    // Pre-populate cache
    g_cache[0].kernel = (void*)0x12345678;
    g_cache[0].version = 1;
    
    for (size_t i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        
        // Fast cache lookup
        CacheEntry* entry = LookupCache(0);
        if (entry && entry->kernel && entry->version > 0) {
            g_dummy_result = 1.0f;
        }
        
        uint64_t end = rdtsc_end();
        cycles.push_back(end - start);
    }
    
    Statistics stats = calculate_stats(cycles);
    double freq_ghz = 3.8;
    
    BenchmarkResult r;
    r.name = "Cached Dispatch";
    r.cycles = stats;
    r.ns_avg = stats.avg / freq_ghz;
    r.ns_median = stats.median / freq_ghz;
    r.samples = iterations;
    return r;
}

int main() {
    printf("=============================================================================\n");
    printf("DISPATCH OVERHEAD BENCHMARK\n");
    printf("=============================================================================\n\n");
    
    const size_t iterations = 1000000;
    printf("Running %zu iterations per test...\n\n", iterations);
    
    // Run benchmarks
    auto r0 = benchmark_empty(iterations);
    auto r1 = benchmark_full_dispatch(iterations);
    auto r2 = benchmark_cached_dispatch(iterations);
    
    // Print results
    printf("=== Results (assuming 3.8 GHz) ===\n");
    printf("%-35s %10s %10s %10s\n", "Test", "Avg(ns)", "Median", "P95");
    printf("%-35s %10s %10s %10s\n", "----", "-------", "------", "---");
    print_result(r0);
    print_result(r1);
    print_result(r2);
    
    // Calculate speedup
    printf("\n=== Analysis ===\n");
    double speedup = r1.ns_avg / r2.ns_avg;
    double overhead_saved = r1.ns_avg - r2.ns_avg;
    
    printf("Speedup (cached vs full): %.1fx\n", speedup);
    printf("Overhead saved: %.1f ns\n", overhead_saved);
    printf("Call overhead: %.1f ns\n", r0.ns_avg);
    
    // Validation
    printf("\n=== Validation ===\n");
    if (speedup >= 2.0) {
        printf("PASS: Dispatch optimization shows measurable improvement\n");
        return 0;
    } else {
        printf("WARNING: Limited improvement detected\n");
        return 1;
    }
}
