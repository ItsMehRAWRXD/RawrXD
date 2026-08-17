// ============================================================================
// NegativeSpaceProfiler.cpp — C++ implementation (non-stub)
// Replaces MASM object dependency with equivalent C++ implementation.
// Uses __rdtsc() intrinsic, std::atomic counters, and printf for reporting.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <atomic>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace rawrxd {

extern "C" {

static std::atomic<unsigned long long> g_batch_size{1};
static std::atomic<unsigned long long> g_call_count{0};
static std::atomic<unsigned long long> g_total_cycles{0};
static std::atomic<int> g_initialized{0};

void Profiler_Initialize()
{
    g_batch_size.store(1, std::memory_order_relaxed);
    g_call_count.store(0, std::memory_order_relaxed);
    g_total_cycles.store(0, std::memory_order_relaxed);
    g_initialized.store(1, std::memory_order_relaxed);
}

void Profiler_SetBatchContext(unsigned long long batchSize)
{
    g_batch_size.store(batchSize, std::memory_order_relaxed);
    g_call_count.store(0, std::memory_order_relaxed);
    g_total_cycles.store(0, std::memory_order_relaxed);
}

unsigned long long Profiler_GetBatchContext()
{
    return g_batch_size.load(std::memory_order_relaxed);
}

unsigned long long Profiler_ReadTsc()
{
#if defined(_MSC_VER)
    return __rdtsc();
#else
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<unsigned long long>(hi) << 32) | lo;
#endif
}

void Profiler_TrackCall(unsigned long long startCycles)
{
    unsigned long long end = Profiler_ReadTsc();
    unsigned long long delta = end - startCycles;
    g_call_count.fetch_add(1, std::memory_order_relaxed);
    g_total_cycles.fetch_add(delta, std::memory_order_relaxed);
}

void Profiler_AnalyzeBottlenecks()
{
    unsigned long long calls = g_call_count.load(std::memory_order_relaxed);
    unsigned long long total = g_total_cycles.load(std::memory_order_relaxed);
    unsigned long long batch = g_batch_size.load(std::memory_order_relaxed);

    (void)total;  // available for future cycle-per-call metrics

    printf("\r\n"
           "==================================================\r\n"
           "  x64 HARDWARE BOTTLENECK & BATCHING ANALYSIS\r\n"
           "==================================================\r\n");

    if (calls >= batch && batch > 1)
    {
        printf("    [!] RED FLAG: call_count >= batch_size (T > 1)\r\n"
               "        Diagnosis: SUPERFICIAL BATCHING detected.\r\n"
               "        The loop is OUTSIDE the kernel.\r\n");
    }
    else
    {
        printf("\r\n"
               "[+] No superficial batching detected.\r\n"
               "    Kernel appears to be truly batched.\r\n");
    }

    printf("\r\nAnalysis complete.\r\n");
    fflush(stdout);
}

} // extern "C"

} // namespace rawrxd
