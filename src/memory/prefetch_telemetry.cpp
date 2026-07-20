//=============================================================================
// Prefetch Telemetry Implementation
// Reality check for IOCP performance
//=============================================================================

#include "prefetch_telemetry.hpp"
#include <algorithm>
#include <cstring>
#include <cstdio>

namespace RawrXD {
namespace Memory {

//=============================================================================
// PrefetchTelemetry Implementation
//=============================================================================

void PrefetchTelemetry::RecordRequest(size_t bytes) {
    requests.fetch_add(1, std::memory_order_relaxed);
    bytes_requested.fetch_add(bytes, std::memory_order_relaxed);
}

void PrefetchTelemetry::RecordSubmit(uint64_t submit_latency_us) {
    total_submit_us.fetch_add(submit_latency_us, std::memory_order_relaxed);
}

void PrefetchTelemetry::RecordCompletion(uint64_t completion_latency_us, size_t bytes) {
    completed.fetch_add(1, std::memory_order_relaxed);
    bytes_loaded.fetch_add(bytes, std::memory_order_relaxed);
    total_completion_us.fetch_add(completion_latency_us, std::memory_order_relaxed);
    
    // Calculate end-to-end and store sample
    uint64_t end_to_end = completion_latency_us; // Simplified - should include submit time
    total_end_to_end_us.fetch_add(end_to_end, std::memory_order_relaxed);
    
    size_t idx = sample_index.fetch_add(1, std::memory_order_relaxed) % kMaxSamples;
    end_to_end_samples[idx] = end_to_end;
}

void PrefetchTelemetry::RecordCacheHit() {
    cache_hits.fetch_add(1, std::memory_order_relaxed);
}

void PrefetchTelemetry::RecordCacheMiss() {
    cache_misses.fetch_add(1, std::memory_order_relaxed);
}

PrefetchTelemetry::Stats PrefetchTelemetry::CalculateStats() const {
    Stats stats = {};
    
    stats.requests = requests.load(std::memory_order_acquire);
    stats.completed = completed.load(std::memory_order_acquire);
    stats.cache_hits = cache_hits.load(std::memory_order_acquire);
    stats.cache_misses = cache_misses.load(std::memory_order_acquire);
    
    uint64_t total_cache = stats.cache_hits + stats.cache_misses;
    stats.hit_rate = total_cache > 0 ? 
        static_cast<double>(stats.cache_hits) / total_cache : 0.0;
    
    if (stats.completed > 0) {
        stats.avg_submit_us = 
            static_cast<double>(total_submit_us.load()) / stats.completed;
        stats.avg_completion_us = 
            static_cast<double>(total_completion_us.load()) / stats.completed;
        stats.avg_end_to_end_us = 
            static_cast<double>(total_end_to_end_us.load()) / stats.completed;
    }
    
    // Calculate percentiles from samples
    size_t num_samples = std::min(
        static_cast<size_t>(sample_index.load()), 
        kMaxSamples
    );
    
    if (num_samples > 0) {
        std::vector<uint64_t> samples(end_to_end_samples, 
                                       end_to_end_samples + num_samples);
        std::sort(samples.begin(), samples.end());
        
        stats.p50_end_to_end_us = samples[num_samples * 50 / 100];
        stats.p95_end_to_end_us = samples[num_samples * 95 / 100];
        stats.p99_end_to_end_us = samples[num_samples * 99 / 100];
    }
    
    stats.bytes_requested = bytes_requested.load();
    stats.bytes_loaded = bytes_loaded.load();
    
    double seconds = stats.avg_end_to_end_us / 1e6;
    if (seconds > 0) {
        stats.bandwidth_mbps = (stats.bytes_loaded / (1024.0 * 1024)) / seconds;
    }
    
    return stats;
}

void PrefetchTelemetry::Reset() {
    requests.store(0);
    completed.store(0);
    cache_hits.store(0);
    cache_misses.store(0);
    bytes_requested.store(0);
    bytes_loaded.store(0);
    total_submit_us.store(0);
    total_completion_us.store(0);
    total_end_to_end_us.store(0);
    sample_index.store(0);
    memset(end_to_end_samples, 0, sizeof(end_to_end_samples));
}

bool PrefetchTelemetry::MeetsLatencyTarget(double target_p95_us) const {
    Stats stats = CalculateStats();
    return stats.p95_end_to_end_us < target_p95_us;
}

//=============================================================================
// LayerSwapTelemetry Implementation
//=============================================================================

void LayerSwapTelemetry::RecordLayerSwap(uint64_t latency_us, bool stalled) {
    layer_swaps.fetch_add(1, std::memory_order_relaxed);
    total_swap_latency_us.fetch_add(latency_us, std::memory_order_relaxed);
    
    uint64_t current_max = max_swap_latency_us.load();
    while (latency_us > current_max && 
           !max_swap_latency_us.compare_exchange_weak(current_max, latency_us)) {
        // Retry
    }
    
    if (stalled) {
        swap_stalls.fetch_add(1, std::memory_order_relaxed);
    }
}

void LayerSwapTelemetry::RecordKernelStarvation(uint64_t duration_us) {
    kernel_starvation_events.fetch_add(1, std::memory_order_relaxed);
    total_starvation_us.fetch_add(duration_us, std::memory_order_relaxed);
}

LayerSwapTelemetry::Stats LayerSwapTelemetry::CalculateStats() const {
    Stats stats = {};
    
    stats.swaps = layer_swaps.load(std::memory_order_acquire);
    stats.stalls = swap_stalls.load(std::memory_order_acquire);
    stats.stall_rate = stats.swaps > 0 ? 
        static_cast<double>(stats.stalls) / stats.swaps : 0.0;
    
    if (stats.swaps > 0) {
        stats.avg_swap_latency_us = 
            static_cast<double>(total_swap_latency_us.load()) / stats.swaps;
    }
    stats.max_swap_latency_us = max_swap_latency_us.load();
    
    stats.starvation_events = kernel_starvation_events.load();
    if (stats.starvation_events > 0) {
        stats.avg_starvation_us = 
            static_cast<double>(total_starvation_us.load()) / stats.starvation_events;
    }
    stats.starvation_rate = stats.swaps > 0 ? 
        static_cast<double>(stats.starvation_events) / stats.swaps : 0.0;
    
    return stats;
}

//=============================================================================
// TelemetryCollector Implementation
//=============================================================================

TelemetryCollector& TelemetryCollector::Instance() {
    static TelemetryCollector instance;
    return instance;
}

void TelemetryCollector::PrintReport() const {
    auto prefetch_stats = prefetch_.CalculateStats();
    auto swap_stats = layer_swap_.CalculateStats();
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║  PREFETCH TELEMETRY REPORT                                        ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Prefetch Operations                                              ║\n");
    printf("║    Requests:     %10llu                                        ║\n", prefetch_stats.requests);
    printf("║    Completed:    %10llu                                        ║\n", prefetch_stats.completed);
    printf("║    Cache Hits:   %10llu (%.1f%%)                              ║\n", 
           prefetch_stats.cache_hits, prefetch_stats.hit_rate * 100);
    printf("║    Bandwidth:    %10.2f MB/s                                   ║\n", prefetch_stats.bandwidth_mbps);
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Latency (microseconds)                                           ║\n");
    printf("║    Submit:       %10.2f us (avg)                               ║\n", prefetch_stats.avg_submit_us);
    printf("║    Completion:    %10.2f us (avg)                               ║\n", prefetch_stats.avg_completion_us);
    printf("║    End-to-End:   %10.2f us (avg)                               ║\n", prefetch_stats.avg_end_to_end_us);
    printf("║    P50:          %10.2f us                                     ║\n", prefetch_stats.p50_end_to_end_us);
    printf("║    P95:          %10.2f us  (Target: <500)                    ║\n", prefetch_stats.p95_end_to_end_us);
    printf("║    P99:          %10.2f us                                     ║\n", prefetch_stats.p99_end_to_end_us);
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Layer Swap Performance                                           ║\n");
    printf("║    Swaps:        %10llu                                        ║\n", swap_stats.swaps);
    printf("║    Stalls:       %10llu (%.2f%%)                               ║\n", 
           swap_stats.stalls, swap_stats.stall_rate * 100);
    printf("║    Avg Latency:  %10.2f us                                     ║\n", swap_stats.avg_swap_latency_us);
    printf("║    Max Latency:  %10llu us                                     ║\n", swap_stats.max_swap_latency_us);
    printf("║    Starvation:   %10llu events (%.2f%%)                        ║\n", 
           swap_stats.starvation_events, swap_stats.starvation_rate * 100);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    // Validation
    auto validation = Validate();
    printf("\n");
    printf("VAL-026 Validation: %s\n", validation.overall_pass ? "PASS" : "FAIL");
    printf("  Prefetch P95:    %s\n", validation.prefetch_latency_ok ? "✅" : "❌");
    printf("  Layer Swap:      %s\n", validation.layer_swap_ok ? "✅" : "❌");
    printf("  Stall Rate:      %s\n", validation.stall_rate_ok ? "✅" : "❌");
    printf("  Starvation:      %s\n", validation.starvation_ok ? "✅" : "❌");
}

TelemetryCollector::ValidationResult TelemetryCollector::Validate() const {
    ValidationResult result = {};
    
    auto prefetch_stats = prefetch_.CalculateStats();
    auto swap_stats = layer_swap_.CalculateStats();
    
    // VAL-026 Targets
    result.prefetch_latency_ok = prefetch_stats.p95_end_to_end_us < 500.0;
    result.layer_swap_ok = swap_stats.avg_swap_latency_us < 1000.0;
    result.stall_rate_ok = swap_stats.stall_rate < 0.05;  // < 5%
    result.starvation_ok = swap_stats.starvation_events == 0;
    
    result.overall_pass = result.prefetch_latency_ok && 
                          result.layer_swap_ok && 
                          result.stall_rate_ok && 
                          result.starvation_ok;
    
    return result;
}

//=============================================================================
// PreciseTimer Implementation
//=============================================================================

PreciseTimer::PreciseTimer() {
    QueryPerformanceFrequency(&freq_);
}

void PreciseTimer::Start() {
    QueryPerformanceCounter(&start_);
}

uint64_t PreciseTimer::ElapsedMicroseconds() const {
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    
    return static_cast<uint64_t>(
        (end.QuadPart - start_.QuadPart) * 1000000 / freq_.QuadPart
    );
}

uint64_t PreciseTimer::ElapsedNanoseconds() const {
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    
    return static_cast<uint64_t>(
        (end.QuadPart - start_.QuadPart) * 1000000000 / freq_.QuadPart
    );
}

} // namespace Memory
} // namespace RawrXD
