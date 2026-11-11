//=============================================================================
// Prefetch Telemetry - Reality Check for IOCP Performance
// Measures: request_issued → NVMe_submit → IOCP_completion → tensor_ready
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <chrono>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Prefetch Telemetry Structure
// Tracks the complete pipeline: request → NVMe → completion → ready
//=============================================================================

struct PrefetchTelemetry {
    // Counters
    alignas(64) std::atomic<uint64_t> requests{0};
    alignas(64) std::atomic<uint64_t> completed{0};
    alignas(64) std::atomic<uint64_t> cache_hits{0};
    alignas(64) std::atomic<uint64_t> cache_misses{0};
    
    // Byte counters
    alignas(64) std::atomic<uint64_t> bytes_requested{0};
    alignas(64) std::atomic<uint64_t> bytes_loaded{0};
    
    // Latency tracking (microseconds)
    // submit_us: Time from request to NVMe queue submit
    // completion_us: Time from NVMe submit to IOCP completion
    // end_to_end_us: Total time from request to tensor ready
    alignas(64) std::atomic<uint64_t> total_submit_us{0};
    alignas(64) std::atomic<uint64_t> total_completion_us{0};
    alignas(64) std::atomic<uint64_t> total_end_to_end_us{0};
    
    // For percentile calculation (circular buffer of last N samples)
    static constexpr size_t kMaxSamples = 10000;
    alignas(64) uint64_t end_to_end_samples[kMaxSamples];
    alignas(64) std::atomic<size_t> sample_index{0};
    
    // Record a prefetch operation
    void RecordRequest(size_t bytes);
    void RecordSubmit(uint64_t submit_latency_us);
    void RecordCompletion(uint64_t completion_latency_us, size_t bytes);
    void RecordCacheHit();
    void RecordCacheMiss();
    
    // Calculate statistics
    struct Stats {
        uint64_t requests;
        uint64_t completed;
        uint64_t cache_hits;
        uint64_t cache_misses;
        double hit_rate;
        
        double avg_submit_us;
        double avg_completion_us;
        double avg_end_to_end_us;
        
        double p50_end_to_end_us;
        double p95_end_to_end_us;
        double p99_end_to_end_us;
        
        uint64_t bytes_requested;
        uint64_t bytes_loaded;
        double bandwidth_mbps;
    };
    Stats CalculateStats() const;
    
    // Reset counters
    void Reset();
    
    // Validation target check
    bool MeetsLatencyTarget(double target_p95_us) const;
};

//=============================================================================
// Layer Swap Telemetry
// Tracks: layer_needed → layer_ready (the critical metric)
//=============================================================================

struct LayerSwapTelemetry {
    // Layer swap events
    alignas(64) std::atomic<uint64_t> layer_swaps{0};
    alignas(64) std::atomic<uint64_t> swap_stalls{0};  // When layer not ready in time
    
    // Latency: from "need layer N" to "layer N ready"
    alignas(64) std::atomic<uint64_t> total_swap_latency_us{0};
    alignas(64) std::atomic<uint64_t> max_swap_latency_us{0};
    
    // Kernel starvation (when compute waits for memory)
    alignas(64) std::atomic<uint64_t> kernel_starvation_events{0};
    alignas(64) std::atomic<uint64_t> total_starvation_us{0};
    
    void RecordLayerSwap(uint64_t latency_us, bool stalled);
    void RecordKernelStarvation(uint64_t duration_us);
    
    struct Stats {
        uint64_t swaps;
        uint64_t stalls;
        double stall_rate;  // Should be < 5%
        
        double avg_swap_latency_us;
        uint64_t max_swap_latency_us;
        
        uint64_t starvation_events;
        double avg_starvation_us;
        double starvation_rate;  // Should be 0%
    };
    Stats CalculateStats() const;
};

//=============================================================================
// Telemetry Collector
// Aggregates all prefetch-related telemetry
//=============================================================================

class TelemetryCollector {
public:
    static TelemetryCollector& Instance();
    
    // Access telemetry structures
    PrefetchTelemetry& GetPrefetchTelemetry() { return prefetch_; }
    LayerSwapTelemetry& GetLayerSwapTelemetry() { return layer_swap_; }
    
    // Print report
    void PrintReport() const;
    
    // Validate against VAL-026 targets
    struct ValidationResult {
        bool prefetch_latency_ok;      // P95 < 500μs
        bool layer_swap_ok;            // P95 < 1000μs
        bool stall_rate_ok;            // < 5%
        bool starvation_ok;            // 0%
        bool overall_pass;
    };
    ValidationResult Validate() const;
    
private:
    TelemetryCollector() = default;
    
    PrefetchTelemetry prefetch_;
    LayerSwapTelemetry layer_swap_;
};

//=============================================================================
// High-Resolution Timer
// For microsecond-precision latency measurement
//=============================================================================

class PreciseTimer {
public:
    PreciseTimer();
    
    void Start();
    uint64_t ElapsedMicroseconds() const;
    uint64_t ElapsedNanoseconds() const;
    
private:
    LARGE_INTEGER freq_;
    LARGE_INTEGER start_;
};

} // namespace Memory
} // namespace RawrXD
