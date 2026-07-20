//=============================================================================
// Fix #4 Telemetry Integration
// Connects Fused Q4_0 Kernel to Performance Profiling
//=============================================================================
// This header provides telemetry hooks for the fused kernel to report
// performance metrics to the profiling system.
//=============================================================================

#pragma once

#include "kernels/RawrXD_FusedQ4_Kernel.hpp"
#include <cstdint>
#include <chrono>

namespace RawrXD {
namespace Telemetry {

//=============================================================================
// Fix #4 Performance Metrics
//=============================================================================
struct Fix4Metrics {
    // Timing
    double kernel_execution_ms;
    double setup_overhead_ms;
    
    // Throughput
    double tps_achieved;
    double tps_target;  // 650 TPS
    double efficiency_percent;
    
    // Cache performance
    uint64_t l1_misses;
    uint64_t l3_misses;
    double cache_hit_rate;
    
    // Instruction mix
    uint64_t avx512_instructions;
    uint64_t gather_instructions;
    uint64_t total_instructions;
    
    // Memory
    double memory_bandwidth_gbps;
    size_t bytes_read;
    size_t bytes_written;
};

//=============================================================================
// Telemetry Collector for Fix #4
//=============================================================================
class Fix4TelemetryCollector {
public:
    // Start collecting metrics for a kernel execution
    static void BeginKernelExecution(
        int M, int K, int N,
        const char* kernel_name = "FusedQ4_0_MatMul"
    );
    
    // End collection and report metrics
    static Fix4Metrics EndKernelExecution();
    
    // Report intermediate checkpoint (for long-running kernels)
    static void ReportCheckpoint(const char* stage);
    
    // Get last collected metrics
    static const Fix4Metrics& GetLastMetrics() { return s_last_metrics; }
    
    // Check if target TPS was achieved
    static bool IsTargetAchieved() {
        return s_last_metrics.tps_achieved >= 650.0;
    }
    
    // Export metrics to JSON for CI/CD integration
    static void ExportToJSON(const char* filename);

private:
    static Fix4Metrics s_last_metrics;
    static std::chrono::high_resolution_clock::time_point s_start_time;
    static bool s_collecting;
};

//=============================================================================
// Integration macros for kernel instrumentation
//=============================================================================
#ifdef RAWRXD_ENABLE_FIX4_TELEMETRY
    #define FIX4_TELEMETRY_BEGIN(m, k, n) \
        RawrXD::Telemetry::Fix4TelemetryCollector::BeginKernelExecution(m, k, n)
    
    #define FIX4_TELEMETRY_END() \
        RawrXD::Telemetry::Fix4TelemetryCollector::EndKernelExecution()
    
    #define FIX4_TELEMETRY_CHECKPOINT(stage) \
        RawrXD::Telemetry::Fix4TelemetryCollector::ReportCheckpoint(stage)
#else
    #define FIX4_TELEMETRY_BEGIN(m, k, n)
    #define FIX4_TELEMETRY_END()
    #define FIX4_TELEMETRY_CHECKPOINT(stage)
#endif

//=============================================================================
// Performance-Aware Replay Integration
// Connects to Deterministic Replay Gate for automated profiling
//=============================================================================
class Fix4ReplayIntegration {
public:
    // Called by replay gate when performance snapshot is triggered
    static void OnPerformanceSnapshot(
        uint64_t sequence_length,
        const Fix4Metrics& metrics
    );
    
    // Check if TPS drops below threshold at specific sequence length
    static bool IsTPSDegradationDetected(
        uint64_t sequence_length,
        double current_tps
    );
    
    // Get recommended sliding window size based on telemetry
    static uint32_t GetRecommendedWindowSize();
    
    // Export performance profile for analysis
    static void ExportPerformanceProfile(const char* filename);

private:
    static constexpr double TPS_DEGRADATION_THRESHOLD = 500.0;  // TPS below this triggers alert
    static constexpr uint64_t WINDOW_SIZE_GRANULARITY = 128;      // Round to nearest 128
};

} // namespace Telemetry
} // namespace RawrXD
