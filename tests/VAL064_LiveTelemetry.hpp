// ============================================================================
// VAL064_LiveTelemetry.hpp — Live Telemetry Integration for VAL-064
// ============================================================================
// Connects the VAL-064 certification harness to the RawrXD MASM telemetry
// kernel for real-time performance measurements.
// ============================================================================
#pragma once

#include <string>
#include <cstdint>
#include <chrono>

namespace VAL064 {

// ============================================================================
// Certification Metrics (matches VAL-064 schema)
// ============================================================================
struct CertificationMetrics {
    double prefill_tps = 0.0;
    double decode_tps = 0.0;
    double first_token_ms = 0.0;
    double peak_vram_mb = 0.0;
    double peak_ram_mb = 0.0;
    double kv_cache_mb = 0.0;
    double gpu_util_pct = 0.0;
    double current_ram_mb = 0.0;
    uint64_t total_tokens = 0;
    bool valid = false;
    uint64_t timestamp_ns = 0;
};

// ============================================================================
// Live Telemetry — Binds to RawrXD MASM Telemetry Kernel
// ============================================================================
class LiveTelemetry {
public:
    // Capture current telemetry snapshot
    static CertificationMetrics Capture();
    
    // Initialize the MASM telemetry kernel
    static bool Initialize();
    
    // Shutdown the MASM telemetry kernel
    static void Shutdown();
    
    // Read a named telemetry counter
    static double ReadTelemetryCounter(const std::string& name);
    
    // Read a Windows performance counter
    static double ReadPerformanceCounter(const std::string& name);
    
    // Log a telemetry event
    static void LogEvent(const std::string& message);
    
    // Flush telemetry to disk
    static void Flush();
    
    // Reset all counters
    static void ResetCounters();
};

} // namespace VAL064
