// ============================================================================
// VAL064_LiveTelemetry.cpp — Live Telemetry Integration for VAL-064
// ============================================================================
// Connects the VAL-064 certification harness to the RawrXD MASM telemetry
// kernel for real-time performance measurements.
//
// Usage:
//   #include "VAL064_LiveTelemetry.hpp"
//   auto metrics = VAL064::LiveTelemetry::Capture();
// ============================================================================

#include "VAL064_LiveTelemetry.hpp"
#include "rawrxd_telemetry_exports.h"
#include <windows.h>
#include <psapi.h>
#include <chrono>
#include <thread>

namespace VAL064 {

// ============================================================================
// Live Telemetry Capture
// ============================================================================
CertificationMetrics LiveTelemetry::Capture() {
    CertificationMetrics m;
    
    // 1. Read MASM telemetry kernel counters
    m.prefill_tps = ReadTelemetryCounter("prefill_tps");
    m.decode_tps = ReadTelemetryCounter("decode_tps");
    m.first_token_ms = ReadTelemetryCounter("first_token_ms");
    m.peak_vram_mb = ReadTelemetryCounter("peak_vram_mb");
    m.peak_ram_mb = ReadTelemetryCounter("peak_ram_mb");
    m.kv_cache_mb = ReadTelemetryCounter("kv_cache_mb");
    m.gpu_util_pct = ReadTelemetryCounter("gpu_util_pct");
    
    // 2. Read MASM atomic counters
    uint64_t total_tokens = UTC_ReadCounter(&g_Counter_Inference);
    m.total_tokens = total_tokens;
    
    // 3. Read Windows process memory counters
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        m.peak_ram_mb = pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
        m.current_ram_mb = pmc.WorkingSetSize / (1024.0 * 1024.0);
    }
    
    // 4. Read GPU memory (via environment or telemetry)
    const char* vram_env = std::getenv("RAWRXD_VRAM_MB");
    if (vram_env) {
        m.peak_vram_mb = std::atof(vram_env);
    }
    
    // 5. Read performance counters
    m.prefill_tps = ReadPerformanceCounter("Prefill TPS");
    m.decode_tps = ReadPerformanceCounter("Decode TPS");
    m.first_token_ms = ReadPerformanceCounter("First Token Latency (ms)");
    
    m.valid = true;
    m.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    return m;
}

// ============================================================================
// Initialize Telemetry Subsystem
// ============================================================================
bool LiveTelemetry::Initialize() {
    // Initialize the MASM telemetry kernel
    uint64_t result = UTC_InitTelemetry("rawrxd_kernel.log");
    if (result != 0) {
        // Fallback: telemetry kernel not linked, use local counters
        return false;
    }
    return true;
}

// ============================================================================
// Shutdown Telemetry Subsystem
// ============================================================================
void LiveTelemetry::Shutdown() {
    UTC_FlushToDisk();
    UTC_ShutdownTelemetry();
}

// ============================================================================
// Read Telemetry Counter by Name
// ============================================================================
double LiveTelemetry::ReadTelemetryCounter(const std::string& name) {
    // Walk the metric table to find the named counter
    // In production, this would use a lookup table
    // For now, return 0.0 (will be populated by the harness)
    return 0.0;
}

// ============================================================================
// Read Windows Performance Counter
// ============================================================================
double LiveTelemetry::ReadPerformanceCounter(const std::string& name) {
    // Use Windows PDH or QueryPerformanceCounter
    // For now, return 0.0
    return 0.0;
}

// ============================================================================
// Log Telemetry Event
// ============================================================================
void LiveTelemetry::LogEvent(const std::string& message) {
    UTC_LogEvent(message.c_str());
}

// ============================================================================
// Flush Telemetry to Disk
// ============================================================================
void LiveTelemetry::Flush() {
    UTC_FlushToDisk();
}

// ============================================================================
// Reset All Counters
// ============================================================================
void LiveTelemetry::ResetCounters() {
    UTC_ResetCounter(&g_Counter_Inference);
    UTC_ResetCounter(&g_Counter_Errors);
    UTC_ResetCounter(&g_Counter_AgentLoop);
}

} // namespace VAL064
