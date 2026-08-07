// ============================================================================
// perf_telemetry_stubs.cpp - Stub implementations for performance telemetry
// ============================================================================

#include <windows.h>
#include <cstdint>

extern "C" {

// Version for slot-based telemetry (used by speculative decoder)
uint64_t asm_perf_begin(uint32_t slot) {
    (void)slot;
    return 0; // Return 0 as start timestamp
}

void asm_perf_end(uint32_t slot, uint64_t start_tsc) {
    (void)slot;
    (void)start_tsc;
    // Stub - no operation
}

void asm_perf_init() {
    OutputDebugStringA("[PerfTelemetry] asm_perf_init stub called\n");
}

uint64_t asm_perf_read_slot(int slot) {
    (void)slot;
    OutputDebugStringA("[PerfTelemetry] asm_perf_read_slot stub called\n");
    return 0;
}

void asm_perf_reset_slot(int slot) {
    (void)slot;
    OutputDebugStringA("[PerfTelemetry] asm_perf_reset_slot stub called\n");
}

} // extern "C"
