// ============================================================================
// perf_telemetry_stubs.cpp - Stub implementations for performance telemetry
// ============================================================================

#include <windows.h>
#include <cstdint>

extern "C" {

void asm_perf_begin(const char* name) {
    (void)name;
    // Stub - no operation
}

void asm_perf_end(const char* name) {
    (void)name;
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
