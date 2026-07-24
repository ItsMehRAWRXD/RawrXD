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

} // extern "C"
