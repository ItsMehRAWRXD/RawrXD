// ============================================================================
// telemetry_stub.cpp - Bridge from Telemetry_* to MasmTelemetry_*
// ============================================================================
// Implements the C++ Telemetry API using the MASM telemetry core
// ============================================================================

#include "telemetry_ids.hpp"
#include "telemetry_masm_bridge.hpp"

namespace RawrXD {
namespace Runtime {
namespace Telemetry {

// ============================================================================
// Bridge Functions: C++ Telemetry API -> MASM Telemetry Core
// ============================================================================

extern "C" {

void Telemetry_Log(uint32_t phase_id, uint64_t value0, uint64_t value1) {
    MasmTelemetry_Log(phase_id, value0, value1);
}

uint64_t Telemetry_Dump(TelemetryEntry* buffer, uint64_t max_entries) {
    // For now, just flush and return 0 (no direct buffer access)
    // In full implementation, would copy from MASM ring buffer
    MasmTelemetry_Flush();
    return 0;
}

void Telemetry_Reset() {
    // Not implemented in MASM core - would need to reset indices
}

uint64_t Telemetry_GetCount() {
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    return stats.eventsLogged;
}

uint64_t Telemetry_GetDropped() {
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    return stats.eventsDropped;
}

uint64_t Telemetry_Now() {
    return MasmTelemetry_Rdtsc();
}

} // extern "C"

} // namespace Telemetry
} // namespace Runtime
} // namespace RawrXD
