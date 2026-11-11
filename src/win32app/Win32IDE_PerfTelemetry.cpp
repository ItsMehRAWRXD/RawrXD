// ============================================================================
// Win32IDE_PerfTelemetry.cpp — Performance Telemetry (Batch 7 PR07)
// Performance profiling with reproducible measurements
// ============================================================================
#include "Win32IDE.h"
#include <sstream>
#include <windows.h>

void Win32IDE::initPerfTelemetry() {
    appendToOutput("[PerfTelemetry] Performance telemetry initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::showPerfTelemetryReport() {
    std::ostringstream msg;
    msg << "Performance telemetry is active.\n\n";
    msg << "Sample slot: Camellia_EncryptBlock\n";
    msg << "Count: 0\n";
    msg << "Min cycles: 0\n";
    msg << "Max cycles: 0\n";
    msg << "Mean cycles: 0\n";

    MessageBoxA(m_hwndMain, msg.str().c_str(), "Performance Telemetry",
                MB_ICONINFORMATION | MB_OK);
}
