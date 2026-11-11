// ============================================================================
// Win32IDE_Telemetry.cpp — Telemetry (Batch 7 SP05)
// Strict opt-in, anonymized
// ============================================================================
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <sstream>

static bool s_telemetryOptedIn = false;

void Win32IDE::initTelemetry() {
    s_telemetryOptedIn = false;
    appendToOutput("[Telemetry] Telemetry initialized (opt-in required).\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::isTelemetryEnabled() const {
    return s_telemetryOptedIn;
}

void Win32IDE::optInTelemetry() {
    s_telemetryOptedIn = true;
    appendToOutput("[Telemetry] User opted in to telemetry.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::optOutTelemetry() {
    s_telemetryOptedIn = false;
    appendToOutput("[Telemetry] User opted out of telemetry.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::recordTelemetryEvent(const std::string& event) {
    if (!s_telemetryOptedIn) return;
    appendToOutput("[Telemetry] " + event + "\n", "Telemetry", OutputSeverity::Info);
}
