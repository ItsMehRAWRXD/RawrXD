// Win32NeuralBridge.h — GATED_STUB (IDE_BRIDGE_STUB_GATE_001)
// Orphan header: not included by Win32IDE product path; CMake-omitted TU sibling
// (Win32IDE_NeuralBridge.cpp comment-omit). Match GateMode: log + false.
// Smoke must NOT claim PASS. PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0.

#pragma once

#include <string>
#include <windows.h>

namespace NeuralBridge {

namespace {
inline void GateStub(const char* name) {
    char buf[192];
    wsprintfA(buf, "[Win32NeuralBridge] GATED_STUB SYNTHETIC=partial name=%s\n", name);
    OutputDebugStringA(buf);
}
} // namespace

inline bool IsInitialized() { return false; }
inline void Shutdown() { GateStub("Shutdown"); }

// Was: return true — silent fake success. Fail-closed.
inline bool Initialize(const std::string& config = "") {
    (void)config;
    GateStub("Initialize");
    return false;
}

// Was: report="…stub" + return true (smoke PASS theater). Fail-closed.
inline bool RunSmokeTest(std::string* report = nullptr) {
    GateStub("RunSmokeTest");
    if (report) {
        *report = "GATED_STUB IDE_BRIDGE_STUB_GATE_001 SYNTHETIC=partial NOT_PASS";
    }
    return false;
}

} // namespace NeuralBridge
