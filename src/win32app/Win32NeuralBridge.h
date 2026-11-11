// Win32NeuralBridge.h — Stub for build compatibility
// Provides minimal NeuralBridge namespace for Win32IDE compilation

#pragma once

#include <string>

namespace NeuralBridge {
    inline bool IsInitialized() { return false; }
    inline void Shutdown() {}
    inline bool Initialize(const std::string& config = "") { (void)config; return true; }
    inline bool RunSmokeTest(std::string* report = nullptr) { if (report) *report = "NeuralBridge smoke test stub"; return true; }
}
