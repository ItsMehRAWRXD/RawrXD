#include "CallStackIntegration.hpp"
#include "CallStackPanel.h"

namespace UI {

namespace {
HWND g_hwnd = nullptr;
CallStackPanel* g_panel = nullptr;
bool g_initialized = false;
}  // namespace

bool CallStackIntegration::Initialize(HWND hwndMain, CallStackPanel* panel) {
    if (!hwndMain || !panel) return false;
    g_hwnd = hwndMain;
    g_panel = panel;
    g_initialized = true;
    return true;
}

void CallStackIntegration::RegisterWithDapService() {
    // The DapService is a process singleton; no per-panel registration is required.
    // This hook exists so the lifecycle is explicit and future multi-session support
    // can attach the panel here.
}

void CallStackIntegration::UnregisterFromDapService() {}

void CallStackIntegration::Shutdown() {
    g_initialized = false;
    g_hwnd = nullptr;
    g_panel = nullptr;
}

bool CallStackIntegration::IsInitialized() { return g_initialized; }

bool HandleDapMessages(HWND, UINT, WPARAM, LPARAM) {
    // DAP protocol requests are handled by Win32IDE_DAPServer; this UI bridge
    // consumes no window messages by default (returns false = not handled).
    return false;
}

}  // namespace UI