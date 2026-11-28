#pragma once
// UI::CallStackIntegration — bridge between the DAP service and the call-stack panel.
#ifndef RAWRXD_UI_CALLSTACK_INTEGRATION_H
#define RAWRXD_UI_CALLSTACK_INTEGRATION_H

#include <windows.h>

namespace UI {

class CallStackPanel;

class CallStackIntegration {
public:
    static bool Initialize(HWND hwndMain, CallStackPanel* panel);
    static void RegisterWithDapService();
    static void UnregisterFromDapService();
    static void Shutdown();
    static bool IsInitialized();
};

// Returns true if the message was consumed by the debugger UI bridge.
bool HandleDapMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

}  // namespace UI

#endif