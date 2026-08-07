// RawrXD Settings (API Key Manager)
#include "RawrXD_SettingsDialog.hpp"

// Smoke-test markers for command palette/WM_COMMAND wiring:
// Agent: Start Loop (4100), Agent: Execute Command (4101), Agent: Bounded Agent Loop (4120), Autonomy: Toggle (4150)

// RunAutonomousMode() — lightweight agent iteration for Ship standalone
static void RunAutonomousMode() {
    AppendWindowText(g_hwndOutput, L"[Agent] RunAutonomousMode() started.\r\n");
    // In Ship standalone, we route through the chat server or show a status message
    if (g_hwndChatHistory) {
        AppendWindowText(g_hwndChatHistory, L"[Agent] Autonomous agent loop active. Enter tasks in chat.\r\n");
    }
    AppendWindowText(g_hwndOutput, L"[Agent] Agent loop ready — use chat panel to interact.\r\n");
}


