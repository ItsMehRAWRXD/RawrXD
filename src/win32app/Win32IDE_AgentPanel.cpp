// =============================================================================
// Win32IDE_AgentPanel.cpp — A1 agent panel host (TOP50 A1).
// =============================================================================
// Replaces the undefined initAgentPanel() stub: a real docked panel (tab 4)
// with a read-only transcript, an input line and a Send button. Send routes
// through the existing chat pipeline (stageCopilotChatInputUtf8 +
// HandleCopilotSend) so the panel is a second surface onto the SAME backend,
// not a parallel model path. A5 streams tokens into the transcript via
// appendAgentTranscript().
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <filesystem>
#include <string>

// A5: native IDE routes through the shared agent controller (same production
// loop as the CLI). Implemented in Win32IDE_AgentControllerBridge.cpp.
void RawrXD_IDE_RunAgenticTask(HWND transcriptHwnd, const std::string& goal,
                               const std::string& root);

// Control IDs are defined in Win32IDE_VSCodeUI.cpp (1308 transcript,
// 1309 input, 1310 send). The WM_COMMAND case lives in Win32IDE_lifecycle.cpp.

void Win32IDE::initAgentPanel() {
    // The panel body is created with the other panel bodies; this method is
    // the host entry point invoked at startup and by the View menu.
    ensurePanelTabBodies();
    if (!m_hwndAgentTranscript || !IsWindow(m_hwndAgentTranscript)) {
        OutputDebugStringA("WARN: initAgentPanel transcript missing\n");
        return;
    }
    if (!m_agentPanelSeeded) {
        appendAgentTranscript(
            "Agent panel ready. Messages route through the configured chat "
            "backend (Deep2/Ollama).\r\n");
        m_agentPanelSeeded = true;
    }
    switchPanelTab(PanelTab::Agent);
}

void Win32IDE::toggleAgentPanel() {
    if (m_activePanelTab == PanelTab::Agent) {
        switchPanelTab(PanelTab::Output);
    } else {
        initAgentPanel();
    }
}

void Win32IDE::appendAgentTranscript(const std::string& text) {
    if (!m_hwndAgentTranscript || !IsWindow(m_hwndAgentTranscript)) return;
    appendText(m_hwndAgentTranscript, text);
}

void Win32IDE::submitAgentPrompt() {
    if (!m_hwndAgentInput || !IsWindow(m_hwndAgentInput)) return;
    const std::string text = getWindowTextUtf8(m_hwndAgentInput);
    if (text.empty()) return;
    appendAgentTranscript("> " + text + "\r\n");
    SetWindowTextA(m_hwndAgentInput, "");
    // A4: an applied prompt template becomes the system prefix.
    std::string staged = text;
    if (!m_activeSystemPrompt.empty()) {
        staged = "[system] " + m_activeSystemPrompt + "\n\n" + text;
    }
    // A5: route through the SHARED agent controller (rawr::runAgentController)
    // on a worker thread — the same production loop the CLI uses — instead of a
    // parallel chat path. Tool receipts and the host verdict stream back into
    // this transcript.
    std::string root = std::filesystem::current_path().string();
    appendAgentTranscript("[agent] dispatching to shared controller...\r\n");
    RawrXD_IDE_RunAgenticTask(m_hwndAgentTranscript, staged, root);
}