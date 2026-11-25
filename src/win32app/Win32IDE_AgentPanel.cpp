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
#include <fstream>
#include <string>

// A5: native IDE routes through the shared agent controller (same production
// loop as the CLI). Implemented in Win32IDE_AgentControllerBridge.cpp.
void RawrXD_IDE_RunAgenticTask(HWND transcriptHwnd, const std::string& goal,
                               const std::string& root);
void RawrXD_IDE_SetE2EReceipt(const char* path);

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
    std::string root = m_agentRootOverride.empty()
                           ? std::filesystem::current_path().string()
                           : m_agentRootOverride;
    appendAgentTranscript("[agent] dispatching to shared controller...\r\n");
    RawrXD_IDE_RunAgenticTask(m_hwndAgentTranscript, staged, root);
}

// A5 native --agent-e2e-test: build an isolated workspace with a deliberately
// broken program, then drive the REAL agent-panel submission path. The worker
// writes the receipt and ExitProcess (0 = host-verified success).
void Win32IDE::beginAgentE2ETest(const char* receiptPath) {
    namespace fs = std::filesystem;
    const std::string ws = "F:\\rawrxd\\_e2e_ws";
    std::error_code ec;
    fs::remove_all(ws, ec);
    fs::create_directories(fs::path(ws) / "src", ec);
    {
        std::ofstream c(fs::path(ws) / "CMakeLists.txt", std::ios::trunc);
        c << "cmake_minimum_required(VERSION 3.20)\nproject(e2e C)\n"
             "add_executable(e2e src/main.c)\n";
    }
    {
        std::ofstream m(fs::path(ws) / "src" / "main.c", std::ios::trunc);
        m << "#include <stdio.h>\nint main(void){ return 1; }\n";
    }
    m_agentRootOverride = ws;
    RawrXD_IDE_SetE2EReceipt(receiptPath);
    if (m_hwndAgentInput && IsWindow(m_hwndAgentInput)) {
        SetWindowTextA(
            m_hwndAgentInput,
            "Edit src/main.c: replace return 1 with return 0. Then call "
            "run_build with dir=\".\" config=\"Release\". Then call run_shell "
            "with command \"build\\Release\\e2e.exe\". Reply final.");
    }
    appendAgentTranscript(
        "[e2e] isolated workspace ready; submitting via agent panel...\r\n");
    submitAgentPrompt();
}

// A5 native --graphical-e2e-test: exercise the ACTUAL native editor buffer
// (open -> modify buffer -> save) and then build + run through the agent panel.
// This closes the graphical-acceptance gap the agent-e2e harness leaves: the
// editor buffer is the source of truth, not a direct on-disk tool write.
void Win32IDE::beginGraphicalE2ETest(const char* receiptPath) {
    namespace fs = std::filesystem;
    const std::string ws = "F:\\rawrxd\\_e2e_ws";
    std::error_code ec;
    fs::remove_all(ws, ec);
    fs::create_directories(fs::path(ws) / "src", ec);
    {
        std::ofstream c(fs::path(ws) / "CMakeLists.txt", std::ios::trunc);
        c << "cmake_minimum_required(VERSION 3.20)\nproject(e2e C)\n"
             "add_executable(e2e src/main.c)\n";
    }
    {
        std::ofstream m(fs::path(ws) / "src" / "main.c", std::ios::trunc);
        m << "#include <stdio.h>\nint main(void){ return 1; }\n";
    }
    m_agentRootOverride = ws;
    RawrXD_IDE_SetE2EReceipt(receiptPath);
    // Authoritative document-load contract (finishers 1-12): clean editor state,
    // synchronous load, then VERIFY the buffer matches the file bytes before any
    // modification. A load that does not apply is a hard failure with a terminal
    // receipt -- never a write of stale content into the file.
    m_fileModified = false;
    const std::string mainPath = (fs::path(ws) / "src" / "main.c").string();
    const bool loaded = openDocumentPath(mainPath);
    std::string buf = (m_hwndEditor && IsWindow(m_hwndEditor))
                          ? getWindowTextUtf8(m_hwndEditor)
                          : std::string();
    if (!loaded || buf.find("return 1") == std::string::npos) {
        std::ofstream rec(receiptPath, std::ios::trunc);
        if (rec)
            rec << "COMPLETED=FAIL\nREASON=EDITOR_LOAD_MISMATCH\nLOADED="
                << (loaded ? 1 : 0) << "\n";
        ::ExitProcess(2);
    }
    // (3) Modify the production editor buffer: return 1 -> return 0.
    std::string modified = buf;
    const auto pos = modified.find("return 1");
    if (pos != std::string::npos) modified.replace(pos, 8, "return 0");
    // RichEdit is a Unicode control: WM_SETTEXT needs a UTF-16 string. Sending a
    // UTF-8 char* makes the control reinterpret the bytes as UTF-16 (mojibake).
    if (m_hwndEditor && IsWindow(m_hwndEditor)) {
        const int wlen = MultiByteToWideChar(
            CP_UTF8, 0, modified.c_str(), -1, nullptr, 0);
        if (wlen > 0) {
            std::wstring wide(static_cast<size_t>(wlen), L'\0');
            MultiByteToWideChar(
                CP_UTF8, 0, modified.c_str(), -1, wide.data(), wlen);
            SendMessageW(m_hwndEditor, WM_SETTEXT, 0,
                         reinterpret_cast<LPARAM>(wide.c_str()));
        }
    }
    // (4) Save through the IDE editor, then verify exact saved bytes.
    saveFile();
    {
        std::ifstream chk(mainPath, std::ios::binary);
        std::string saved((std::istreambuf_iterator<char>(chk)),
                          std::istreambuf_iterator<char>());
        if (saved.find("return 0") == std::string::npos) {
            std::ofstream rec(receiptPath, std::ios::trunc);
            if (rec) rec << "COMPLETED=FAIL\nREASON=SAVE_BYTE_MISMATCH\n";
            ::ExitProcess(2);
        }
    }
    // (5-9) Build + run + present results through the agent panel.
    if (m_hwndAgentInput && IsWindow(m_hwndAgentInput)) {
        SetWindowTextA(
            m_hwndAgentInput,
            "Call run_build with dir=\".\" config=\"Release\". Then call "
            "run_shell with command \"F:\\rawrxd\\_e2e_ws\\build\\Release\\e2e.exe\". "
            "Reply final.");
    }
    appendAgentTranscript(
        "[graph-e2e] editor buffer modified + saved (bytes verified); building...\r\n");
    submitAgentPrompt();
}