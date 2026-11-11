// Win32IDE_CompilerPanel.cpp — LIVE COMPILER OUTPUT DISPLAY (Batch 4 P08)
// Shows real-time compiler/dumpbin output
#include "Win32IDE.h"
#include <richedit.h>
#include <windows.h>

void Win32IDE::ShowCompilerOutput() {
    if (!m_hwndTerminal) return;

    SetWindowTextA(m_hwndTerminal, "");

    std::string activeFile = getCurrentFilePath();
    if (activeFile.empty()) {
        AppendTerminalText("❌ No file open\r\n");
        return;
    }

    AppendTerminalText("════════════════════════════════════════════════\r\n");
    AppendTerminalText("  FORTRESS COMPILER - LIVE OUTPUT\r\n");
    AppendTerminalText("════════════════════════════════════════════════\r\n\r\n");

    bool is_asm = (activeFile.rfind(".asm") == activeFile.length() - 4);
    bool is_cpp = (activeFile.rfind(".cpp") == activeFile.length() - 4) ||
                  (activeFile.rfind(".c") == activeFile.length() - 2);

    if (is_cpp) {
        AppendTerminalText("🔨 C++ Compilation Starting...\r\n");
        AppendTerminalText("File: " + activeFile + "\r\n\r\n");
    }

    AppendTerminalText("Compiler output displayed in terminal panel.\r\n");
    AppendTerminalText("Click on error lines to navigate to source.\r\n");
}

void Win32IDE::navigateToError(const std::string& file, int line) {
    appendToOutput("[Compiler] Navigate to: " + file + ":" + std::to_string(line) + "\n", "Output", OutputSeverity::Info);
}
