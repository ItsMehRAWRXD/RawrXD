#include "embedded_terminal.hpp"
#include <cstdio>

namespace rawrxd::terminal {
namespace {
void GateEmbeddedConPty(const char* reason) {
    char line[240];
    std::snprintf(line, sizeof(line),
                  "[EMBEDDED_TERMINAL] FAIL_CLOSED reason=%s "
                  "OWNER=Win32TerminalManager SYNTHETIC_PIPE=0 NOT_PASS\n",
                  reason ? reason : "?");
    OutputDebugStringA(line);
}
}  // namespace

// Product CreatePseudoConsole stream owner = Win32TerminalManager.
// Pipe-as-ConPTY success (prior Track B v14.7) is FORBIDDEN.
bool EmbeddedTerminal::initialize(void* /*parent_hwnd*/, int /*width*/,
                                  int /*height*/) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32 || !GetProcAddress(k32, "CreatePseudoConsole")) {
        GateEmbeddedConPty("CreatePseudoConsole_absent");
        return false;
    }
    GateEmbeddedConPty("not_product_owner_use_Win32TerminalManager");
    return false;
}

bool EmbeddedTerminal::executeCommand(const std::string& /*command*/,
                                      OutputCallback /*output_cb*/,
                                      ExitCallback /*exit_cb*/) {
    GateEmbeddedConPty("execute_without_real_ConPTY");
    return false;
}

void EmbeddedTerminal::outputReader(OutputCallback /*cb*/) {}

std::string EmbeddedTerminal::executeAndCapture(const std::string& /*command*/,
                                                uint32_t /*timeout_ms*/) {
    GateEmbeddedConPty("capture_without_real_ConPTY");
    return "[ERROR] EmbeddedTerminal FAIL_CLOSED; use Win32TerminalManager";
}

void EmbeddedTerminal::terminate() {
    running_ = false;
}

bool EmbeddedTerminal::isRunning() const { return false; }
int EmbeddedTerminal::getLastExitCode() const { return last_exit_code_; }

bool EmbeddedTerminal::sendInput(const std::string& /*input*/) { return false; }
void EmbeddedTerminal::resize(int /*cols*/, int /*rows*/) {}
bool EmbeddedTerminal::initializeLegacy(void* /*parent_hwnd*/) {
    GateEmbeddedConPty("legacy_pipe_forbidden");
    return false;
}
void EmbeddedTerminal::errorReader(OutputCallback /*cb*/) {}

}  // namespace rawrxd::terminal
