// ============================================================================
// agentic_bridge_headless.cpp — Headless AgenticBridge (headless build variant) for RawrEngine
// ============================================================================
// RawrEngine has no Win32IDE; Win32IDE_AgenticBridge requires Win32IDE*.
// This file provides minimal implementations so AgentLoop and other agentic
// code link without the full Win32 GUI stack.
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

// Winsock2 must come before Win32IDE_AgenticBridge.h (which pulls windows.h)
#include <winsock2.h>
#include <ws2tcpip.h>
#include "Win32IDE_AgenticBridge.h"
#include <stdio.h>

// Forward-declared; never dereferenced in headless
struct Win32IDE;

AgenticBridge::AgenticBridge(Win32IDE* ide)
    : m_ide(ide)
    , m_initialized(false)
    , m_agentLoopRunning(false)
    , m_hProcess(nullptr)
    , m_hStdoutRead(nullptr)
    , m_hStdoutWrite(nullptr)
    , m_hStdinRead(nullptr)
    , m_hStdinWrite(nullptr)
    , m_headlessPort(0)
    , m_headlessPipe(INVALID_HANDLE_VALUE)
{
    (void)ide;
}

AgenticBridge::~AgenticBridge() {}

bool AgenticBridge::Initialize(const std::string&, const std::string&) { return false; }

AgentResponse AgenticBridge::ExecuteAgentCommand(const std::string& prompt) {
    (void)prompt;
    return {AgentResponseType::AGENT_ERROR, "Headless: AgenticBridge not available"};
}

bool AgenticBridge::StartAgentLoop(const std::string&, int) { return false; }
void AgenticBridge::StopAgentLoop() {}
std::vector<std::string> AgenticBridge::GetAvailableTools() { return {}; }
std::string AgenticBridge::GetAgentStatus() { return "Headless"; }
void AgenticBridge::SetModel(const std::string&) {}
void AgenticBridge::SetOllamaServer(const std::string&) {}
void AgenticBridge::SetMaxMode(bool) {}
void AgenticBridge::SetDeepThinking(bool) {}
void AgenticBridge::SetDeepResearch(bool) {}
void AgenticBridge::SetNoRefusal(bool) {}
void AgenticBridge::SetAutoCorrect(bool) {}
void AgenticBridge::SetContextSize(const std::string&) {}
bool AgenticBridge::LoadModel(const std::string&) { return false; }
void AgenticBridge::SetLanguageContext(const std::string&, const std::string&) {}
void AgenticBridge::SetOutputCallback(OutputCallback) {}

std::string AgenticBridge::RunDumpbin(const std::string&, const std::string&) { return ""; }
std::string AgenticBridge::RunCodex(const std::string&) { return ""; }
std::string AgenticBridge::RunCompiler(const std::string&) { return ""; }
SubAgentManager* AgenticBridge::GetSubAgentManager() { return nullptr; }
std::string AgenticBridge::RunSubAgent(const std::string&, const std::string&) { return ""; }
std::string AgenticBridge::ExecuteChain(const std::vector<std::string>&, const std::string&) { return ""; }
std::string AgenticBridge::ExecuteSwarm(const std::vector<std::string>&, const std::string&, int) { return ""; }
void AgenticBridge::CancelAllSubAgents() {}
std::string AgenticBridge::GetSubAgentStatus() const { return ""; }
bool AgenticBridge::DispatchModelToolCalls(const std::string&, std::string&) { return false; }

// IPC stubs — fully stubbed in headless; real transport lives in Win32IDE bridge
bool AgenticBridge::ConnectToHeadlessBackend(int)     { return false; }
void AgenticBridge::DisconnectHeadlessBackend()       {}
AgentResponse AgenticBridge::SendViaLoopbackHttp(const std::string&) {
    return {AgentResponseType::AGENT_ERROR, "Headless: loopback IPC unavailable"};
}
AgentResponse AgenticBridge::SendViaNamedPipe(const std::string&) {
    return {AgentResponseType::AGENT_ERROR, "Headless: named pipe IPC unavailable"};
}

// ============================================================================
// StartHeadlessServer / StopHeadlessServer / GetHeadlessServerPort
//
// Launches the current executable with --headless --port <port> to spin up
// HeadlessIDE's HTTP API server + agent loop in a detached child process.
// The caller then connects via ConnectToHeadlessBackend(port).
// ============================================================================

namespace {

static HANDLE s_headlessProc = nullptr;
static int    s_headlessPort = 0;

// Probe whether a TCP port is accepting connections on 127.0.0.1
static bool HeadlessProbePort(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool up = (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    closesocket(s);
    return up;
}

} // namespace

// Starts the headless backend (port 11435 by default).
// Blocks up to 10 s waiting for the port to open.
// Returns the listening port on success, 0 on failure.
extern "C" int StartHeadlessServer(int preferredPort) {
    // Reuse already-running process if alive
    if (s_headlessProc != nullptr) {
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(s_headlessProc, &exitCode);
        if (exitCode == STILL_ACTIVE && s_headlessPort > 0) return s_headlessPort;
        CloseHandle(s_headlessProc);
        s_headlessProc = nullptr;
        s_headlessPort = 0;
    }

    WSADATA wsaData{};
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (preferredPort <= 0 || preferredPort > 65535) preferredPort = 11435;

    // Resolve path of the current executable
    char exePath[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, exePath, MAX_PATH - 1)) return 0;

    // Build command-line: same binary, headless mode
    char cmdLine[MAX_PATH + 64]{};
    _snprintf_s(cmdLine, sizeof(cmdLine), _TRUNCATE,
                "\"%s\" --headless --port %d --quiet", exePath, preferredPort);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(nullptr, cmdLine, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | DETACHED_PROCESS,
                        nullptr, nullptr, &si, &pi)) {
        return 0;
    }

    CloseHandle(pi.hThread);
    s_headlessProc = pi.hProcess;
    s_headlessPort = preferredPort;

    // Poll up to 10 s (100 × 100 ms) for the port to accept connections
    for (int attempt = 0; attempt < 100; ++attempt) {
        Sleep(100);
        if (HeadlessProbePort(preferredPort)) return preferredPort;

        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(s_headlessProc, &exitCode);
        if (exitCode != STILL_ACTIVE) {
            // Child terminated before opening the port
            CloseHandle(s_headlessProc);
            s_headlessProc = nullptr;
            s_headlessPort = 0;
            return 0;
        }
    }

    // Process alive but port never opened; caller may retry
    return 0;
}

// Terminate a running headless server process.
extern "C" void StopHeadlessServer(void) {
    if (!s_headlessProc) return;
    TerminateProcess(s_headlessProc, 0);
    WaitForSingleObject(s_headlessProc, 3000);
    CloseHandle(s_headlessProc);
    s_headlessProc = nullptr;
    s_headlessPort = 0;
}

// Query the port of an already-started headless server (0 if not running).
extern "C" int GetHeadlessServerPort(void) {
    return s_headlessPort;
}
