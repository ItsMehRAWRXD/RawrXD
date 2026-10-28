#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

// CONPTY_STREAM_OWNER_001: product ConPTY/PTY stream owner for PowerShell
// panel + terminal tabs (Win32IDE::m_dedicatedPowerShellTerminal / tab.manager).
// CreatePseudoConsole path — SOURCE_WIRED; RELINK_REQUIRED; RUNTIME=NOT_RUN.
// HWND chrome geometry remains getPowerShellPanel (SHELLLAYOUT_PHASE5_001).

#ifndef HPCON
typedef VOID* HPCON;
#endif

class Win32TerminalManager
{
public:
    enum ShellType {
        PowerShell,
        CommandPrompt
    };

    Win32TerminalManager();
    ~Win32TerminalManager();

    bool start(ShellType shell);
    void stop();
    DWORD pid() const;
    bool isRunning() const;
    void writeInput(const std::string& data);

    std::function<void(const std::string&)> onOutput;
    std::function<void(const std::string&)> onError;
    std::function<void()> onStarted;
    std::function<void(int)> onFinished;

private:
    void readOutputThread();
    void monitorProcessThread();
    static void GateConPtyStream(const char* reason);
    static bool ResolveConPtyApis();

    HANDLE m_hProcess;
    HANDLE m_hThread;
    DWORD m_processId;
    HPCON m_hPC;

    HANDLE m_hStdInWrite;   // parent → ConPTY
    HANDLE m_hStdOutRead;   // ConPTY → parent (stdout+stderr merged)

    std::thread m_outputThread;
    std::thread m_monitorThread;

    std::atomic<bool> m_running;
    ShellType m_shellType;
};
