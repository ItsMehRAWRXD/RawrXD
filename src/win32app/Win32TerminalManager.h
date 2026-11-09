#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

// CONPTY_STREAM_OWNER_001 + FOUR_PANEL_COMPLETION_001 Track G:
// Product CreatePseudoConsole owner. Capture fix (OS 26300):
// CREATE_SUSPENDED + close PTY-side pipes before ResumeThread +
// STARTF_USESTDHANDLES cleared + UpdateProcThreadAttribute(hPC).
// PROMOTE=0 TIP_CLIMB=HOLD. No redirected-pipe-only interactive claim.

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

    void setWorkingDirectory(const std::wstring& cwd);
    bool start(ShellType shell);
    void stop();
    bool resize(short cols, short rows);
    void interrupt();
    bool restart();
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
    bool assignJobObject();
    static void GateConPtyStream(const char* reason);
    static bool ResolveConPtyApis();

    HANDLE m_hProcess;
    HANDLE m_hThread;
    HANDLE m_hJob;
    DWORD m_processId;
    HPCON m_hPC;

    HANDLE m_hStdInWrite;
    HANDLE m_hStdOutRead;

    std::thread m_outputThread;
    std::thread m_monitorThread;

    std::atomic<bool> m_running;
    ShellType m_shellType;
    std::wstring m_workingDir;
    short m_cols;
    short m_rows;
};