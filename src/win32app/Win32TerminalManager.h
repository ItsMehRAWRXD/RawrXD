#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

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
    bool startCommandLine(ShellType shell, const std::string& commandLine);
    void stop();
    DWORD pid() const;
    bool isRunning() const;
    void writeInput(const std::string& data);
    // Close the parent side of stdin after a one-shot script has been
    // submitted.  PowerShell's `-Command -` consumes the script at EOF;
    // persistent interactive terminals do not call this.
    void closeInput();

    // Callbacks
    std::function<void(const std::string&)> onOutput;
    std::function<void(const std::string&)> onError;
    std::function<void()> onStarted;
    std::function<void(int)> onFinished;

private:
    void readOutputThread();
    void readErrorThread();
    void monitorProcessThread();

    HANDLE m_hProcess;
    HANDLE m_hThread;
    DWORD m_processId;

    HANDLE m_hStdInRead;
    HANDLE m_hStdInWrite;
    HANDLE m_hStdOutRead;
    HANDLE m_hStdOutWrite;
    HANDLE m_hStdErrRead;
    HANDLE m_hStdErrWrite;

    std::thread m_outputThread;
    std::thread m_errorThread;
    std::thread m_monitorThread;

    std::atomic<bool> m_running;
    std::atomic<uint64_t> m_stdoutBytes{0};
    std::atomic<uint64_t> m_stderrBytes{0};
    ShellType m_shellType;
};
