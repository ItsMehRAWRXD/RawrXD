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

    // Transport actually used by the last successful start().
    enum Transport {
        TransportNone = 0,
        TransportPipe = 1,
        TransportConPTY = 2
    };

    Win32TerminalManager();
    ~Win32TerminalManager();

    bool start(ShellType shell);
    bool startCommandLine(ShellType shell, const std::string& commandLine);
    // Panel/command-pump path: redirected pipes + `-Command -` (no ConPTY VT).
    bool startNonInteractive(ShellType shell);
    void stop();
    DWORD pid() const;
    bool isRunning() const;
    Transport transport() const { return m_transport; }
    void writeInput(const std::string& data);
    // Close the parent side of stdin after a one-shot script has been
    // submitted.  PowerShell's `-Command -` consumes the script at EOF;
    // persistent interactive terminals do not call this.
    void closeInput();
    // Resize ConPTY (no-op for pipe transport).
    void resize(short cols, short rows);
    // Deliver Ctrl+C (0x03) to ConPTY input; falls back to TerminateProcess.
    bool interrupt();
    int lastExitCode() const { return m_lastExitCode; }

    // Callbacks
    std::function<void(const std::string&)> onOutput;
    std::function<void(const std::string&)> onError;
    std::function<void()> onStarted;
    std::function<void(int)> onFinished;

private:
    bool startConPTY(ShellType shell, const std::string& commandLine);
    bool startPipe(ShellType shell, const std::string& commandLine);
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

    // ConPTY handle (HPCON). Null when using pipe transport.
    void* m_hPC;
    Transport m_transport;

    std::thread m_outputThread;
    std::thread m_errorThread;
    std::thread m_monitorThread;

    std::atomic<bool> m_running;
    std::atomic<uint64_t> m_stdoutBytes{0};
    std::atomic<uint64_t> m_stderrBytes{0};
    std::atomic<int> m_lastExitCode{0};
    // 0 = infinite (interactive). Non-zero for one-shot fixture/compile pipes.
    DWORD m_boundedWaitMs{0};
    ShellType m_shellType;
};
