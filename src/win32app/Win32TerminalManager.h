#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <windows.h>

class Win32TerminalManager
{
  public:
    enum ShellType
    {
        PowerShell,
        CommandPrompt
    };

    Win32TerminalManager();
    ~Win32TerminalManager();

    /// Optional UTF-8 working directory for the child shell (CreateProcess lpCurrentDirectory).
    /// Pass nullptr to inherit the IDE process current directory.
    bool start(ShellType shell, const char* workingDirectoryUtf8 = nullptr);
    void stop();
    DWORD pid() const;
    bool isRunning() const;
    void writeInput(const std::string& data);

    // Callbacks
    std::function<void(const std::string&)> onOutput;
    std::function<void(const std::string&)> onError;
    std::function<void()> onStarted;
    std::function<void(int)> onFinished;

  private:
    void readOutputThread();
    void readErrorThread();
    void monitorProcessThread();
    /// After natural exit, threads are done but handles may still be open — release before a new start().
    void resetStaleStateFromExitedProcess();

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
    ShellType m_shellType;
    std::mutex m_stdinWriteMutex;
};
