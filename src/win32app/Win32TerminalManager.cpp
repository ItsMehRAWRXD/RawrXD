#include "Win32TerminalManager.h"
#include <iostream>
#include <string>
#include <vector>

Win32TerminalManager::Win32TerminalManager()
    : m_hProcess(nullptr), m_hThread(nullptr), m_processId(0), m_hStdInRead(nullptr), m_hStdInWrite(nullptr),
      m_hStdOutRead(nullptr), m_hStdOutWrite(nullptr), m_hStdErrRead(nullptr), m_hStdErrWrite(nullptr), m_running(false)
{
}

Win32TerminalManager::~Win32TerminalManager()
{
    stop();
}

void Win32TerminalManager::resetStaleStateFromExitedProcess()
{
    if (!m_hProcess && !m_outputThread.joinable() && !m_errorThread.joinable() && !m_monitorThread.joinable())
        return;

    m_running = false;

    if (m_outputThread.joinable())
        m_outputThread.join();
    if (m_errorThread.joinable())
        m_errorThread.join();
    if (m_monitorThread.joinable())
        m_monitorThread.join();

    if (m_hProcess)
    {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    if (m_hThread)
    {
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    if (m_hStdInWrite)
    {
        CloseHandle(m_hStdInWrite);
        m_hStdInWrite = nullptr;
    }
    if (m_hStdOutRead)
    {
        CloseHandle(m_hStdOutRead);
        m_hStdOutRead = nullptr;
    }
    if (m_hStdErrRead)
    {
        CloseHandle(m_hStdErrRead);
        m_hStdErrRead = nullptr;
    }
}

bool Win32TerminalManager::start(ShellType shell, const char* workingDirectoryUtf8)
{
    if (m_running)
        return false;
    resetStaleStateFromExitedProcess();

    m_shellType = shell;

    // Create pipes for stdin, stdout, stderr
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&m_hStdOutRead, &m_hStdOutWrite, &sa, 0) || !CreatePipe(&m_hStdErrRead, &m_hStdErrWrite, &sa, 0) ||
        !CreatePipe(&m_hStdInRead, &m_hStdInWrite, &sa, 0))
    {
        std::cerr << "Failed to create pipes" << std::endl;
        return false;
    }

    // Ensure the PARENT's pipe ends are NOT inherited by the child process.
    // The child inherits: m_hStdInRead (its stdin), m_hStdOutWrite (its stdout), m_hStdErrWrite (its stderr)
    // The parent keeps: m_hStdInWrite (write to child), m_hStdOutRead (read child out), m_hStdErrRead (read child err)
    SetHandleInformation(m_hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdErrRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    // Set up process startup info
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = m_hStdInRead;
    si.hStdOutput = m_hStdOutWrite;
    si.hStdError = m_hStdErrWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Choose shell — try pwsh (PS7) first, fall back to powershell.exe (PS5)
    std::string cmd;
    if (shell == PowerShell)
    {
        // -NoExit keeps session alive, -NoLogo suppresses banner
        // -ExecutionPolicy Bypass prevents script restrictions
        // Try pwsh.exe first (PowerShell 7), fall back to powershell.exe
        char pwshPath[MAX_PATH];
        // Prompt hook: emit RAWRXD_CWD|<path>|END on each prompt so the IDE status bar tracks `cd` (stripped before
        // display).
        const char* psTail = " -Command \"function global:prompt { $p=(Get-Location).ProviderPath; "
                             "[Console]::Out.WriteLine(('RAWRXD_CWD|' + $p + '|END')); return ('PS ' + $p + '> ') }\"";
        if (SearchPathA(nullptr, "pwsh.exe", nullptr, MAX_PATH, pwshPath, nullptr))
        {
            cmd = std::string("pwsh.exe -NoExit -NoLogo -NoProfile") + psTail;
        }
        else
        {
            cmd = std::string("powershell.exe -NoExit -NoLogo -NoProfile") + psTail;
        }
    }
    else
    {
        // CMD: strip RAWRXD_CWD|path|END in the IDE (same wire format as PowerShell). Use ^| so echo is not parsed as
        // a shell pipe. doskey macros ($T = "then") emit a line after cd/pushd/popd so the status bar tracks cwd.
        cmd = "cmd.exe /K \"doskey cd=cd $* $T echo RAWRXD_CWD^|%CD%^|END & "
              "doskey pushd=pushd $* $T echo RAWRXD_CWD^|%CD%^|END & "
              "doskey popd=popd $T echo RAWRXD_CWD^|%CD%^|END & "
              "echo RAWRXD_CWD^|%CD%^|END\"";
    }

    const char* lpCurrentDirectory = nullptr;
    char resolvedDir[1024];
    resolvedDir[0] = '\0';
    if (workingDirectoryUtf8 && workingDirectoryUtf8[0])
    {
        const DWORD n =
            GetFullPathNameA(workingDirectoryUtf8, static_cast<DWORD>(sizeof(resolvedDir)), resolvedDir, nullptr);
        if (n > 0 && n < sizeof(resolvedDir))
        {
            const DWORD attr = GetFileAttributesA(resolvedDir);
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                lpCurrentDirectory = resolvedDir;
        }
    }

    // Writable command line buffer — CreateProcess may modify the string
    std::vector<char> cmdLine(cmd.begin(), cmd.end());
    cmdLine.push_back('\0');

    // Create the process
    if (!CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, lpCurrentDirectory,
                        &si, &pi))
    {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        return false;
    }

    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_running = true;

    // Close unnecessary handles
    CloseHandle(m_hStdOutWrite);
    CloseHandle(m_hStdErrWrite);
    CloseHandle(m_hStdInRead);

    // Start threads to read output
    m_outputThread = std::thread(&Win32TerminalManager::readOutputThread, this);
    m_errorThread = std::thread(&Win32TerminalManager::readErrorThread, this);
    m_monitorThread = std::thread(&Win32TerminalManager::monitorProcessThread, this);

    if (onStarted)
    {
        onStarted();
    }

    return true;
}

void Win32TerminalManager::stop()
{
    if (m_running)
    {
        m_running = false;

        // Null callbacks BEFORE terminating process to prevent
        // output/error/monitor threads from calling into destroyed owners
        onOutput = nullptr;
        onError = nullptr;
        onStarted = nullptr;
        onFinished = nullptr;

        TerminateProcess(m_hProcess, 0);
        WaitForSingleObject(m_hProcess, 5000);  // 5s max instead of INFINITE

        if (m_outputThread.joinable())
            m_outputThread.join();
        if (m_errorThread.joinable())
            m_errorThread.join();
        if (m_monitorThread.joinable())
            m_monitorThread.join();

        CloseHandle(m_hProcess);
        CloseHandle(m_hThread);
        CloseHandle(m_hStdInWrite);
        CloseHandle(m_hStdOutRead);
        CloseHandle(m_hStdErrRead);

        m_hProcess = nullptr;
        m_hThread = nullptr;
    }
    else
    {
        // Process exited on its own; monitor cleared m_running but handles were never released.
        resetStaleStateFromExitedProcess();
    }
}

DWORD Win32TerminalManager::pid() const
{
    return m_processId;
}

bool Win32TerminalManager::isRunning() const
{
    return m_running;
}

void Win32TerminalManager::writeInput(const std::string& data)
{
    if (!m_running || !m_hStdInWrite)
        return;

    std::lock_guard<std::mutex> lock(m_stdinWriteMutex);
    DWORD written = 0;
    WriteFile(m_hStdInWrite, data.c_str(), static_cast<DWORD>(data.size()), &written, nullptr);
}

void Win32TerminalManager::readOutputThread()
{
    char buffer[4096];
    DWORD bytesRead = 0;
    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buffer) - 1);

    while (m_running)
    {
        if (ReadFile(m_hStdOutRead, buffer, kMaxChunk, &bytesRead, nullptr) && bytesRead > 0)
        {
            const size_t safeBytes =
                (bytesRead <= kMaxChunk) ? static_cast<size_t>(bytesRead) : static_cast<size_t>(kMaxChunk);
            buffer[safeBytes] = '\0';
            if (onOutput)
            {
                onOutput(std::string(buffer, safeBytes));
            }
        }
        else
        {
            break;
        }
    }
}

void Win32TerminalManager::readErrorThread()
{
    char buffer[4096];
    DWORD bytesRead = 0;
    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buffer) - 1);

    while (m_running)
    {
        if (ReadFile(m_hStdErrRead, buffer, kMaxChunk, &bytesRead, nullptr) && bytesRead > 0)
        {
            const size_t safeBytes =
                (bytesRead <= kMaxChunk) ? static_cast<size_t>(bytesRead) : static_cast<size_t>(kMaxChunk);
            buffer[safeBytes] = '\0';
            if (onError)
            {
                onError(std::string(buffer, safeBytes));
            }
        }
        else
        {
            break;
        }
    }
}

void Win32TerminalManager::monitorProcessThread()
{
    WaitForSingleObject(m_hProcess, INFINITE);
    m_running = false;

    DWORD exitCode;
    GetExitCodeProcess(m_hProcess, &exitCode);

    if (onFinished)
    {
        onFinished(exitCode);
    }
}
