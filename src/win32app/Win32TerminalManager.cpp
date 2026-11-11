#include "Win32TerminalManager.h"
#include <iostream>
#include <fstream>
#include <vector>

Win32TerminalManager::Win32TerminalManager()
    : m_hProcess(nullptr), m_hThread(nullptr), m_processId(0),
      m_hStdInRead(nullptr), m_hStdInWrite(nullptr),
      m_hStdOutRead(nullptr), m_hStdOutWrite(nullptr),
      m_hStdErrRead(nullptr), m_hStdErrWrite(nullptr),
      m_running(false)
{
}

Win32TerminalManager::~Win32TerminalManager()
{
    stop();
}

bool Win32TerminalManager::start(ShellType shell)
{
    return startCommandLine(shell, {});
}

bool Win32TerminalManager::startCommandLine(ShellType shell,
                                             const std::string& commandLine)
{
    // A shell may have exited naturally.  Reap its worker threads and handles
    // before replacing them; assigning to a joinable std::thread terminates.
    stop();
    m_shellType = shell;
    m_stdoutBytes.store(0);
    m_stderrBytes.store(0);

    // Create pipes for stdin, stdout, stderr
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&m_hStdOutRead, &m_hStdOutWrite, &sa, 0) ||
        !CreatePipe(&m_hStdErrRead, &m_hStdErrWrite, &sa, 0) ||
        !CreatePipe(&m_hStdInRead, &m_hStdInWrite, &sa, 0)) {
        std::cerr << "Failed to create pipes" << std::endl;
        stop();
        return false;
    }

    // The child inherits stdin-read and stdout/stderr-write.  Keep the
    // parent's opposite ends private; clearing the output write handles here
    // would leave the child with invalid stdout/stderr and silently lose all
    // captured output.
    SetHandleInformation(m_hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdErrRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    // Set up process startup info
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = m_hStdInRead;
    si.hStdOutput = m_hStdOutWrite;
    si.hStdError = m_hStdErrWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Choose shell
    std::string cmd;
    if (!commandLine.empty()) {
        cmd = commandLine;
    } else if (shell == PowerShell) {
        // Keep the established command-stream host for the stable terminal
        // startup path.  Build completion remains gated on a live receipt;
        // this avoids promoting the experimental line-pump process until it
        // has its own runtime regression test.
        cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command -";
    } else {
        cmd = "cmd.exe";
    }

    // Create the process
    {
        std::ofstream trace("F:\\rawrxd\\terminal_start_trace.log", std::ios::app);
        if (trace) trace << cmd << '\n';
    }
    std::wstring wideCommand(cmd.begin(), cmd.end());
    if (!CreateProcessW(nullptr, wideCommand.data(), nullptr, nullptr,
                       TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        const DWORD error = GetLastError();
        std::ofstream trace("F:\\rawrxd\\terminal_start_errors.log", std::ios::app);
        if (trace) trace << "CreateProcess error=" << error << " command=" << cmd << '\n';
        std::cerr << "Failed to create process: " << error << std::endl;
        stop();
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
    m_hStdOutWrite = nullptr;
    m_hStdErrWrite = nullptr;
    m_hStdInRead = nullptr;

    // Start threads to read output
    m_outputThread = std::thread(&Win32TerminalManager::readOutputThread, this);
    m_errorThread = std::thread(&Win32TerminalManager::readErrorThread, this);
    m_monitorThread = std::thread(&Win32TerminalManager::monitorProcessThread, this);

    if (onStarted) {
        onStarted();
    }

    return true;
}

void Win32TerminalManager::stop()
{
    // stop() is also the reaper for a process that exited on its own.
    // Always join/close any existing resources, even when m_running is false.
    if (m_hProcess) {
        if (m_running) {
            m_running = false;
            TerminateProcess(m_hProcess, 0);
        }
        m_running = false;
        WaitForSingleObject(m_hProcess, INFINITE);
    }

    if (m_outputThread.joinable() &&
        m_outputThread.get_id() != std::this_thread::get_id()) m_outputThread.join();
    if (m_errorThread.joinable() &&
        m_errorThread.get_id() != std::this_thread::get_id()) m_errorThread.join();
    if (m_monitorThread.joinable() &&
        m_monitorThread.get_id() != std::this_thread::get_id()) m_monitorThread.join();

    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    if (m_hThread) {
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    if (m_hStdInRead) { CloseHandle(m_hStdInRead); m_hStdInRead = nullptr; }
    if (m_hStdInWrite) { CloseHandle(m_hStdInWrite); m_hStdInWrite = nullptr; }
    if (m_hStdOutRead) { CloseHandle(m_hStdOutRead); m_hStdOutRead = nullptr; }
    if (m_hStdOutWrite) { CloseHandle(m_hStdOutWrite); m_hStdOutWrite = nullptr; }
    if (m_hStdErrRead) { CloseHandle(m_hStdErrRead); m_hStdErrRead = nullptr; }
    if (m_hStdErrWrite) { CloseHandle(m_hStdErrWrite); m_hStdErrWrite = nullptr; }
    m_processId = 0;
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
    if (!m_running || !m_hStdInWrite) return;

    DWORD written = 0;
    if (!WriteFile(m_hStdInWrite, data.c_str(), static_cast<DWORD>(data.size()),
                   &written, nullptr)) {
        const DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
            m_running = false;
        }
    }
}

void Win32TerminalManager::closeInput()
{
    HANDLE input = m_hStdInWrite;
    m_hStdInWrite = nullptr;
    if (input) {
        FlushFileBuffers(input);
        CloseHandle(input);
    }
}

void Win32TerminalManager::readOutputThread()
{
    char buffer[4096];
    DWORD bytesRead;

    // Drain until the pipe reaches EOF.  The monitor thread may mark the
    // process stopped before the final buffered bytes are read.
    while (true) {
        if (ReadFile(m_hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            m_stdoutBytes.fetch_add(bytesRead, std::memory_order_relaxed);
            if (onOutput) {
                onOutput(std::string(buffer, bytesRead));
            }
        } else {
            break;
        }
    }
}

void Win32TerminalManager::readErrorThread()
{
    char buffer[4096];
    DWORD bytesRead;

    // Drain until EOF independently of process state so short-lived commands
    // cannot lose their final stdout/stderr chunk.
    while (true) {
        if (ReadFile(m_hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            m_stderrBytes.fetch_add(bytesRead, std::memory_order_relaxed);
            if (onError) {
                onError(std::string(buffer, bytesRead));
            }
        } else {
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
    {
        std::ofstream trace("F:\\rawrxd\\terminal_start_trace.log", std::ios::app);
        if (trace) trace << "finished pid=" << m_processId << " exit=" << exitCode
                         << " stdout_bytes=" << m_stdoutBytes.load()
                         << " stderr_bytes=" << m_stderrBytes.load() << '\n';
    }

    if (onFinished) {
        onFinished(exitCode);
    }
}
