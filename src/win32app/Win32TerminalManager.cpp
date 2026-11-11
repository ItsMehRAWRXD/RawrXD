#include "Win32TerminalManager.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

namespace {

using CreatePseudoConsole_fn = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, void**);
using ClosePseudoConsole_fn = void(WINAPI*)(void*);
using ResizePseudoConsole_fn = HRESULT(WINAPI*)(void*, COORD);

CreatePseudoConsole_fn DynCreatePseudoConsole() {
    static auto fn = reinterpret_cast<CreatePseudoConsole_fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreatePseudoConsole"));
    return fn;
}
ClosePseudoConsole_fn DynClosePseudoConsole() {
    static auto fn = reinterpret_cast<ClosePseudoConsole_fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ClosePseudoConsole"));
    return fn;
}
ResizePseudoConsole_fn DynResizePseudoConsole() {
    static auto fn = reinterpret_cast<ResizePseudoConsole_fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ResizePseudoConsole"));
    return fn;
}

void traceLine(const std::string& line) {
    std::ofstream trace("F:\\rawrxd\\terminal_start_trace.log", std::ios::app);
    if (trace) trace << line << '\n';
}

std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

}  // namespace

Win32TerminalManager::Win32TerminalManager()
    : m_hProcess(nullptr), m_hThread(nullptr), m_processId(0),
      m_hStdInRead(nullptr), m_hStdInWrite(nullptr),
      m_hStdOutRead(nullptr), m_hStdOutWrite(nullptr),
      m_hStdErrRead(nullptr), m_hStdErrWrite(nullptr),
      m_hPC(nullptr), m_transport(TransportNone),
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

bool Win32TerminalManager::startNonInteractive(ShellType shell)
{
    stop();
    m_shellType = shell;
    m_stdoutBytes.store(0);
    m_stderrBytes.store(0);
    m_transport = TransportNone;
    m_boundedWaitMs = 0; // persistent panel pump; not fixture-bounded
    traceLine("startNonInteractive: forcing pipe transport");
    return startPipe(shell, {});
}

bool Win32TerminalManager::startCommandLine(ShellType shell,
                                             const std::string& commandLine)
{
    stop();
    m_shellType = shell;
    m_stdoutBytes.store(0);
    m_stderrBytes.store(0);
    m_transport = TransportNone;
    m_boundedWaitMs = 0;

    // One-shot MSVC fixture compiles hang under ConPTY after the /nologo
    // filename line; pipe transport delivers full diagnostics to Problems.
    char forcePipe[8] = {};
    const DWORD forceLen =
        GetEnvironmentVariableA("RAWRXD_TERMINAL_FORCE_PIPE", forcePipe,
                                static_cast<DWORD>(sizeof(forcePipe)));
    if (forceLen > 0 && forcePipe[0] == '1') {
        m_boundedWaitMs = 120000; // fixture/compile must not hang forever
        traceLine("FORCE_PIPE=1; skipping ConPTY bounded_ms=120000");
        return startPipe(shell, commandLine);
    }

    // Prefer ConPTY for interactive fidelity; fall back to redirected pipes.
    if (startConPTY(shell, commandLine)) {
        return true;
    }
    traceLine("ConPTY start failed; falling back to pipe transport");
    return startPipe(shell, commandLine);
}

bool Win32TerminalManager::startConPTY(ShellType shell,
                                        const std::string& commandLine)
{
    auto createPC = DynCreatePseudoConsole();
    auto closePC = DynClosePseudoConsole();
    if (!createPC || !closePC) {
        traceLine("ConPTY APIs absent");
        return false;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE inputRead = nullptr, inputWrite = nullptr;
    HANDLE outputRead = nullptr, outputWrite = nullptr;
    if (!CreatePipe(&inputRead, &inputWrite, &sa, 0) ||
        !CreatePipe(&outputRead, &outputWrite, &sa, 0)) {
        return false;
    }
    SetHandleInformation(inputWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(outputRead, HANDLE_FLAG_INHERIT, 0);

    COORD size{120, 30};
    void* hPC = nullptr;
    HRESULT hr = createPC(size, inputRead, outputWrite, 0, &hPC);
    if (FAILED(hr) || !hPC) {
        CloseHandle(inputRead);
        CloseHandle(outputWrite);
        CloseHandle(inputWrite);
        CloseHandle(outputRead);
        traceLine("CreatePseudoConsole failed");
        return false;
    }

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<uint8_t> attrBuf(attrSize);
    auto* attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        closePC(hPC);
        CloseHandle(inputRead);
        CloseHandle(outputWrite);
        CloseHandle(inputWrite);
        CloseHandle(outputRead);
        return false;
    }
    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   hPC, sizeof(hPC), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrList);
        closePC(hPC);
        CloseHandle(inputRead);
        CloseHandle(outputWrite);
        CloseHandle(inputWrite);
        CloseHandle(outputRead);
        return false;
    }

    std::string cmd;
    if (!commandLine.empty()) {
        cmd = commandLine;
    } else if (shell == PowerShell) {
        // Interactive host under ConPTY (not -Command - pipe mode). -NoExit keeps host alive.
        cmd = "powershell.exe -NoExit -NoLogo -NoProfile -ExecutionPolicy Bypass";
    } else {
        cmd = "cmd.exe /K";
    }

    STARTUPINFOEXW siex{};
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrList;
    // OS 26300: clear STD handles so child cannot attach parent console.
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    siex.StartupInfo.hStdInput = nullptr;
    siex.StartupInfo.hStdOutput = nullptr;
    siex.StartupInfo.hStdError = nullptr;

    PROCESS_INFORMATION pi{};
    std::wstring wide = toWide(cmd);
    std::vector<wchar_t> mutableCmd(wide.begin(), wide.end());
    mutableCmd.push_back(L'\0');

    // CREATE_SUSPENDED: close PTY-side pipe ends before ResumeThread (OS 26300).
    const BOOL created = CreateProcessW(
        nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
        nullptr, nullptr, &siex.StartupInfo, &pi);

    DeleteProcThreadAttributeList(attrList);
    CloseHandle(inputRead);
    CloseHandle(outputWrite);
    inputRead = nullptr;
    outputWrite = nullptr;

    if (!created) {
        closePC(hPC);
        CloseHandle(inputWrite);
        CloseHandle(outputRead);
        const DWORD error = GetLastError();
        std::ofstream errLog("F:\\rawrxd\\terminal_start_errors.log", std::ios::app);
        if (errLog) errLog << "ConPTY CreateProcess error=" << error
                           << " command=" << cmd << '\n';
        return false;
    }

    m_hPC = hPC;
    m_transport = TransportConPTY;
    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_running = true;
    m_hStdInWrite = inputWrite;   // host → ConPTY input
    m_hStdOutRead = outputRead;   // ConPTY output → host
    m_hStdErrRead = nullptr;      // ConPTY merges stderr into output stream
    m_hStdInRead = nullptr;
    m_hStdOutWrite = nullptr;
    m_hStdErrWrite = nullptr;

    traceLine(std::string("ConPTY start ok pid=") + std::to_string(m_processId) +
              " cmd=" + cmd + " os26300_capture=1");

    m_outputThread = std::thread(&Win32TerminalManager::readOutputThread, this);
    m_monitorThread = std::thread(&Win32TerminalManager::monitorProcessThread, this);
    ResumeThread(pi.hThread);

    if (onStarted) onStarted();
    return true;
}

bool Win32TerminalManager::startPipe(ShellType shell,
                                      const std::string& commandLine)
{
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

    SetHandleInformation(m_hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdErrRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m_hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = m_hStdInRead;
    si.hStdOutput = m_hStdOutWrite;
    si.hStdError = m_hStdErrWrite;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::string cmd;
    if (!commandLine.empty()) {
        cmd = commandLine;
    } else if (shell == PowerShell) {
        cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command -";
    } else {
        cmd = "cmd.exe";
    }

    traceLine(std::string("PIPE start cmd=") + cmd);
    std::wstring wideCommand(cmd.begin(), cmd.end());
    std::vector<wchar_t> mutablePipeCmd(wideCommand.begin(), wideCommand.end());
    mutablePipeCmd.push_back(L'\0');
    if (!CreateProcessW(nullptr, mutablePipeCmd.data(), nullptr, nullptr,
                       TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        const DWORD error = GetLastError();
        std::ofstream errLog("F:\\rawrxd\\terminal_start_errors.log", std::ios::app);
        if (errLog) errLog << "CreateProcess error=" << error << " command=" << cmd << '\n';
        std::cerr << "Failed to create process: " << error << std::endl;
        stop();
        return false;
    }

    m_transport = TransportPipe;
    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_running = true;

    CloseHandle(m_hStdOutWrite);
    CloseHandle(m_hStdErrWrite);
    CloseHandle(m_hStdInRead);
    m_hStdOutWrite = nullptr;
    m_hStdErrWrite = nullptr;
    m_hStdInRead = nullptr;

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
    m_running = false;

    // Unblock ReadFile joiners BEFORE waiting on threads (ConPTY/pipe hang fix).
    if (m_hStdInWrite) { CloseHandle(m_hStdInWrite); m_hStdInWrite = nullptr; }
    if (m_hStdOutRead) { CloseHandle(m_hStdOutRead); m_hStdOutRead = nullptr; }
    if (m_hStdErrRead) { CloseHandle(m_hStdErrRead); m_hStdErrRead = nullptr; }
    if (m_hStdInRead) { CloseHandle(m_hStdInRead); m_hStdInRead = nullptr; }
    if (m_hStdOutWrite) { CloseHandle(m_hStdOutWrite); m_hStdOutWrite = nullptr; }
    if (m_hStdErrWrite) { CloseHandle(m_hStdErrWrite); m_hStdErrWrite = nullptr; }

    if (m_hPC) {
        if (auto closePC = DynClosePseudoConsole()) {
            closePC(m_hPC);
        }
        m_hPC = nullptr;
    }

    if (m_hProcess) {
        TerminateProcess(m_hProcess, 0);
        WaitForSingleObject(m_hProcess, 3000);
    }

    // Join only after pipes/PC closed so ReadFile returns. Do not detach:
    // detach+UAF caused term-smoke EXIT=-1 mid-stop.
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
    m_transport = TransportNone;
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

void Win32TerminalManager::resize(short cols, short rows)
{
    if (m_transport != TransportConPTY || !m_hPC) return;
    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;
    auto resizePC = DynResizePseudoConsole();
    if (!resizePC) return;
    COORD size{cols, rows};
    resizePC(m_hPC, size);
    traceLine(std::string("ConPTY resize cols=") + std::to_string(cols) +
              " rows=" + std::to_string(rows));
}

bool Win32TerminalManager::interrupt()
{
    if (!m_running) return false;
    if (m_transport == TransportConPTY && m_hStdInWrite) {
        const char ctrlC = '\x03';
        DWORD written = 0;
        if (WriteFile(m_hStdInWrite, &ctrlC, 1, &written, nullptr) && written == 1) {
            traceLine("ConPTY interrupt Ctrl+C written");
            return true;
        }
    }
    if (m_hProcess) {
        const BOOL ok = TerminateProcess(m_hProcess, 1);
        traceLine(ok ? "interrupt TerminateProcess ok" : "interrupt TerminateProcess fail");
        return ok != 0;
    }
    return false;
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
    // Drain to EOF. Do NOT gate on m_running — process exit flips that flag
    // before remaining pipe bytes are consumed (FIXTURE_START-only symptom).
    char buffer[4096];
    DWORD bytesRead = 0;
    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buffer) - 1);
    HANDLE h = m_hStdOutRead;
    while (h) {
        if (!ReadFile(h, buffer, kMaxChunk, &bytesRead, nullptr) || bytesRead == 0) {
            break;
        }
        m_stdoutBytes.fetch_add(bytesRead, std::memory_order_relaxed);
        if (onOutput) {
            onOutput(std::string(buffer, bytesRead));
        }
    }
}

void Win32TerminalManager::readErrorThread()
{
    if (!m_hStdErrRead) return;
    char buffer[4096];
    DWORD bytesRead;
    HANDLE h = m_hStdErrRead;
    while (h) {
        if (!ReadFile(h, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) ||
            bytesRead == 0) {
            break;
        }
        m_stderrBytes.fetch_add(bytesRead, std::memory_order_relaxed);
        if (onError) {
            onError(std::string(buffer, bytesRead));
        }
    }
}

void Win32TerminalManager::monitorProcessThread()
{
    // Interactive terminals: infinite. Fixture FORCE_PIPE: bounded (cl hang).
    const DWORD waitMs = m_boundedWaitMs ? m_boundedWaitMs : INFINITE;
    const DWORD waitRc = WaitForSingleObject(m_hProcess, waitMs);
    std::string disposition = "success";
    if (waitRc == WAIT_TIMEOUT) {
        disposition = "timeout";
        TerminateProcess(m_hProcess, 259);
        WaitForSingleObject(m_hProcess, 5000);
    } else if (waitRc != WAIT_OBJECT_0) {
        disposition = "failure";
    }

    // Child exit (or TerminateProcess on timeout) closes pipe ends → readers
    // observe EOF on blocking ReadFile. closeInput unblocks any stdin waiters.
    closeInput();
    m_running = false;

    // Brief settle so drain threads can deliver final STDOUT/STDERR callbacks
    // before Finished (Problems insert runs on UI thread via PostMessage).
    Sleep(50);

    DWORD exitCode = 0;
    GetExitCodeProcess(m_hProcess, &exitCode);
    if (disposition == "timeout") {
        exitCode = 259;
    }
    m_lastExitCode.store(static_cast<int>(exitCode), std::memory_order_relaxed);

    {
        std::ofstream trace("F:\\rawrxd\\terminal_start_trace.log", std::ios::app);
        if (trace) {
            trace << "finished pid=" << m_processId << " exit=" << exitCode
                  << " disposition=" << disposition
                  << " transport=" << static_cast<int>(m_transport)
                  << " stdout_bytes=" << m_stdoutBytes.load()
                  << " stderr_bytes=" << m_stderrBytes.load() << '\n';
        }
        std::ofstream receipt(
            "F:\\rawrxd\\evidence\\FULL_FEATURE_FINAL_COMPLETION_001\\artifacts\\"
            "COMPILER_CAPTURE_RECEIPT.txt",
            std::ios::app);
        if (receipt) {
            receipt << "PROCESS_EXIT pid=" << m_processId
                    << " exit=" << exitCode
                    << " disposition=" << disposition
                    << " transport=" << static_cast<int>(m_transport)
                    << " stdout_bytes=" << m_stdoutBytes.load()
                    << " stderr_bytes=" << m_stderrBytes.load() << '\n'
                    << "BUILD_RESULT=" << disposition << '\n';
        }
    }

    if (onFinished) {
        onFinished(static_cast<int>(exitCode));
    }
}
