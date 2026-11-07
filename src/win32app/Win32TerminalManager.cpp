#include "Win32TerminalManager.h"
#include <windows.h>
#include <cstring>
#include <iostream>
#include <vector>

namespace {

std::string base64Encode(const unsigned char* data, size_t size)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((size + 2) / 3) * 4);
    for (size_t i = 0; i < size; i += 3) {
        const unsigned int a = data[i];
        const unsigned int b = (i + 1 < size) ? data[i + 1] : 0;
        const unsigned int c = (i + 2 < size) ? data[i + 2] : 0;
        const unsigned int block = (a << 16) | (b << 8) | c;
        encoded.push_back(alphabet[(block >> 18) & 0x3f]);
        encoded.push_back(alphabet[(block >> 12) & 0x3f]);
        encoded.push_back(i + 1 < size ? alphabet[(block >> 6) & 0x3f] : '=');
        encoded.push_back(i + 2 < size ? alphabet[block & 0x3f] : '=');
    }
    return encoded;
}

std::string encodeUtf8AsPowerShellCommand(const char* script)
{
    if (!script || !*script) return {};
    const int sourceLength = static_cast<int>(std::strlen(script));
    int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         script, sourceLength, nullptr, 0);
    if (wideLength <= 0) {
        wideLength = MultiByteToWideChar(CP_ACP, 0, script, sourceLength,
                                         nullptr, 0);
        if (wideLength <= 0) return {};
    }
    std::vector<wchar_t> wide(static_cast<size_t>(wideLength));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, script, sourceLength,
                            wide.data(), wideLength) <= 0) {
        if (MultiByteToWideChar(CP_ACP, 0, script, sourceLength,
                                wide.data(), wideLength) <= 0) return {};
    }
    // Windows PowerShell expects UTF-16LE bytes for -EncodedCommand.
    return base64Encode(reinterpret_cast<const unsigned char*>(wide.data()),
                        wide.size() * sizeof(wchar_t));
}

} // namespace

// === PS_TRACE: Runtime-local logging for PowerShell execution tracing ===
static inline void PsTrace(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    const char* configuredLogDir = std::getenv("RAWRXD_LOG_DIR");
    const std::string logPath = (configuredLogDir && *configuredLogDir)
        ? std::string(configuredLogDir) + "\\ps_trace.log"
        : std::string("ps_trace.log");
    FILE* file = nullptr;
    if (fopen_s(&file, logPath.c_str(), "a") == 0 && file) {
        fprintf(file, "%lu %s\n", GetCurrentThreadId(), buf);
        fflush(file);
        fclose(file);
    }
    OutputDebugStringA(buf);
}

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
    if (m_running.load()) {
        PsTrace("[PS_TRACE] start() rejected: terminal process is already running\n");
        return false;
    }

    const auto currentThread = std::this_thread::get_id();
    if ((m_outputThread.joinable() && m_outputThread.get_id() == currentThread) ||
        (m_errorThread.joinable() && m_errorThread.get_id() == currentThread) ||
        (m_monitorThread.joinable() && m_monitorThread.get_id() == currentThread)) {
        PsTrace("[PS_TRACE] start() rejected from a terminal worker thread\n");
        return false;
    }

    // A process can exit asynchronously and leave its handles/reader threads
    // pending cleanup while m_running is already false.  Reap that state before
    // creating a new set of handles; otherwise assigning a new std::thread to
    // a still-joinable reader would terminate the process.
    stop();
    m_shellType = shell;

    // Create pipes for stdin, stdout, stderr
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&m_hStdOutRead, &m_hStdOutWrite, &sa, 0)) {
        std::cerr << "Failed to create stdout pipe" << std::endl;
        stop();
        return false;
    }
    if (!CreatePipe(&m_hStdErrRead, &m_hStdErrWrite, &sa, 0)) {
        std::cerr << "Failed to create stderr pipe" << std::endl;
        stop();
        return false;
    }
    if (!CreatePipe(&m_hStdInRead, &m_hStdInWrite, &sa, 0)) {
        std::cerr << "Failed to create stdin pipe" << std::endl;
        stop();
        return false;
    }

    // Child-side handles (m_hStdInRead, m_hStdOutWrite, m_hStdErrWrite) are
    // passed via STARTUPINFO and MUST remain inheritable.
    // Parent-side handles must NOT be inherited by the child.
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

    // Choose shell
    std::string cmd;
    if (shell == PowerShell) {
        // Keep one process alive with a line-oriented command pump.  Passing
        // the script through -Command with nested quotes is fragile under
        // CreateProcessA (PowerShell can receive literal backticks or a
        // truncated script).  -EncodedCommand is UTF-16LE and therefore
        // preserves the script exactly across Win32 command-line parsing.
        static constexpr char pumpScript[] =
            "$utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false; "
            "$OutputEncoding = $utf8; [Console]::OutputEncoding = $utf8; "
            "while(($line = [Console]::In.ReadLine()) -ne $null) { "
            "if($line -eq '__RAWRXD_EXIT__') { break }; "
            "try { Invoke-Expression -Command $line 2>&1 | "
            "ForEach-Object { [Console]::Out.WriteLine($_.ToString()); [Console]::Out.Flush() } } "
            "catch { [Console]::Error.WriteLine($_.Exception.ToString()); [Console]::Error.Flush() } }";
        const std::string encoded = encodeUtf8AsPowerShellCommand(pumpScript);
        if (encoded.empty()) {
            std::cerr << "Failed to encode PowerShell command pump" << std::endl;
            stop();
            return false;
        }
        PsTrace("[PS_TRACE] start() encoded command length=%zu\n", encoded.length());
        cmd = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded;
        PsTrace("[PS_TRACE] start() cmd=%.200s...\n", cmd.c_str());
    } else {
        cmd = "cmd.exe";
    }

    // Create the process
    if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr,
                       TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        PsTrace("[PS_TRACE] CreateProcessA FAILED GetLastError=%lu\n", GetLastError());
        stop();
        return false;
    }
    PsTrace("[PS_TRACE] CreateProcessA SUCCESS pid=%lu\n", pi.dwProcessId);

    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_running = true;
    PsTrace("[PS_TRACE] Process started, starting output threads\n");

    // Close unnecessary handles
    CloseHandle(m_hStdOutWrite); m_hStdOutWrite = nullptr;
    CloseHandle(m_hStdErrWrite); m_hStdErrWrite = nullptr;
    CloseHandle(m_hStdInRead); m_hStdInRead = nullptr;

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
    // The monitor thread can observe process exit and clear m_running before
    // destruction.  Join every started thread regardless of that flag, or a
    // finished terminal leaves joinable std::threads and terminates the IDE.
    m_running = false;
    if (m_hProcess) {
        DWORD exitCode = STILL_ACTIVE;
        if (GetExitCodeProcess(m_hProcess, &exitCode) &&
            exitCode == STILL_ACTIVE) {
            TerminateProcess(m_hProcess, 0);
        }
        WaitForSingleObject(m_hProcess, 5000);
    }

    if (m_outputThread.joinable()) m_outputThread.join();
    if (m_errorThread.joinable()) m_errorThread.join();
    if (m_monitorThread.joinable()) m_monitorThread.join();

    if (m_hProcess) CloseHandle(m_hProcess); m_hProcess = nullptr;
    if (m_hThread) CloseHandle(m_hThread); m_hThread = nullptr;
    if (m_hStdInWrite) { CloseHandle(m_hStdInWrite); m_hStdInWrite = nullptr; }
    if (m_hStdInRead) { CloseHandle(m_hStdInRead); m_hStdInRead = nullptr; }
    if (m_hStdOutRead) { CloseHandle(m_hStdOutRead); m_hStdOutRead = nullptr; }
    if (m_hStdOutWrite) { CloseHandle(m_hStdOutWrite); m_hStdOutWrite = nullptr; }
    if (m_hStdErrRead) { CloseHandle(m_hStdErrRead); m_hStdErrRead = nullptr; }
    if (m_hStdErrWrite) { CloseHandle(m_hStdErrWrite); m_hStdErrWrite = nullptr; }

    m_hProcess = nullptr;
    m_hThread = nullptr;
    m_hStdInWrite = nullptr;
    m_hStdOutRead = nullptr;
    m_hStdErrRead = nullptr;
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
    if (!m_running || !m_hStdInWrite || m_hStdInWrite == INVALID_HANDLE_VALUE) {
        PsTrace("[PS_TRACE] writeInput() early exit: m_running=%d m_hStdInWrite=%p\n", m_running ? 1 : 0, m_hStdInWrite);
        return;
    }

    std::string framed = data;
    if (framed.empty() || framed.back() != '\n') framed += "\r\n";
    DWORD written = 0;
    BOOL ok = WriteFile(m_hStdInWrite, framed.data(), (DWORD)framed.size(), &written, nullptr);
    DWORD err = GetLastError();
    PsTrace("[PS_TRACE] writeInput() WriteFile ok=%d written=%lu GetLastError=%lu framed_len=%zu\n", ok ? 1 : 0, written, err, framed.size());
}

void Win32TerminalManager::readOutputThread()
{
    char buffer[4096];
    DWORD bytesRead;

    PsTrace("[PS_TRACE] readOutputThread() STARTED thread=%lu\n", GetCurrentThreadId());

    while (m_running) {
        BOOL ok = ReadFile(m_hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        DWORD err = GetLastError();
        if (ok && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            PsTrace("[PS_TRACE] readOutputThread() read %lu bytes thread=%lu\n", bytesRead, GetCurrentThreadId());
            if (onOutput) {
                PsTrace("[PS_TRACE] readOutputThread() calling onOutput() bytes=%lu\n", bytesRead);
                onOutput(std::string(buffer, bytesRead));
            }
        } else {
            PsTrace("[PS_TRACE] readOutputThread() ReadFile ok=%d bytesRead=%lu GetLastError=%lu %s\n", ok ? 1 : 0, bytesRead, err, (err == 109 ? "EOF/broken pipe" : "ERROR"));
            break;
        }
    }
    PsTrace("[PS_TRACE] readOutputThread() EXITING\n");
}

void Win32TerminalManager::readErrorThread()
{
    char buffer[4096];
    DWORD bytesRead;
    std::string pending;

    // Windows PowerShell can emit a one-time startup progress record as
    // CLIXML on stderr ("Preparing modules for first use.").  It is not a
    // command failure and should not be rendered as an IDE error.  Keep the
    // filtering at the pipe boundary so real stderr, including later
    // CLIXML errors, remains visible to the UI.
    auto emitErrorLine = [this](std::string line) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line == "#< CLIXML") {
            return;
        }
        const bool startupProgress =
            line.find("S=\"progress\"") != std::string::npos &&
            line.find("Preparing modules for first use.") != std::string::npos;
        if (startupProgress) {
            return;
        }
        if (onError && !line.empty()) {
            PsTrace("[PS_TRACE] readErrorThread() onError line='%s'\n", line.c_str());
            onError(line + "\n");
        }
    };

    while (m_running) {
        BOOL ok = ReadFile(m_hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        DWORD err = GetLastError();
        if (ok && bytesRead > 0) {
            pending.append(buffer, bytesRead);
            size_t newline = std::string::npos;
            while ((newline = pending.find('\n')) != std::string::npos) {
                emitErrorLine(pending.substr(0, newline));
                pending.erase(0, newline + 1);
            }
        } else {
            PsTrace("[PS_TRACE] readErrorThread() ReadFile ok=%d bytesRead=%lu GetLastError=%lu %s\n", ok ? 1 : 0, bytesRead, err, (err == 109 ? "EOF/broken pipe" : "ERROR"));
            break;
        }
    }
    PsTrace("[PS_TRACE] readErrorThread() EXITING\n");

    if (!pending.empty()) {
        emitErrorLine(std::move(pending));
    }
}

void Win32TerminalManager::monitorProcessThread()
{
    PsTrace("[PS_TRACE] monitorProcessThread() STARTED thread=%lu\n", GetCurrentThreadId());
    WaitForSingleObject(m_hProcess, INFINITE);
    m_running = false;

    DWORD exitCode;
    GetExitCodeProcess(m_hProcess, &exitCode);
    PsTrace("[PS_TRACE] monitorProcessThread() process exited code=%lu\n", exitCode);

    if (onFinished) {
        PsTrace("[PS_TRACE] monitorProcessThread() calling onFinished() exitCode=%lu\n", exitCode);
        onFinished(exitCode);
    }
    PsTrace("[PS_TRACE] monitorProcessThread() EXITING\n");
}
