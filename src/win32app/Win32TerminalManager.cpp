#include "Win32TerminalManager.h"
#include <cstdio>
#include <cstring>

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

using FnCreatePseudoConsole = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using FnClosePseudoConsole = VOID(WINAPI*)(HPCON);
using FnResizePseudoConsole = HRESULT(WINAPI*)(HPCON, COORD);

static FnCreatePseudoConsole g_CreatePseudoConsole = nullptr;
static FnClosePseudoConsole g_ClosePseudoConsole = nullptr;
static FnResizePseudoConsole g_ResizePseudoConsole = nullptr;
static bool g_ConPtyResolved = false;
static bool g_ConPtyPresent = false;

Win32TerminalManager::Win32TerminalManager()
    : m_hProcess(nullptr), m_hThread(nullptr), m_hJob(nullptr),
      m_processId(0), m_hPC(nullptr), m_hStdInWrite(nullptr),
      m_hStdOutRead(nullptr), m_running(false), m_cols(80), m_rows(25)
{
}

Win32TerminalManager::~Win32TerminalManager()
{
    stop();
}

void Win32TerminalManager::setWorkingDirectory(const std::wstring& cwd)
{
    m_workingDir = cwd;
}

bool Win32TerminalManager::ResolveConPtyApis()
{
    if (g_ConPtyResolved)
        return g_ConPtyPresent;
    g_ConPtyResolved = true;
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        return false;
    g_CreatePseudoConsole = reinterpret_cast<FnCreatePseudoConsole>(
        GetProcAddress(k32, "CreatePseudoConsole"));
    g_ClosePseudoConsole = reinterpret_cast<FnClosePseudoConsole>(
        GetProcAddress(k32, "ClosePseudoConsole"));
    g_ResizePseudoConsole = reinterpret_cast<FnResizePseudoConsole>(
        GetProcAddress(k32, "ResizePseudoConsole"));
    g_ConPtyPresent = (g_CreatePseudoConsole && g_ClosePseudoConsole);
    return g_ConPtyPresent;
}

void Win32TerminalManager::GateConPtyStream(const char* reason)
{
    char line[256];
    std::snprintf(line, sizeof(line),
                  "[CONPTY_STREAM_OWNER] GateConPty FAIL_CLOSED reason=%s "
                  "OWNER=Win32TerminalManager SYNTHETIC=0 NOT_PASS\n",
                  reason ? reason : "?");
    OutputDebugStringA(line);
    CreateDirectoryA("evidence", nullptr);
    CreateDirectoryA("evidence\\CONPTY_STREAM_OWNER_001", nullptr);
    FILE* f = nullptr;
    if (fopen_s(&f, "evidence\\CONPTY_STREAM_OWNER_001\\GATE_STREAM.txt",
                "wb") == 0 && f) {
        std::fprintf(f,
                     "GATE_STREAM\nFAIL_CLOSED=1\nREASON=%s\n"
                     "OWNER=Win32TerminalManager\n"
                     "API=CreatePseudoConsole\nPASS=0\nPROMOTE=0\n",
                     reason ? reason : "?");
        std::fclose(f);
    }
}

bool Win32TerminalManager::assignJobObject()
{
    if (m_hJob)
        return true;
    m_hJob = CreateJobObjectW(nullptr, nullptr);
    if (!m_hJob)
        return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(m_hJob, JobObjectExtendedLimitInformation,
                                 &info, sizeof(info))) {
        CloseHandle(m_hJob);
        m_hJob = nullptr;
        return false;
    }
    if (m_hProcess && !AssignProcessToJobObject(m_hJob, m_hProcess)) {
        DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED) {
            CloseHandle(m_hJob);
            m_hJob = nullptr;
            return false;
        }
    }
    return true;
}

bool Win32TerminalManager::start(ShellType shell)
{
    if (m_running)
        return true;
    m_shellType = shell;

    if (!ResolveConPtyApis()) {
        GateConPtyStream("CreatePseudoConsole_absent");
        return false;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hInConRead = nullptr;
    HANDLE hInOurWrite = nullptr;
    HANDLE hOutOurRead = nullptr;
    HANDLE hOutConWrite = nullptr;

    if (!CreatePipe(&hInConRead, &hInOurWrite, &sa, 0) ||
        !CreatePipe(&hOutOurRead, &hOutConWrite, &sa, 0)) {
        GateConPtyStream("create_pipe_failed");
        return false;
    }
    SetHandleInformation(hInOurWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutOurRead, HANDLE_FLAG_INHERIT, 0);

    COORD size = {m_cols, m_rows};
    HRESULT hr =
        g_CreatePseudoConsole(size, hInConRead, hOutConWrite, 0, &m_hPC);
    if (FAILED(hr) || !m_hPC) {
        GateConPtyStream("CreatePseudoConsole_failed");
        CloseHandle(hInConRead);
        CloseHandle(hInOurWrite);
        CloseHandle(hOutOurRead);
        CloseHandle(hOutConWrite);
        m_hPC = nullptr;
        return false;
    }

    SIZE_T attrBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrBytes);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attrBytes));
    // FOUR_PANEL: pass HPCON by value (MSDN sample) — &hPC failed capture on 26300
    if (!attrs ||
        !InitializeProcThreadAttributeList(attrs, 1, 0, &attrBytes) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   m_hPC, sizeof(m_hPC), nullptr, nullptr)) {
        GateConPtyStream("proc_thread_attr_failed");
        if (attrs) {
            DeleteProcThreadAttributeList(attrs);
            HeapFree(GetProcessHeap(), 0, attrs);
        }
        g_ClosePseudoConsole(m_hPC);
        m_hPC = nullptr;
        CloseHandle(hInConRead);
        CloseHandle(hInOurWrite);
        CloseHandle(hOutOurRead);
        CloseHandle(hOutConWrite);
        return false;
    }

    wchar_t cmd[MAX_PATH + 64];
    if (shell == PowerShell) {
        wchar_t pwsh[MAX_PATH];
        if (SearchPathW(nullptr, L"pwsh.exe", nullptr, MAX_PATH, pwsh, nullptr))
            wcscpy_s(cmd, L"pwsh.exe -NoExit -NoLogo -NoProfile");
        else
            wcscpy_s(cmd, L"powershell.exe -NoExit -NoLogo -NoProfile");
    } else {
        wcscpy_s(cmd, L"cmd.exe");
    }

    wchar_t cwdBuf[MAX_PATH];
    const wchar_t* cwdPtr = nullptr;
    if (!m_workingDir.empty()) {
        cwdPtr = m_workingDir.c_str();
    } else if (GetCurrentDirectoryW(MAX_PATH, cwdBuf)) {
        cwdPtr = cwdBuf;
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.lpAttributeList = attrs;
    // Critical on OS 26300: clear STD handles so child cannot attach parent console.
    // Do NOT claim interactive from redirected pipes — ConPTY remains the console.
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.StartupInfo.hStdInput = nullptr;
    si.StartupInfo.hStdOutput = nullptr;
    si.StartupInfo.hStdError = nullptr;

    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED: close PTY-side pipe ends before the child runs (winner matrix).
    BOOL ok = CreateProcessW(
        nullptr, cmd, nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
            CREATE_SUSPENDED,
        nullptr, cwdPtr, &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);

    // Close handles given to CreatePseudoConsole BEFORE ResumeThread
    CloseHandle(hInConRead);
    CloseHandle(hOutConWrite);
    hInConRead = nullptr;
    hOutConWrite = nullptr;

    if (!ok) {
        GateConPtyStream("CreateProcessW_failed");
        g_ClosePseudoConsole(m_hPC);
        m_hPC = nullptr;
        CloseHandle(hInOurWrite);
        CloseHandle(hOutOurRead);
        return false;
    }

    m_hProcess = pi.hProcess;
    m_hThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_hStdInWrite = hInOurWrite;
    m_hStdOutRead = hOutOurRead;
    m_running = true;
    assignJobObject();

    // Start reader before resume so we do not miss early output
    m_outputThread = std::thread(&Win32TerminalManager::readOutputThread, this);
    m_monitorThread =
        std::thread(&Win32TerminalManager::monitorProcessThread, this);

    ResumeThread(pi.hThread);

    if (onStarted)
        onStarted();
    return true;
}

void Win32TerminalManager::stop()
{
    if (!m_running && !m_hProcess && !m_hPC)
        return;

    // Fail-closed stop order (G05-05/G06-05): pipes then kill then join then ClosePseudoConsole.
    m_running = false;
    onOutput = nullptr;
    onError = nullptr;
    onStarted = nullptr;
    onFinished = nullptr;

    if (m_hStdInWrite) {
        CloseHandle(m_hStdInWrite);
        m_hStdInWrite = nullptr;
    }
    if (m_hStdOutRead) {
        CloseHandle(m_hStdOutRead);
        m_hStdOutRead = nullptr;
    }
    if (m_hJob) {
        CloseHandle(m_hJob);
        m_hJob = nullptr;
    }
    if (m_hProcess) {
        TerminateProcess(m_hProcess, 0);
        WaitForSingleObject(m_hProcess, 3000);
    }
    if (m_outputThread.joinable())
        m_outputThread.join();
    if (m_monitorThread.joinable())
        m_monitorThread.join();

    if (m_hPC && g_ClosePseudoConsole) {
        g_ClosePseudoConsole(m_hPC);
        m_hPC = nullptr;
    }
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    if (m_hThread) {
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    m_processId = 0;
}

bool Win32TerminalManager::resize(short cols, short rows)
{
    if (cols < 1 || rows < 1)
        return false;
    m_cols = cols;
    m_rows = rows;
    if (!m_hPC || !g_ResizePseudoConsole)
        return false;
    COORD size = {cols, rows};
    return SUCCEEDED(g_ResizePseudoConsole(m_hPC, size));
}

void Win32TerminalManager::interrupt()
{
    writeInput("\x03");
}

bool Win32TerminalManager::restart()
{
    ShellType shell = m_shellType;
    // Preserve callbacks across stop/start (stop clears them for dtor safety).
    auto out = onOutput;
    auto err = onError;
    auto started = onStarted;
    auto finished = onFinished;
    stop();
    onOutput = out;
    onError = err;
    onStarted = started;
    onFinished = finished;
    Sleep(200);
    return start(shell);
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
    DWORD written = 0;
    WriteFile(m_hStdInWrite, data.c_str(),
              static_cast<DWORD>(data.size()), &written, nullptr);
}

void Win32TerminalManager::readOutputThread()
{
    char buffer[4096];
    DWORD bytesRead = 0;
    constexpr DWORD kMaxChunk = static_cast<DWORD>(sizeof(buffer) - 1);
    while (m_running) {
        // Peek first so stop() can interrupt without indefinite block after close
        DWORD avail = 0;
        if (!PeekNamedPipe(m_hStdOutRead, nullptr, 0, nullptr, &avail, nullptr)) {
            // Fall back to blocking ReadFile when peek unsupported
            if (ReadFile(m_hStdOutRead, buffer, kMaxChunk, &bytesRead, nullptr) &&
                bytesRead > 0) {
                if (onOutput)
                    onOutput(std::string(buffer, bytesRead));
                continue;
            }
            break;
        }
        if (avail == 0) {
            Sleep(10);
            continue;
        }
        DWORD toRead = avail;
        if (toRead > kMaxChunk)
            toRead = kMaxChunk;
        if (ReadFile(m_hStdOutRead, buffer, toRead, &bytesRead, nullptr) &&
            bytesRead > 0) {
            if (onOutput)
                onOutput(std::string(buffer, bytesRead));
        } else {
            break;
        }
    }
}

void Win32TerminalManager::monitorProcessThread()
{
    if (!m_hProcess)
        return;
    WaitForSingleObject(m_hProcess, INFINITE);
    m_running = false;
    DWORD exitCode = 1;
    GetExitCodeProcess(m_hProcess, &exitCode);
    if (onFinished)
        onFinished(static_cast<int>(exitCode));
}