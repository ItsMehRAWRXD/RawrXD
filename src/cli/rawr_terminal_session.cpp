// rawr_terminal_session.cpp — Win32 pipes + reader thread
#include "rawr_terminal_session.hpp"
#include <vector>

namespace rawr {

#ifdef _WIN32
static void pumpPipe(HANDLE h, TerminalSession& s, bool isErr) {
    char buf[4096];
    DWORD avail = 0, rd = 0;
    if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr) || !avail)
        return;
    DWORD want = (std::min)(avail, (DWORD)sizeof(buf));
    if (!ReadFile(h, buf, want, &rd, nullptr) || !rd) return;
    s.ring.append(buf, rd);
    TerminalLogAppend(s.name, buf, rd);
    if (isErr) s.stderrBytes += rd;
    else s.stdoutBytes += rd;
}

static void readerMain(TerminalSession* sp) {
    TerminalSession& s = *sp;
    while (!s.stopReq.load()) {
        if (s.hOutR) pumpPipe(s.hOutR, s, false);
        if (s.hErrR) pumpPipe(s.hErrR, s, true);
        DWORD st = WaitForSingleObject(s.hProc, 20);
        if (st != WAIT_TIMEOUT) {
            if (s.hOutR) pumpPipe(s.hOutR, s, false);
            if (s.hErrR) pumpPipe(s.hErrR, s, true);
            DWORD code = 1;
            GetExitCodeProcess(s.hProc, &code);
            s.exitCode = (int)code;
            s.alive = false;
            TerminalMetaWrite(s.name, s.pid, s.cmd, 0);
            break;
        }
    }
}
#endif

bool TerminalSessionStart(TerminalSession& s, const std::string& name,
                          const std::string& command) {
#ifdef _WIN32
    s.name = name;
    s.cmd = command;
    s.exitCode = -1;
    s.stopReq = false;
    s.stdoutBytes = s.stderrBytes = 0;
    s.ring.clear();
    EnsureTerminalRoot();
    DeleteFileA(TerminalLogPath(name).c_str());

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE outR = 0, outW = 0, errR = 0, errW = 0, inR = 0, inW = 0;
    if (!CreatePipe(&outR, &outW, &sa, 0)) return false;
    if (!CreatePipe(&errR, &errW, &sa, 0)) return false;
    if (!CreatePipe(&inR, &inW, &sa, 0)) return false;
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outW;
    si.hStdError = errW;
    si.hStdInput = inR;
    PROCESS_INFORMATION pi{};
    std::vector<char> cl(command.begin(), command.end());
    cl.push_back('\0');
    BOOL ok = CreateProcessA(nullptr, cl.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(outW);
    CloseHandle(errW);
    CloseHandle(inR);
    if (!ok) {
        CloseHandle(outR);
        CloseHandle(errR);
        CloseHandle(inW);
        return false;
    }
    s.hProc = pi.hProcess;
    s.hThread = pi.hThread;
    s.hOutR = outR;
    s.hErrR = errR;
    s.hInW = inW;
    s.pid = pi.dwProcessId;
    s.alive = true;
    TerminalMetaWrite(s.name, s.pid, s.cmd, 1);
    s.reader = std::thread(readerMain, &s);
    return true;
#else
    (void)s; (void)name; (void)command;
    return false;
#endif
}

bool TerminalSessionSend(TerminalSession& s, const std::string& input) {
#ifdef _WIN32
    if (!s.hInW || !s.isAlive()) return false;
    std::string line = input;
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    DWORD wr = 0;
    return WriteFile(s.hInW, line.data(), (DWORD)line.size(), &wr, nullptr) != 0;
#else
    (void)s; (void)input;
    return false;
#endif
}

bool TerminalSessionStop(TerminalSession& s) {
#ifdef _WIN32
    if (!s.hProc) return false;
    s.stopReq = true;
    BOOL ok = TerminateProcess(s.hProc, 1);
    WaitForSingleObject(s.hProc, 3000);
    if (s.reader.joinable()) s.reader.join();
    DWORD code = 1;
    GetExitCodeProcess(s.hProc, &code);
    s.exitCode = (int)code;
    s.alive = false;
    TerminalMetaWrite(s.name, s.pid, s.cmd, 0);
    return ok != 0;
#else
    (void)s;
    return false;
#endif
}

void TerminalSessionPoll(TerminalSession& s) {
    if (!s.alive.load()) return;
    if (!s.isAlive() && s.exitCode < 0) {
#ifdef _WIN32
        DWORD code = 0;
        if (s.hProc && GetExitCodeProcess(s.hProc, &code) &&
            code != STILL_ACTIVE) {
            s.exitCode = (int)code;
            s.alive = false;
            TerminalMetaWrite(s.name, s.pid, s.cmd, 0);
        }
#endif
    }
}

} // namespace rawr
