// rawr_named_pipe.hpp + steering bus (local only)
#pragma once
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

inline const char* SteerPipeName() { return "\\\\.\\pipe\\rawrxd_steer"; }

struct SteerCommand {
    std::string verb; // pause|continue|stop|show_plan|undo|...
    std::string arg;
};

inline bool ParseSteerLine(const std::string& line, SteerCommand& c) {
    c = {};
    if (line.empty()) return false;
    auto sp = line.find(' ');
    if (sp == std::string::npos) {
        c.verb = line;
        return true;
    }
    c.verb = line.substr(0, sp);
    c.arg = line.substr(sp + 1);
    return true;
}

// Non-blocking client send (creates pipe client briefly).
inline bool SteerSend(const std::string& line) {
#ifdef _WIN32
    HANDLE h = CreateFileA(SteerPipeName(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, line.data(), (DWORD)line.size(), &wr, nullptr);
    CloseHandle(h);
    return ok == TRUE;
#else
    (void)line;
    return false;
#endif
}

// One-shot server accept for cert (timeout ms).
inline bool SteerServeOnce(std::string& outLine, DWORD timeoutMs = 2000) {
#ifdef _WIN32
    HANDLE h = CreateNamedPipeA(
        SteerPipeName(), PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096,
        timeoutMs, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BOOL connected = ConnectNamedPipe(h, nullptr)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        CloseHandle(h);
        return false;
    }
    char buf[1024]{};
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    DisconnectNamedPipe(h);
    CloseHandle(h);
    if (!ok || rd == 0) return false;
    outLine.assign(buf, buf + rd);
    return true;
#else
    (void)outLine;
    (void)timeoutMs;
    return false;
#endif
}

} // namespace rawr
