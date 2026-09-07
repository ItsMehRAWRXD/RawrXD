// rawr_terminal_session.hpp — one background CreateProcess + capture
#pragma once
#include "rawr_terminal_ring_buffer.hpp"
#include "rawr_terminal_log.hpp"
#include <atomic>
#include <string>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

struct TerminalSession {
    std::string name;
    std::string cmd;
    DWORD pid = 0;
    int exitCode = -1;
    std::atomic<bool> alive{false};
    std::atomic<bool> stopReq{false};
    size_t stdoutBytes = 0;
    size_t stderrBytes = 0;
    TerminalRingBuffer ring;
#ifdef _WIN32
    HANDLE hProc = nullptr;
    HANDLE hThread = nullptr;
    HANDLE hOutR = nullptr;
    HANDLE hErrR = nullptr;
    HANDLE hInW = nullptr;
#endif
    std::thread reader;

    ~TerminalSession() { joinReader(); closeHandles(); }

    void joinReader() {
        stopReq = true;
        if (reader.joinable()) reader.join();
    }

    void closeHandles() {
#ifdef _WIN32
        auto cl = [](HANDLE& h) {
            if (h && h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
                h = nullptr;
            }
        };
        cl(hOutR);
        cl(hErrR);
        cl(hInW);
        cl(hThread);
        cl(hProc);
#endif
    }

    bool isAlive() const {
#ifdef _WIN32
        if (!hProc) return false;
        DWORD st = 0;
        if (!GetExitCodeProcess(hProc, &st)) return false;
        return st == STILL_ACTIVE;
#else
        return alive.load();
#endif
    }
};

bool TerminalSessionStart(TerminalSession& s, const std::string& name,
                          const std::string& command);
bool TerminalSessionSend(TerminalSession& s, const std::string& input);
bool TerminalSessionStop(TerminalSession& s);
void TerminalSessionPoll(TerminalSession& s);

} // namespace rawr
