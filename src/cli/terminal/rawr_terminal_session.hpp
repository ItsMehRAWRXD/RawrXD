// rawr_terminal_session.hpp
#pragma once
#include "../../platform/rawr_win32_process.hpp"
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace rawr::term {

inline std::string TermRoot() {
    return "G:\\~dev\\rawrxd\\.rawrxd\\terminals";
}

void EnsureTermRoot();
bool AppendTermLog(const std::string& name, const char* p, size_t n);
std::string ReadTermLogTail(const std::string& name, size_t maxBytes);
bool WriteTermMeta(const std::string& name, DWORD pid, int alive, int exitCode,
                   const std::string& cmd);

struct TermSession {
    std::string name;
    std::string cmd;
    WinProcess proc;
    std::atomic<bool> alive{false};
    std::atomic<bool> stopReq{false};
    int exitCode = -1;
    size_t outBytes = 0;
    size_t errBytes = 0;
    std::mutex ringMu;
    std::string ring; // last ~256KB
    std::thread reader;

    ~TermSession() { stopReader(); WinProcessClose(proc); }
    void stopReader();
    void appendRing(const char* p, size_t n);
    std::string tail(size_t maxBytes);
};

bool SessionStart(TermSession& s, const std::string& name,
                  const std::string& cmd);
bool SessionSend(TermSession& s, const std::string& input);
bool SessionStop(TermSession& s);
void SessionPoll(TermSession& s);

} // namespace rawr::term
