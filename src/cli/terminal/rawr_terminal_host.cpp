// rawr_terminal_host.cpp
#include "rawr_terminal_host.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sstream>

namespace rawr::term {

static std::string takeAfterDashDash(const std::string& s) {
    auto p = s.find(" -- ");
    if (p == std::string::npos) return {};
    return s.substr(p + 4);
}

std::string HandleHostRequest(TerminalSupervisor& sup, const std::string& line) {
    if (line.empty()) return ErrLine(1, "empty");
    if (line == "PING") return OkLine("PONG");
    if (line == "LIST") {
        std::string body = sup.list();
        return OkLine("list") + "+DATA " + std::to_string(body.size()) + "\n" +
               body;
    }
    if (line == "KILLALL") {
        int n = sup.killall();
        return OkLine("killed=" + std::to_string(n));
    }
    if (StartsWith(line, "START ")) {
        std::string rest = line.substr(6);
        auto sp = rest.find(' ');
        std::string name = sp == std::string::npos ? rest : rest.substr(0, sp);
        std::string cmd = takeAfterDashDash(line);
        if (cmd.empty() && sp != std::string::npos) cmd = rest.substr(sp + 1);
        int rc = sup.start(name, cmd);
        if (rc) return ErrLine(rc, "start");
        auto* s = sup.get(name);
        return OkLine("name=" + name + " pid=" +
                      std::to_string(s ? s->proc.pid : 0));
    }
    if (StartsWith(line, "TAIL ")) {
        std::istringstream is(line.substr(5));
        std::string name;
        size_t maxb = 8192;
        is >> name >> maxb;
        std::string data = sup.tail(name, maxb);
        return "+DATA " + std::to_string(data.size()) + "\n" + data;
    }
    if (StartsWith(line, "STATUS ")) return OkLine(sup.status(line.substr(7)));
    if (StartsWith(line, "SEND ")) {
        std::string rest = line.substr(5);
        auto sp = rest.find(" -- ");
        std::string name = sp == std::string::npos ? rest : rest.substr(0, sp);
        std::string text = sp == std::string::npos ? "" : rest.substr(sp + 4);
        if (!sup.send(name, text)) return ErrLine(4, "send");
        return OkLine("sent=1");
    }
    if (StartsWith(line, "STOP ")) {
        if (!sup.stop(line.substr(5))) return ErrLine(5, "stop");
        return OkLine("stopped=1");
    }
    return ErrLine(9, "unknown");
}

int RunTerminalHost(int idleExitMs) {
    (void)idleExitMs;
    TerminalSupervisor& sup = TerminalSupervisor::instance();
    for (;;) {
        HANDLE h = CreateNamedPipeA(
            HostPipeName(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1 << 16, 1 << 16,
            0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return 1;
        BOOL ok = ConnectNamedPipe(h, nullptr)
                      ? TRUE
                      : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!ok) {
            CloseHandle(h);
            continue;
        }
        char buf[8192]{};
        DWORD rd = 0;
        if (!ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr) || !rd) {
            DisconnectNamedPipe(h);
            CloseHandle(h);
            continue;
        }
        std::string req(buf, buf + rd);
        while (!req.empty() && (req.back() == '\n' || req.back() == '\r'))
            req.pop_back();
        std::string rsp = HandleHostRequest(sup, req);
        DWORD wr = 0;
        WriteFile(h, rsp.data(), (DWORD)rsp.size(), &wr, nullptr);
        FlushFileBuffers(h);
        DisconnectNamedPipe(h);
        CloseHandle(h);
        if (req == "HOST_EXIT") break;
    }
    return 0;
}

bool HostIsAlive() {
    HANDLE h = CreateFileA(HostPipeName(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

} // namespace rawr::term
