// rawr_terminal_client.cpp
#include "rawr_terminal_client.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <vector>

namespace rawr::term {

bool EnsureHostRunning(const std::string& hostExePath) {
    HANDLE h = CreateFileA(HostPipeName(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return true;
    }
    if (hostExePath.empty()) return false;
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cl = "\"" + hostExePath + "\"";
    std::vector<char> buf(cl.begin(), cl.end());
    buf.push_back(0);
    BOOL ok = CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr,
                             nullptr, &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    for (int i = 0; i < 50; ++i) {
        Sleep(50);
        h = CreateFileA(HostPipeName(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
    }
    return false;
}

bool TermClientTransact(const std::string& req, std::string& rsp) {
    rsp.clear();
    HANDLE h = CreateFileA(HostPipeName(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::string line = req;
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    DWORD wr = 0;
    if (!WriteFile(h, line.data(), (DWORD)line.size(), &wr, nullptr)) {
        CloseHandle(h);
        return false;
    }
    char buf[65536];
    DWORD rd = 0;
    if (!ReadFile(h, buf, sizeof(buf), &rd, nullptr) || rd == 0) {
        CloseHandle(h);
        return false;
    }
    rsp.assign(buf, buf + rd);
    CloseHandle(h);
    return true;
}

static bool parseData(const std::string& rsp, std::string& data) {
    auto p = rsp.find("+DATA ");
    if (p == std::string::npos) return false;
    size_t nl = rsp.find('\n', p);
    if (nl == std::string::npos) return false;
    data = rsp.substr(nl + 1);
    return true;
}

bool TermClientStart(const std::string& name, const std::string& cmd,
                     std::string& rsp) {
    return TermClientTransact("START " + name + " -- " + cmd, rsp) &&
           rsp.rfind("+OK", 0) == 0;
}

bool TermClientTail(const std::string& name, size_t maxBytes,
                    std::string& data) {
    std::string rsp;
    if (!TermClientTransact(
            "TAIL " + name + " " + std::to_string(maxBytes), rsp))
        return false;
    return parseData(rsp, data);
}

bool TermClientStatus(const std::string& name, std::string& rsp) {
    return TermClientTransact("STATUS " + name, rsp) && rsp.rfind("+OK", 0) == 0;
}

bool TermClientStop(const std::string& name, std::string& rsp) {
    return TermClientTransact("STOP " + name, rsp) && rsp.rfind("+OK", 0) == 0;
}

bool TermClientSend(const std::string& name, const std::string& text,
                    std::string& rsp) {
    return TermClientTransact("SEND " + name + " -- " + text, rsp) &&
           rsp.rfind("+OK", 0) == 0;
}

bool TermClientList(std::string& data) {
    std::string rsp;
    if (!TermClientTransact("LIST", rsp)) return false;
    return parseData(rsp, data);
}

bool TermClientKillAll(std::string& rsp) {
    return TermClientTransact("KILLALL", rsp) && rsp.rfind("+OK", 0) == 0;
}

} // namespace rawr::term
