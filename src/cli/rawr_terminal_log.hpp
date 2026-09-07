// rawr_terminal_log.hpp — durable logs under .rawrxd/terminals/
#pragma once
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

inline std::string TerminalRoot() {
    return "G:\\~dev\\rawrxd\\.rawrxd\\terminals";
}

inline void EnsureTerminalRoot() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\.rawrxd", nullptr);
    CreateDirectoryA(TerminalRoot().c_str(), nullptr);
#endif
}

inline std::string TerminalLogPath(const std::string& name) {
    return TerminalRoot() + "\\" + name + ".log";
}
inline std::string TerminalMetaPath(const std::string& name) {
    return TerminalRoot() + "\\" + name + ".meta";
}

inline bool TerminalLogAppend(const std::string& name, const char* p,
                              size_t n) {
    if (!p || !n) return true;
    EnsureTerminalRoot();
    FILE* f = fopen(TerminalLogPath(name).c_str(), "ab");
    if (!f) return false;
    fwrite(p, 1, n, f);
    fclose(f);
    return true;
}

inline bool TerminalMetaWrite(const std::string& name, DWORD pid,
                              const std::string& cmd, int alive) {
    EnsureTerminalRoot();
    FILE* f = fopen(TerminalMetaPath(name).c_str(), "wb");
    if (!f) return false;
    fprintf(f, "name=%s\npid=%lu\nalive=%d\ncmd=%s\n", name.c_str(),
            (unsigned long)pid, alive, cmd.c_str());
    fclose(f);
    return true;
}

inline bool TerminalMetaRead(const std::string& name, DWORD& pid, int& alive,
                             std::string& cmd) {
    FILE* f = fopen(TerminalMetaPath(name).c_str(), "rb");
    if (!f) return false;
    char line[1024];
    pid = 0;
    alive = 0;
    cmd.clear();
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "pid=", 4)) pid = (DWORD)strtoul(line + 4, nullptr, 10);
        else if (!strncmp(line, "alive=", 6)) alive = atoi(line + 6);
        else if (!strncmp(line, "cmd=", 4)) {
            cmd = line + 4;
            while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
                cmd.pop_back();
        }
    }
    fclose(f);
    return pid != 0;
}

inline std::string TerminalLogReadTail(const std::string& name,
                                       size_t maxBytes) {
    FILE* f = fopen(TerminalLogPath(name).c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return {}; }
    size_t n = (size_t)sz;
    if (n > maxBytes) {
        fseek(f, (long)(n - maxBytes), SEEK_SET);
        n = maxBytes;
    } else {
        fseek(f, 0, SEEK_SET);
    }
    std::string out(n, '\0');
    fread(&out[0], 1, n, f);
    fclose(f);
    return out;
}

} // namespace rawr
