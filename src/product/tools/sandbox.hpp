#pragma once
#include "permission.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct Sandbox {
    std::string workspace;
    PermSet perm;
    int lastDenied = 0;

    bool checkRead(const std::string& path) {
        if (!perm.has(Perm::Read) || !PathUnder(workspace, path)) {
            lastDenied = 1;
            return false;
        }
        return true;
    }
    bool checkWrite(const std::string& path) {
        if (!perm.has(Perm::Write) || !PathUnder(workspace, path)) {
            lastDenied = 2;
            return false;
        }
        return true;
    }
    bool checkExec(const std::string& cmd) {
        if (!perm.has(Perm::Exec) || CmdBlocked(cmd)) {
            lastDenied = 3;
            return false;
        }
        return true;
    }
};

inline int SandboxRunEcho(const Sandbox& sb, const std::string& msg,
                          std::string& out) {
    if (!sb.perm.has(Perm::Exec)) return 3;
#ifdef _WIN32
    std::string cmd = "cmd /c echo " + msg;
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return 4;
    char buf[256];
    out.clear();
    while (fgets(buf, sizeof(buf), p)) out += buf;
    return _pclose(p);
#else
    (void)msg;
    (void)out;
    return 4;
#endif
}

} // namespace rawr::product
