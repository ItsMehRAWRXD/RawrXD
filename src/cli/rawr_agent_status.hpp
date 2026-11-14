// rawr_agent_status.hpp — non-hanging agent status (session disk scan)
#pragma once
#include "rawr_output_router.hpp"
#include "rawr_session_store.hpp"
#include "rawr_exit_codes.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

inline int CmdAgentStatus(const std::string& filterId) {
    const std::string root = DefaultSessionRoot();
    EnsureSessionRoot(root);
    Diag("AGENT_STATUS=1\nSESSION_ROOT=%s\n", root.c_str());
    int n = 0;
#ifdef _WIN32
    WIN32_FIND_DATAA fd{};
    const std::string glob = root + "\\*.session";
    HANDLE h = FindFirstFileA(glob.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        Diag("SESSIONS=0\nAGENT_STATUS_OK=1\n");
        return ExitCode::Ok;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string name = fd.cFileName ? fd.cFileName : "";
        if (name.size() < 9) continue;
        std::string id = name.substr(0, name.size() - 8);
        if (!filterId.empty() && id != filterId) continue;
        SessionState s{};
        if (!LoadSession(id, s)) continue;
        Diag("SESSION id=%s model=%s turns=%zu plan=%s\n", s.id.c_str(),
             s.modelAlias.c_str(), s.history.size(), s.lastPlan.c_str());
        ++n;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    (void)filterId;
#endif
    Diag("SESSIONS=%d\nAGENT_STATUS_OK=1\n", n);
    return ExitCode::Ok;
}

} // namespace rawr
