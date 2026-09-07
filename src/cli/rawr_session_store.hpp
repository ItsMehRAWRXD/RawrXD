// rawr_session_store.hpp — disk session + resume (no network)
#pragma once
#include "rawr_session_state.hpp"
#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

inline std::string DefaultSessionRoot() {
    return "G:\\~dev\\rawrxd\\evidence\\RAWRXD_SESSIONS";
}

inline void EnsureSessionRoot(const std::string& root) {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(root.c_str(), nullptr);
#else
    (void)root;
#endif
}

inline std::string NewSessionId() {
    char buf[64];
    snprintf(buf, sizeof(buf), "sess_%llu", (unsigned long long)time(nullptr));
    return buf;
}

inline std::string SessionPath(const std::string& id) {
    return DefaultSessionRoot() + "\\" + id + ".session";
}

inline bool SaveSession(const SessionState& s) {
    EnsureSessionRoot(DefaultSessionRoot());
    std::ofstream out(SessionPath(s.id), std::ios::binary);
    if (!out) return false;
    out << "id=" << s.id << "\n";
    out << "model=" << s.modelAlias << "\n";
    out << "path=" << s.modelPath << "\n";
    out << "workspace=" << s.workspace << "\n";
    out << "autonomy=" << AutonomyName(s.autonomy) << "\n";
    out << "plan=" << s.lastPlan << "\n";
    out << "patch=" << s.lastPatchId << "\n";
    out << "turns=" << s.history.size() << "\n";
    for (const auto& t : s.history) {
        out << t.role << "\t" << t.content << "\n";
    }
    return true;
}

inline bool LoadSession(const std::string& id, SessionState& s) {
    std::ifstream in(SessionPath(id), std::ios::binary);
    if (!in) return false;
    s = {};
    s.id = id;
    std::string line;
    size_t turns = 0;
    while (std::getline(in, line)) {
        if (line.rfind("model=", 0) == 0) s.modelAlias = line.substr(6);
        else if (line.rfind("path=", 0) == 0) s.modelPath = line.substr(5);
        else if (line.rfind("workspace=", 0) == 0) s.workspace = line.substr(10);
        else if (line.rfind("autonomy=", 0) == 0)
            s.autonomy = ParseAutonomy(line.c_str() + 9);
        else if (line.rfind("plan=", 0) == 0) s.lastPlan = line.substr(5);
        else if (line.rfind("patch=", 0) == 0) s.lastPatchId = line.substr(6);
        else if (line.rfind("turns=", 0) == 0) turns = (size_t)atoi(line.c_str() + 6);
        else if (!line.empty() && turns) {
            auto tab = line.find('\t');
            ChatTurn t{};
            if (tab == std::string::npos) {
                t.role = "user";
                t.content = line;
            } else {
                t.role = line.substr(0, tab);
                t.content = line.substr(tab + 1);
            }
            s.history.push_back(std::move(t));
        }
    }
    s.alive = true;
    return true;
}

} // namespace rawr
