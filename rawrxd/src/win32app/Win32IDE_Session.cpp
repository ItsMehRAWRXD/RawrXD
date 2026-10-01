// Win32IDE_Session.cpp — session: save/restore open files and cursor positions
//
// RAWRXD_SESSION_PERSISTENCE_001
//
// Historically Session_SetPath() had no caller, so this file compiled and linked
// but could not read or write anything. It now has a deterministic path, an
// atomic save, line-level reject accounting, and a diagnostics surface.
//
// Record format is unchanged (path|line|col) so an existing session file from an
// earlier build still restores. The only additions are a '#' comment allowance
// and a header line.

#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstdlib>

#include "Win32IDE_Session.h"
#include "Win32IDE_Settings.h"   // for the resolved settings directory

namespace RawrXD::IDE {

static std::vector<SessionFile> g_session;
static std::string g_sessionPath;
static SessionDiagnostics g_diag;

const SessionDiagnostics& Session_Diagnostics() { return g_diag; }

void Session_SetPath(const std::string& path) {
    g_sessionPath = path;
    g_diag.pathResolved = !path.empty();
    g_diag.resolvedPath = path;
}

// The session lives in the same directory as the settings file so the two are
// one configuration location rather than two conventions to discover.
static std::string resolveDefaultSessionPath() {
    std::string settingsPath;
    if (Settings_GetResolvedPath(settingsPath)) {
        const size_t slash = settingsPath.find_last_of("\\/");
        if (slash != std::string::npos) {
            return settingsPath.substr(0, slash) + "\\session.state";
        }
    }
    char localAppData[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
        std::string base(localAppData);
        if (!base.empty()) {
            CreateDirectoryA((base + "\\RawrXD").c_str(), nullptr);
            return base + "\\RawrXD\\session.state";
        }
    }
    return "session.state";
}

bool Session_InitDefaultPath() {
    if (!g_sessionPath.empty()) return true;
    Session_SetPath(resolveDefaultSessionPath());
    return g_diag.pathResolved;
}

void Session_AddFile(const std::string& path, int line, int col)
{
    if (path.empty()) return;
    for (auto& f : g_session) {
        if (f.path == path) { f.line = line; f.col = col; return; }
    }
    g_session.push_back({path, line, col});
    g_diag.filesTracked = g_session.size();
}

bool Session_Load() {
    g_diag.loadCalled = true;
    g_diag.linesRead = 0;
    g_diag.linesRejected = 0;

    if (!Session_InitDefaultPath()) {
        g_diag.lastError = "session path could not be resolved";
        return false;
    }

    std::ifstream f(g_sessionPath);
    if (!f) {
        // First run is not an error: there is no session to restore yet.
        g_diag.lastError = "session file absent (first run)";
        return true;
    }
    g_diag.fileExisted = true;

    std::vector<SessionFile> parsed;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        auto p1 = line.find('|'), p2 = line.rfind('|');
        if (p1 == std::string::npos || p1 == p2) { ++g_diag.linesRejected; continue; }
        SessionFile sf;
        sf.path = line.substr(0, p1);
        if (sf.path.empty()) { ++g_diag.linesRejected; continue; }
        try { sf.line = std::stoi(line.substr(p1 + 1, p2 - p1 - 1)); }
        catch (...) { sf.line = 0; ++g_diag.linesRejected; }
        try { sf.col  = std::stoi(line.substr(p2 + 1)); }
        catch (...) { sf.col  = 0; ++g_diag.linesRejected; }
        parsed.push_back(sf);
        ++g_diag.linesRead;
    }
    f.close();

    g_session.swap(parsed);
    g_diag.filesInSession = g_session.size();
    g_diag.filesTracked = g_session.size();
    return true;
}

bool Session_Persist() {
    g_diag.saveCalled = true;
    if (!Session_InitDefaultPath()) {
        g_diag.lastError = "session path unset; refusing to write";
        return false;
    }

    std::string body;
    body += "# RawrXD IDE session\n";
    body += "# RAWRXD_SESSION_PERSISTENCE_001\n";
    for (const auto& s : g_session) {
        body += s.path + "|" + std::to_string(s.line) + "|" + std::to_string(s.col) + "\n";
    }

    // Atomic: a crash mid-write must not leave a truncated session that would
    // silently drop the user's open editors on the next start.
    const std::string tmp = g_sessionPath + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            g_diag.lastError = "session temp file could not be opened for write";
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.flush();
        if (!out.good()) {
            out.close();
            DeleteFileA(tmp.c_str());
            g_diag.lastError = "session write failed";
            return false;
        }
    }

    if (!ReplaceFileA(g_sessionPath.c_str(), tmp.c_str(), nullptr, 0, nullptr, nullptr)) {
        if (MoveFileExA(tmp.c_str(), g_sessionPath.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            g_diag.saveBytesWritten = body.size();
            g_diag.saveWroteFile = true;
            g_diag.filesInSession = g_session.size();
            return true;
        }
        DWORD err = GetLastError();
        DeleteFileA(tmp.c_str());
        char msg[128] = {};
        snprintf(msg, sizeof(msg), "session atomic replace failed (winerr=%lu)",
                 static_cast<unsigned long>(err));
        g_diag.lastError = msg;
        return false;
    }

    g_diag.saveBytesWritten = body.size();
    g_diag.saveWroteFile = true;
    g_diag.filesInSession = g_session.size();
    return true;
}

void Session_Save() { (void)Session_Persist(); }

const std::vector<SessionFile>& Session_GetFiles() { return g_session; }

void Session_Clear() {
    g_session.clear();
    g_diag.filesInSession = 0;
    g_diag.filesTracked = 0;
}

} // namespace RawrXD::IDE