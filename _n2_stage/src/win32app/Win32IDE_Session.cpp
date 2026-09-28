// Win32IDE_Session.cpp — session: save/restore open files and cursor positions
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace RawrXD::IDE {

struct SessionFile { std::string path; int line; int col; };
static std::vector<SessionFile> g_session;
static std::string g_sessionPath;

void Session_SetPath(const std::string& path) { g_sessionPath = path; }

void Session_AddFile(const std::string& path, int line, int col)
{
    for (auto& f : g_session) { if (f.path == path) { f.line = line; f.col = col; return; } }
    g_session.push_back({path, line, col});
}

void Session_Save()
{
    if (g_sessionPath.empty()) return;
    std::ofstream f(g_sessionPath);
    if (!f) return;
    for (auto& s : g_session) f << s.path << "|" << s.line << "|" << s.col << "\n";
}

void Session_Load()
{
    if (g_sessionPath.empty()) return;
    std::ifstream f(g_sessionPath);
    if (!f) return;
    g_session.clear();
    std::string line;
    while (std::getline(f, line)) {
        auto p1 = line.find('|'), p2 = line.rfind('|');
        if (p1 == std::string::npos || p1 == p2) continue;
        SessionFile sf;
        sf.path = line.substr(0, p1);
        try { sf.line = std::stoi(line.substr(p1+1, p2-p1-1)); } catch(...) { sf.line = 0; }
        try { sf.col  = std::stoi(line.substr(p2+1)); }          catch(...) { sf.col  = 0; }
        g_session.push_back(sf);
    }
}

const std::vector<SessionFile>& Session_GetFiles() { return g_session; }
void Session_Clear() { g_session.clear(); }

} // namespace RawrXD::IDE
