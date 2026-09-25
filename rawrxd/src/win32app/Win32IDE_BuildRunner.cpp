// Win32IDE_BuildRunner.cpp — build execution with output capture and error parsing
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <regex>
#include <cstdio>

namespace RawrXD::IDE {

void TerminalSplit_AppendOutput(const std::string& text);

struct BuildDiagnostic {
    std::string file;
    int         line   = 0;
    int         col    = 0;
    bool        isError = true;
    std::string message;
};

struct BuildRunnerState {
    std::atomic<bool> running{false};
    std::vector<BuildDiagnostic> diagnostics;
    std::function<void(const std::string&)> onOutput;
    std::function<void(bool success, int errors, int warnings)> onDone;
    std::string buildDir;
    std::string buildCmd;
    int errorCount   = 0;
    int warningCount = 0;
};

static BuildRunnerState g_build;

// ── Parse MSVC/GCC diagnostic lines ──────────────────────────────────────────
static void ParseDiagnosticLine(const std::string& line)
{
    // MSVC: file(line,col): error C1234: msg
    {
        std::regex re(R"(^(.+)\((\d+),(\d+)\)\s*:\s*(error|warning)\s+\w+:\s*(.+)$)");
        std::smatch m;
        if (std::regex_match(line, m, re)) {
            BuildDiagnostic d;
            d.file    = m[1].str();
            d.line    = std::stoi(m[2].str());
            d.col     = std::stoi(m[3].str());
            d.isError = (m[4].str() == "error");
            d.message = m[5].str();
            g_build.diagnostics.push_back(d);
            if (d.isError) ++g_build.errorCount;
            else           ++g_build.warningCount;
            return;
        }
    }
    // GCC/Clang: file:line:col: error: msg
    {
        std::regex re(R"(^(.+):(\d+):(\d+):\s*(error|warning):\s*(.+)$)");
        std::smatch m;
        if (std::regex_match(line, m, re)) {
            BuildDiagnostic d;
            d.file    = m[1].str();
            d.line    = std::stoi(m[2].str());
            d.col     = std::stoi(m[3].str());
            d.isError = (m[4].str() == "error");
            d.message = m[5].str();
            g_build.diagnostics.push_back(d);
            if (d.isError) ++g_build.errorCount;
            else           ++g_build.warningCount;
        }
    }
}

// ── Run build in background thread ───────────────────────────────────────────
static void BuildThread(std::string cmd, std::string dir)
{
    g_build.diagnostics.clear();
    g_build.errorCount   = 0;
    g_build.warningCount = 0;

    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    CreatePipe(&hR, &hW, &sa, 0);
    SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hW;
    si.hStdError   = hW;

    PROCESS_INFORMATION pi = {};
    bool ok = !!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr,
                               TRUE, CREATE_NO_WINDOW, nullptr,
                               dir.empty() ? nullptr : dir.c_str(), &si, &pi);
    CloseHandle(hW);

    if (!ok) {
        std::string err = "[BuildRunner] Failed to launch: " + cmd + "\n";
        TerminalSplit_AppendOutput(err);
        if (g_build.onOutput) g_build.onOutput(err);
        g_build.running.store(false);
        if (g_build.onDone) g_build.onDone(false, 1, 0);
        CloseHandle(hR);
        return;
    }

    char buf[4096];
    DWORD read;
    std::string partial;
    while (ReadFile(hR, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = '\0';
        partial += buf;
        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string line = partial.substr(0, pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            partial = partial.substr(pos + 1);
            ParseDiagnosticLine(line);
            TerminalSplit_AppendOutput(line);
            if (g_build.onOutput) g_build.onOutput(line);
        }
    }
    if (!partial.empty()) {
        ParseDiagnosticLine(partial);
        TerminalSplit_AppendOutput(partial);
        if (g_build.onOutput) g_build.onOutput(partial);
    }

    CloseHandle(hR);
    DWORD exitCode = 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    bool success = (exitCode == 0);
    char summary[128];
    snprintf(summary, sizeof(summary),
             "[Build] %s — %d error(s), %d warning(s)\n",
             success ? "SUCCEEDED" : "FAILED",
             g_build.errorCount, g_build.warningCount);
    TerminalSplit_AppendOutput(summary);
    if (g_build.onOutput) g_build.onOutput(summary);

    g_build.running.store(false);
    if (g_build.onDone) g_build.onDone(success, g_build.errorCount, g_build.warningCount);
}

// ── Public API ────────────────────────────────────────────────────────────────
void BuildRunner_SetBuildDir(const std::string& dir) { g_build.buildDir = dir; }
void BuildRunner_SetBuildCmd(const std::string& cmd) { g_build.buildCmd = cmd; }

void BuildRunner_SetOutputCallback(std::function<void(const std::string&)> cb)
{
    g_build.onOutput = std::move(cb);
}

void BuildRunner_SetDoneCallback(std::function<void(bool, int, int)> cb)
{
    g_build.onDone = std::move(cb);
}

bool BuildRunner_IsRunning() { return g_build.running.load(); }

bool BuildRunner_Run(const std::string& cmd, const std::string& dir)
{
    if (g_build.running.load()) return false;
    g_build.running.store(true);
    std::string c = cmd.empty() ? g_build.buildCmd : cmd;
    std::string d = dir.empty() ? g_build.buildDir : dir;
    if (c.empty()) c = "cmake --build . --config Release";
    std::thread(BuildThread, c, d).detach();
    return true;
}

bool BuildRunner_RunCMake(const std::string& buildDir, const std::string& config)
{
    std::string cmd = "cmake --build \"" + buildDir + "\" --config " + config;
    return BuildRunner_Run(cmd, buildDir);
}

const std::vector<BuildDiagnostic>& BuildRunner_GetDiagnostics()
{
    return g_build.diagnostics;
}

int BuildRunner_ErrorCount()   { return g_build.errorCount; }
int BuildRunner_WarningCount() { return g_build.warningCount; }

} // namespace RawrXD::IDE
