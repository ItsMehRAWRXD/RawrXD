#include "AgentProduct.hpp"
#include "AgentSession.hpp"
#include "IdeAuthBoundary.hpp"
#include <windows.h>
#include <string>
#include <vector>

namespace {
void* g_ctx = nullptr;
std::string (*g_spawn)(void*, const char*, const char*) = nullptr;
bool (*g_wait)(void*, const char*, int) = nullptr;
std::string (*g_result)(void*, const char*) = nullptr;
const char* (*g_state)(void*, const char*) = nullptr;

std::string Arg(const std::string& json, const char* key) {
    const std::string pat = std::string("\"") + key + "\"";
    auto p = json.find(pat);
    if (p == std::string::npos) return {};
    p = json.find(':', p);
    auto a = p == std::string::npos ? std::string::npos : json.find('"', p + 1);
    auto b = a == std::string::npos ? std::string::npos : json.find('"', a + 1);
    if (a == std::string::npos || b == std::string::npos) return {};
    return json.substr(a + 1, b - a - 1);
}
}

void AgentBindWorker(void* ctx, std::string (*spawn)(void*, const char*, const char*),
                     bool (*wait)(void*, const char*, int),
                     std::string (*result)(void*, const char*),
                     const char* (*state)(void*, const char*)) {
    g_ctx = ctx; g_spawn = spawn; g_wait = wait; g_result = result; g_state = state;
}

std::vector<std::string> AgentToolNames() {
    return {"read_file", "write_file", "list_directory", "search_files", "grep_files",
            "execute_command", "git_status", "run_subagent"};
}

std::string AgentSpawnWorker(const std::string& arguments, std::string* workerId) {
    if (!g_spawn || !g_ctx) return "{\"error\":\"worker_unavailable\"}";
    std::string id = g_spawn(g_ctx, Arg(arguments, "description").c_str(),
                             Arg(arguments, "prompt").c_str());
    if (workerId) *workerId = id;
    return "{\"workerId\":\"" + id + "\",\"state\":\"pending\"}";
}

std::string AgentJoinWorkers(const std::vector<std::string>& ids) {
    std::string out;
    for (const auto& id : ids) {
        if (!g_wait || !g_ctx) { out += id + " worker_unavailable\n"; continue; }
        g_wait(g_ctx, id.c_str(), 120000);
        const char* st = g_state ? g_state(g_ctx, id.c_str()) : "unknown";
        std::string result = g_result ? g_result(g_ctx, id.c_str()) : "";
        if (result.size() > 4000) result.resize(4000);
        out += id + " state=" + (st ? st : "unknown") + " result=" + result + "\n";
    }
    return out;
}

std::string AgentRunCommand(const std::string& name, const std::string& arguments) {
    if (!RawrXD::IdeAuth::PrivilegedExecGranted())
        return "{\"error\":\"execution_not_granted\"}";
    std::string command = name == "git_status" ? "git status" : Arg(arguments, "command");
    if (command.empty()) return "{\"error\":\"missing_command\"}";
    std::string root, err;
    if (!RawrXD::IdeAuth::CanonicalInsideWorkspace(".", root, err))
        return "{\"error\":\"workspace_unset\"}";
    SECURITY_ATTRIBUTES sa = {}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return "{\"error\":\"pipe_failed\"}";
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    std::string cmd = "cmd.exe /c " + command;
    std::vector<char> buf(cmd.begin(), cmd.end()); buf.push_back('\0');
    STARTUPINFOA si = {}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr; si.hStdError = wr;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             nullptr, root.c_str(), &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return "{\"error\":\"CreateProcess_failed\"}"; }
    AgentSessionNoteTerminal(pi.dwProcessId, 1);
    std::string output; char tmp[1024]; DWORD n = 0; DWORD waited = 0;
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail &&
            ReadFile(rd, tmp, sizeof(tmp), &n, nullptr) && n) output.append(tmp, n);
        if (AgentSessionCancelled()) { AgentSessionKillTree(pi.hProcess); break; }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) break;
        if ((waited += 50) >= 15000) { AgentSessionKillTree(pi.hProcess); break; }
    }
    while (PeekNamedPipe(rd, nullptr, 0, nullptr, &n, nullptr) && n &&
           ReadFile(rd, tmp, sizeof(tmp), &n, nullptr) && n) output.append(tmp, n);
    CloseHandle(rd);
    AgentSessionNoteTerminal(pi.dwProcessId, 0);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (output.size() > 4000) output.resize(4000);
    return "{\"exitCode\":" + std::to_string(code) + ",\"output\":\"" + output + "\"}";
}
