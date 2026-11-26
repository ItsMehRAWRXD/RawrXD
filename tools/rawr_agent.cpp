// rawr_agent.cpp — RAWRXD_GENERAL_HEADLESS_AUTONOMOUS_CLI_033
// Headless native CLI to RawrXD's autonomous controller. Reuses the production
// Ollama WinHTTP transport (OllamaExecutor.hpp). The MODEL generates tool calls;
// this controller parses and executes them inside an authorized workspace, loops
// with real feedback, and emits inference + tool telemetry. No simulated tools.
#include "OllamaExecutor.hpp"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <atomic>
#include <chrono>
#include <filesystem>

using namespace std;
static atomic<bool> g_cancel{false};
static string g_ws;

static string NowMs() {
    using namespace std::chrono;
    return to_string(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}
static double NowS() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// Extract a JSON string value for a key, handling escapes (\n \t \" \\ \uXXXX).
static string ExtractJsonString(const string& j, const string& key) {
    const string pat = "\"" + key + "\"";
    size_t p = j.find(pat);
    if (p == string::npos) return {};
    p = j.find(':', p);
    if (p == string::npos) return {};
    ++p;
    while (p < j.size() && (j[p]==' '||j[p]=='\t'||j[p]=='\n'||j[p]=='\r')) ++p;
    if (p >= j.size() || j[p] != '"') return {};
    ++p; string out;
    while (p < j.size()) {
        char c = j[p++];
        if (c == '"') break;
        if (c == '\\' && p < j.size()) {
            char e = j[p++];
            switch (e) {
                case 'n': out += '\n'; break; case 't': out += '\t'; break;
                case 'r': out += '\r'; break; case '"': out += '"'; break;
                case '\\': out += '\\'; break; case '/': out += '/'; break;
                case 'u': { if (p+4 <= j.size()) { int v = (int)strtol(j.substr(p,4).c_str(),nullptr,16); if (v<128) out += (char)v; p += 4; } break; }
                default: out += e; break;
            }
        } else out += c;
    }
    return out;
}

static string JsonEscape(const string& s) {
    string o; o.reserve(s.size()+16);
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break; case '\r': o += "\\r"; break; case '\t': o += "\\t"; break;
            default: o += c;
        }
    }
    return o;
}

// First balanced {...} object in text (the model's tool call).
static string FirstJsonObject(const string& t) {
    size_t s = t.find('{');
    if (s == string::npos) return {};
    int depth = 0; bool inStr = false; char esc = 0;
    for (size_t i = s; i < t.size(); ++i) {
        char c = t[i];
        if (inStr) { if (esc) esc = 0; else if (c=='\\') esc = 1; else if (c=='"') inStr = false; continue; }
        if (c == '"') inStr = true;
        else if (c == '{') ++depth;
        else if (c == '}') { if (--depth == 0) return t.substr(s, i - s + 1); }
    }
    return {};
}

static bool PathInWs(const string& rel, string& full) {
    namespace fs = std::filesystem;
    fs::path base = fs::path(g_ws).lexically_normal();
    fs::path f = (fs::path(rel).is_absolute() ? fs::path(rel) : base / rel).lexically_normal();
    auto b = base.string(); auto fs2 = f.string();
    if (fs2.size() < b.size() || fs2.compare(0, b.size(), b) != 0) return false;
    full = fs2; return true;
}

static bool SrcHasRealApi() {
    ifstream f(std::filesystem::path(g_ws) / "sysmon.cpp");
    stringstream ss; ss << f.rdbuf(); string s = ss.str();
    return s.find("GetSystemTimes") != string::npos ||
           s.find("GlobalMemoryStatusEx") != string::npos ||
           s.find("GetDiskFreeSpaceEx") != string::npos ||
           s.find("EnumDisplayDevices") != string::npos;
}

static string RunCmd(const string& cmd) {
    string full = "cd /d \"" + g_ws + "\" && " + cmd + " 2>&1";
    string out;
    FILE* p = _popen(full.c_str(), "r");
    if (!p) return "ERROR: popen failed";
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) { out.append(buf, n); if (out.size() > 8000) { out += "\n[truncated]"; break; } }
    _pclose(p);
    return out;
}

static BOOL WINAPI CtrlHandler(DWORD t) { if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT) g_cancel.store(true); return TRUE; }

// Functional completion: real APIs in source + exe exists + exe launches (bounded).
static bool VerifyFunctional() {
    namespace fs = std::filesystem;
    if (!fs::exists(fs::path(g_ws) / "sysmon.cpp")) return false;
    if (!SrcHasRealApi()) return false;
    if (!fs::exists(fs::path(g_ws) / "sysmon.exe")) return false;
    string cmd = "\"" + g_ws + "\\sysmon.exe\"";
    vector<wchar_t> w(cmd.begin(), cmd.end()); w.push_back(0);
    std::wstring wdir(g_ws.begin(), g_ws.end());
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, w.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, wdir.c_str(), &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 2000);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    const bool alive = (code == STILL_ACTIVE);
    if (alive) TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return alive || code == 0;   // launched and did not immediately crash
}

struct Telemetry {
    int requests = 0, promptTokens = 0, evalTokens = 0;
    double promptNs = 0, evalNs = 0;
    int toolCalls = 0, toolOk = 0, toolFail = 0, corrections = 0;
    double start = 0;
} g_tel;

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    string model = "qwen3:8b", objective, ws = "F:\\rawrxd_acceptance_sysmon_native";
    int maxTurns = 30;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        auto next = [&]() -> string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--model") model = next();
        else if (a == "--workspace") ws = next();
        else if (a == "--objective") objective = next();
        else if (a == "--max-turns") maxTurns = atoi(next().c_str());
    }
    g_ws = ws;
    std::filesystem::create_directories(g_ws);
    g_tel.start = NowS();
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    // Compiler discovery: tell the model the real build environment.
    string envNote;
    {
        const char* vcvars = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat";
        if (std::filesystem::exists(vcvars))
            envNote = "\nCOMPILER_ENV: MSVC cl is NOT on PATH. build.cmd MUST call \"" + string(vcvars) +
                      "\" before cl. Example build.cmd: @echo off / call \"...vcvars64.bat\" >nul 2>&1 / cl /nologo /std:c++17 /EHsc sysmon.cpp /Fe:sysmon.exe /link user32.lib gdi32.lib";
        else
            envNote = "\nCOMPILER_ENV: no MSVC found; use g++ (on PATH) if available.";
    }

    const string sys =
        "You are RawrXD, an autonomous software engineer operating a real workstation. "
        "Work ONLY inside the given workspace. Output EXACTLY ONE tool call per turn as a single JSON object, nothing else. "
        "Tools: {\"tool\":\"write\",\"path\":\"FILE\",\"content\":\"TEXT\"} writes a file; "
        "{\"tool\":\"run\",\"cmd\":\"COMMAND\"} runs a shell command in the workspace and returns its output; "
        "{\"tool\":\"read\",\"path\":\"FILE\"} reads a file; {\"tool\":\"list\"} lists the workspace; "
        "{\"tool\":\"finish\",\"summary\":\"...\"} declares completion (ONLY allowed once sysmon.cpp AND sysmon.exe exist). "
        "DELIVERABLE: a file named sysmon.cpp and a build.cmd that compiles it to sysmon.exe. Do not finish until sysmon.exe exists. "
        "Inspect first, then create source, build, read compiler output, fix errors, test, and finish. Be efficient.";

    vector<pair<string,string>> msgs; // role, content
    msgs.push_back({"system", sys});
    msgs.push_back({"user", "OBJECTIVE: " + objective + "\nWorkspace: " + g_ws + envNote + ". Begin."});

    string finalSummary;
    int finishRejects = 0;
    string lastCall; int repeatCount = 0;
    for (int turn = 0; turn < maxTurns && !g_cancel.load(); ++turn) {
        // Build /api/chat body.
        string body = "{\"model\":\"" + model + "\",\"stream\":false,\"keep_alive\":\"10m\",\"options\":{\"temperature\":0,\"seed\":42},\"messages\":[";
        for (size_t i = 0; i < msgs.size(); ++i) {
            if (i) body += ",";
            body += "{\"role\":\"" + msgs[i].first + "\",\"content\":\"" + JsonEscape(msgs[i].second) + "\"}";
        }
        body += "]}";
        bool ok = false;
        string resp = rawrxd::ollama::HttpPost(L"127.0.0.1", 11434, L"/api/chat", body, ok);
        if (!ok || resp.empty()) { printf("[turn %d] transport failure\n", turn); g_tel.toolFail++; break; }
        ++g_tel.requests;
        g_tel.promptTokens += (int)rawrxd::ollama::JsonInt(resp, "\"prompt_eval_count\":");
        g_tel.evalTokens    += (int)rawrxd::ollama::JsonInt(resp, "\"eval_count\":");
        g_tel.promptNs      += (double)rawrxd::ollama::JsonInt(resp, "\"prompt_eval_duration\":");
        g_tel.evalNs        += (double)rawrxd::ollama::JsonInt(resp, "\"eval_duration\":");
        string content = ExtractJsonString(resp, "content");
        string call = FirstJsonObject(content);
        string tool = ExtractJsonString(call, "tool");
        printf("[turn %d] model_tool=%s\n", turn, tool.empty() ? "(none)" : tool.c_str());
        if (tool.empty()) { msgs.push_back({"user", "You must output exactly one JSON tool call."}); continue; }
        ++g_tel.toolCalls;
        // Repeated-action detection: identical tool call 3x => corrective feedback.
        if (!call.empty() && call == lastCall) {
            if (++repeatCount >= 3) {
                msgs.push_back({"user", "You are repeating the IDENTICAL tool call. STOP. Take a different action that advances the objective (write the source, then build)."}); 
                g_tel.corrections++; repeatCount = 0;
                msgs.push_back({"assistant", content});
                continue;
            }
        } else { lastCall = call; repeatCount = 1; }
        string result;
        if (tool == "finish") {
            if (VerifyFunctional()) { finalSummary = ExtractJsonString(call, "summary"); printf("FINISH: %s\n", finalSummary.c_str()); break; }
            ++finishRejects; ++g_tel.corrections;
            printf("  finish REJECTED (#%d) — functional check failed; continue\n", finishRejects);
            msgs.push_back({"assistant", content});
            if (finishRejects >= 3)
                msgs.push_back({"user", "You have claimed completion 3+ times without a working app. Do NOT call finish. Use run to invoke build.cmd (it must call vcvars64.bat first), READ the compiler errors, WRITE a corrected sysmon.cpp that uses GetSystemTimes/GlobalMemoryStatusEx/GetDiskFreeSpaceExW/EnumDisplayDevicesW, and only finish after sysmon.exe launches."});
            else
                msgs.push_back({"user", "Completion rejected: sysmon.cpp must use the Win32 stat APIs, build.cmd must call vcvars64.bat then cl, and sysmon.exe must launch. Continue working."});
            continue;
        }
        else if (tool == "write") {
            string path = ExtractJsonString(call, "path"), content2 = ExtractJsonString(call, "content"), full;
            if (!PathInWs(path, full)) { result = "ERROR: path escapes workspace"; g_tel.toolFail++; }
            else { ofstream f(full, ios::binary); f << content2; result = f.good() ? ("OK wrote " + path + " (" + to_string(content2.size()) + " bytes)") : "ERROR: write failed"; if (f.good()) g_tel.toolOk++; else g_tel.toolFail++; }
        } else if (tool == "run") {
            string cmd = ExtractJsonString(call, "cmd");
            result = RunCmd(cmd);
            if (result.rfind("ERROR", 0) == 0) { g_tel.toolFail++; g_tel.corrections++; } else g_tel.toolOk++;
        } else if (tool == "read") {
            string path = ExtractJsonString(call, "path"), full;
            if (!PathInWs(path, full)) { result = "ERROR: path escapes workspace"; g_tel.toolFail++; }
            else { ifstream f(full); stringstream ss; ss << f.rdbuf(); result = ss.str(); if (result.size() > 4000) result = result.substr(0,4000) + "\n[truncated]"; g_tel.toolOk++; }
        } else if (tool == "list") {
            result = "FILES:\n";
            for (auto& e : std::filesystem::directory_iterator(g_ws)) result += e.path().filename().string() + "\n";
            g_tel.toolOk++;
        } else { result = "ERROR: unknown tool " + tool; g_tel.toolFail++; g_tel.corrections++; }
        printf("  -> %s\n", result.substr(0, 160).c_str());
        msgs.push_back({"assistant", content});
        msgs.push_back({"user", "TOOL_RESULT: " + result});
    }

    double el = NowS() - g_tel.start;
    double prefillTps = g_tel.promptNs > 0 ? g_tel.promptTokens * 1e9 / g_tel.promptNs : 0.0;
    double decodeTps  = g_tel.evalNs > 0 ? g_tel.evalTokens * 1e9 / g_tel.evalNs : 0.0;
    printf("=== TELEMETRY ===\n");
    printf("MODEL=%s BACKEND=Ollama REQUESTS=%d\n", model.c_str(), g_tel.requests);
    printf("PROMPT_TOKENS=%d EVAL_TOKENS=%d PREFILL_TPS=%.2f DECODE_TPS=%.2f\n", g_tel.promptTokens, g_tel.evalTokens, prefillTps, decodeTps);
    printf("TOOL_CALLS=%d TOOL_OK=%d TOOL_FAIL=%d CORRECTIONS=%d\n", g_tel.toolCalls, g_tel.toolOk, g_tel.toolFail, g_tel.corrections);
    printf("ELAPSED_S=%.1f FINISHED=%s\n", el, finalSummary.empty() ? "no" : "yes");
    // Evidence-based completion: a source file exists and an exe was produced.
    bool func = VerifyFunctional();
    printf("EVIDENCE functional=%d\n", (int)func);
    printf("RESULT=%s\n", func ? "PASS" : "INCOMPLETE");
    return func ? 0 : 1;
}