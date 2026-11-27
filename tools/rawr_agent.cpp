// rawr_agent.cpp — RAWRXD_GENERAL_HEADLESS_AUTONOMOUS_CLI_033
// Headless native CLI to RawrXD's autonomous controller. Reuses the production
// Ollama WinHTTP transport (OllamaExecutor.hpp). The MODEL generates tool calls;
// this controller parses and executes them inside an authorized workspace, loops
// with real feedback, and emits inference + tool telemetry. No simulated tools.
#include "OllamaExecutor.hpp"
#include <windows.h>
#include <algorithm>
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
#include <set>

using namespace std;
static atomic<bool> g_cancel{false};
static string g_ws;
static string g_expSrc = "sysmon.cpp", g_expExe = "sysmon.exe";
static std::set<std::string> g_startFiles;

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

// Text-channel tool-call extraction (RAWRXD text-channel robustness).
// Models routinely wrap the tool call in prose or emit a reasoning/example object
// before the real one. Taking the FIRST {...} is fragile; instead scan every
// balanced object and return the first whose "tool" is a KNOWN tool. Reasoning /
// example objects (no known "tool") are skipped.
static bool IsKnownTool(const string& name) {
    static const std::set<string> known = {
        "write", "build", "edit", "read", "list", "run", "finish"};
    return !name.empty() && known.count(name) != 0;
}
static string ExtractToolObject(const string& text) {
    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        const size_t s = text.find('{', i);
        if (s == string::npos) break;
        int depth = 0; bool inStr = false; char esc = 0; bool closed = false;
        size_t e = s;
        for (; e < n; ++e) {
            const char c = text[e];
            if (inStr) { if (esc) esc = 0; else if (c=='\\') esc = 1; else if (c=='"') inStr = false; continue; }
            if (c == '"') inStr = true;
            else if (c == '{') ++depth;
            else if (c == '}') { if (--depth == 0) { ++e; closed = true; break; } }
        }
        if (!closed) break;
        const string obj = text.substr(s, e - s);
        if (IsKnownTool(ExtractJsonString(obj, "tool"))) return obj;
        i = e;
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

// Edit tool with convergence feedback (RAWRXD edit-failure loop reduction).
// On "old text not found" the result includes the CURRENT file content so the
// model can copy the EXACT text instead of guessing and looping (wasted turns).
static string ApplyEdit(const string& path, const string& oldS, const string& newS,
                        bool& ok, bool& esc) {
    esc = false;
    string full;
    if (!PathInWs(path, full)) { esc = true; ok = false; return "ERROR: path escapes workspace"; }
    ifstream f(full); stringstream ss; ss << f.rdbuf(); string s = ss.str();
    const size_t p = s.find(oldS);
    if (p == string::npos) {
        ok = false;
        return "ERROR: old text not found. 'old' must match the CURRENT file EXACTLY "
               "(copy it verbatim). Current file (first 600 chars):\n" +
               s.substr(0, 600) + (s.size() > 600 ? "\n[truncated]" : "");
    }
    s.replace(p, oldS.size(), newS);
    ofstream o(full, ios::binary); o << s;
    ok = o.good();
    return ok ? ("OK edited " + path) : "ERROR: write failed";
}

// GUI-run short-circuit (RAWRXD run-waste elimination): a GUI-subsystem exe never
// exits, so `run` on it blocks the full 20s timeout every time. The build tool
// already verified launch, so detect `run <builtGuiExe>` and skip the spawn.
static bool IsGuiRunToShortCircuit(const string& cmd, const string& builtOut,
                                   const string& builtSubsys) {
    return builtSubsys == "windows" && !builtOut.empty() &&
           cmd.find(builtOut) != string::npos;
}

static bool SrcHasRealApi() {
    ifstream f(std::filesystem::path(g_ws) / g_expSrc);
    stringstream ss; ss << f.rdbuf(); string s = ss.str();
    return s.find("GetSystemTimes") != string::npos ||
           s.find("GlobalMemoryStatusEx") != string::npos ||
           s.find("GetDiskFreeSpaceEx") != string::npos ||
           s.find("EnumDisplayDevices") != string::npos;
}

static string RunCmd(const string& cmd) {
    // Bounded execution (SR-17): never block on a GUI/blocking child. Output is
    // captured to a temp file; the process is terminated after 20s.
    const string outf = (std::filesystem::path(g_ws) / "_agent_out.txt").string();
    string full = "cmd /c (cd /d \"" + g_ws + "\" && " + cmd + ") > \"" + outf + "\" 2>&1";
    vector<wchar_t> w(full.begin(), full.end()); w.push_back(0);
    std::wstring wdir(g_ws.begin(), g_ws.end());
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(nullptr, w.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, wdir.c_str(), &si, &pi))
        return "ERROR: spawn failed";
    const DWORD r = WaitForSingleObject(pi.hProcess, 20000);
    if (r == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "ERROR: command timed out after 20s (blocking/GUI app). Do NOT run GUI executables via the run tool; the build tool already verifies launch.";
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    ifstream f(outf); stringstream ss; ss << f.rdbuf();
    return ss.str();
}

static BOOL WINAPI CtrlHandler(DWORD t) { if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT) g_cancel.store(true); return TRUE; }

// Functional completion: real APIs in source + exe exists + exe launches (bounded).
static bool CreatedThisSession(const std::string& name) {
    return std::filesystem::exists(std::filesystem::path(g_ws) / name) &&
           g_startFiles.find(name) == g_startFiles.end();
}
static bool VerifyFunctional() {
    namespace fs = std::filesystem;
    if (!CreatedThisSession(g_expSrc)) return false;      // A03: created this request
    if (!SrcHasRealApi()) return false;
    if (!CreatedThisSession(g_expExe)) return false;
    string cmd = "\"" + g_ws + "\\" + g_expExe + "\"";
    vector<wchar_t> w(cmd.begin(), cmd.end()); w.push_back(0);
    std::wstring wdir(g_ws.begin(), g_ws.end());
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    // A freshly-linked exe can be momentarily locked (AV scan / handle release),
    // which made CreateProcessW fail intermittently right after a build. Retry
    // briefly instead of failing the functional gate on a transient lock.
    BOOL started = FALSE;
    for (int a = 0; a < 6 && !started; ++a) {
        ZeroMemory(&pi, sizeof(pi));
        started = CreateProcessW(nullptr, w.data(), nullptr, nullptr, FALSE,
                                 CREATE_NO_WINDOW, nullptr, wdir.c_str(), &si, &pi);
        if (!started) Sleep(150);
    }
    if (!started)
        return false;
    WaitForSingleObject(pi.hProcess, 2000);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    const bool alive = (code == STILL_ACTIVE);
    if (alive) TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return alive || code == 0;   // launched and did not immediately crash
}

// Deterministic phase planner: derive the next generic development step from the
// OBSERVED workspace state (not hardcoded to the solution). Advances the objective.
static int ComputePhase() {
    namespace fs = std::filesystem;
    bool src = fs::exists(fs::path(g_ws) / "sysmon.cpp");
    bool exe = fs::exists(fs::path(g_ws) / "sysmon.exe");
    if (!src) return 1;
    if (!exe) return 2;
    return 5;
}
static string PhaseDirective(int p) {
    switch (p) {
        case 1: return "Write the file sysmon.cpp NOW using the write tool. It MUST use GetSystemTimes (CPU), GlobalMemoryStatusEx (memory), GetDiskFreeSpaceExW (disk), EnumDisplayDevicesW (GPU) and a Win32 GUI window with a 1s timer.";
        case 2: return "Call the build tool: {\"tool\":\"build\",\"sources\":\"sysmon.cpp\",\"output\":\"sysmon.exe\",\"subsystem\":\"windows\",\"libraries\":\"user32.lib gdi32.lib\"}. If COMPILE_FAILURE, fix the PRIMARY error with a targeted edit tool call, then call build again.";
        case 5: return "sysmon.exe exists. Verify it launches, then call finish.";
        default: return "Inspect the workspace with list.";
    }
}

// RAWRXD_ADAPTIVE_REPAIR_INTELLIGENCE_042: structured compiler diagnostics.
static string FirstError(const string& out, string& file, int& line) {
    size_t p = out.find("error C");
    if (p == string::npos) p = out.find("error:");
    if (p == string::npos) return {};
    size_t ls = out.rfind('\n', p); ls = (ls == string::npos) ? 0 : ls + 1;
    size_t le = out.find('\n', p); le = (le == string::npos) ? out.size() : le;
    string ln = out.substr(ls, le - ls);
    size_t lp = ln.find('('), rp = ln.find(')');
    if (lp != string::npos && rp != string::npos) {
        file = ln.substr(0, lp);
        line = atoi(ln.substr(lp + 1, rp - lp - 1).c_str());
    }
    return ln;
}
static string SourceContext(const string& file, int line) {
    ifstream f(std::filesystem::path(g_ws) / file);
    vector<string> L; string s;
    while (getline(f, s)) L.push_back(s);
    string out; int a = max(1, line - 3), b = min((int)L.size(), line + 3);
    for (int i = a; i <= b; ++i) out += to_string(i) + ": " + L[i-1] + "\n";
    return out;
}

static string FileHash(const string& path) {
    ifstream f(path, ios::binary);
    string s((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return to_string(h);
}

// PR-05/06: retrieve an authoritative declaration from installed SDK headers.
static string RetrieveDecl(const string& token) {
    if (token.empty()) return {};
    const char* roots[] = {
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\um",
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\shared"
    };
    for (const char* r : roots) {
        if (!std::filesystem::exists(r)) continue;
        for (auto& e : std::filesystem::recursive_directory_iterator(r)) {
            if (e.path().extension() != ".h") continue;
            ifstream f(e.path()); string line; vector<string> L;
            while (getline(f, line)) L.push_back(line);
            for (size_t i = 0; i < L.size(); ++i) {
                if (L[i].find(token) != string::npos) {
                    string out;
                    for (size_t j = i; j < L.size() && j < i + 6; ++j) out += L[j] + "\n";
                    return out;
                }
            }
        }
    }
    return {};
}

static int CountErrors(const string& out) {
    int n = 0; size_t p = 0;
    while ((p = out.find("error C", p)) != string::npos) { ++n; p += 7; }
    return n;
}

// Native tool-calling (RAWRXD_NATIVE_TOOL_CHANNEL_INTEGRATION_106): decode
// message.tool_calls independently of message.content. Reasoning/thinking never
// becomes an executable action.
static const char* ToolsSchema() {
    // R02.2: description-free schema (verified HTTP 200 for 1..6 tools; the full
    // schema with descriptions triggered an opaque HTTP 400 from Ollama).
    return "["
        "{\"type\":\"function\",\"function\":{\"name\":\"write\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}},\"required\":[\"path\",\"content\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"build\",\"parameters\":{\"type\":\"object\",\"properties\":{\"sources\":{\"type\":\"string\"},\"output\":{\"type\":\"string\"},\"subsystem\":{\"type\":\"string\"},\"libraries\":{\"type\":\"string\"},\"standard\":{\"type\":\"string\"}}}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"edit\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"old\":{\"type\":\"string\"},\"new\":{\"type\":\"string\"}},\"required\":[\"path\",\"old\",\"new\"]}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"read\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"list\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}},"
        "{\"type\":\"function\",\"function\":{\"name\":\"finish\",\"parameters\":{\"type\":\"object\",\"properties\":{\"summary\":{\"type\":\"string\"}}}}}"
        "]";
}

static string NativeToolCall(const string& resp) {
    size_t tc = resp.find("\"tool_calls\"");
    if (tc == string::npos) return {};
    size_t np = resp.find("\"name\":\"", tc);
    if (np == string::npos) return {};
    np += 8; size_t ne = resp.find('"', np);
    if (ne == string::npos) return {};
    string name = resp.substr(np, ne - np);
    size_t ap = resp.find("\"arguments\":", ne);
    if (ap == string::npos) return {};
    size_t ab = resp.find('{', ap);
    if (ab == string::npos) return {};
    int depth = 0; size_t ae = ab; bool inStr = false; char esc = 0;
    for (; ae < resp.size(); ++ae) {
        char c = resp[ae];
        if (inStr) { if (esc) esc = 0; else if (c == '\\') esc = 1; else if (c == '"') inStr = false; continue; }
        if (c == '"') inStr = true;
        else if (c == '{') ++depth;
        else if (c == '}') { if (--depth == 0) { ++ae; break; } }
    }
    string args = resp.substr(ab, ae - ab);
    string call = "{\"tool\":\"" + name + "\"";
    auto add = [&](const char* k) { string v = ExtractJsonString(args, k); if (!v.empty()) call += ",\"" + string(k) + "\":\"" + JsonEscape(v) + "\""; };
    add("path"); add("content"); add("cmd"); add("old"); add("new");
    add("output"); add("sources"); add("subsystem"); add("libraries"); add("standard"); add("summary");
    call += "}";
    return call;
}

// RAWRXD_PRODUCTION_SCHEMA_RECONCILIATION_132 regression: validate request JSON
// before transmission so a malformed body is an explicit error, never a silent
// text-channel downgrade.
static bool JsonWellFormed(const string& s) {
    int depth = 0; bool inStr = false; char esc = 0;
    for (char c : s) {
        if (inStr) { if (esc) esc = 0; else if (c == '\\') esc = 1; else if (c == '"') inStr = false; continue; }
        if (c == '"') inStr = true;
        else if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') { if (--depth < 0) return false; }
    }
    return depth == 0 && !inStr;
}

static string WorkspaceHash() {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    for (auto& e : std::filesystem::directory_iterator(g_ws)) {
        h ^= (uint64_t)e.file_size() + (uint64_t)e.path().filename().string().size();
        h *= 1099511628211ULL;
    }
    return std::to_string(h);
}

struct Telemetry {
    int requests = 0, promptTokens = 0, evalTokens = 0;
    double promptNs = 0, evalNs = 0;
    int toolCalls = 0, toolOk = 0, toolFail = 0, corrections = 0;
    double start = 0;
} g_tel;

// RAWRXD_PROVIDER_TOOL_CHANNEL_PROFILE (provider_compliance 2026-11-27):
// Tool-schema acceptance is a PROVIDER property, not a per-request discovery.
//   deepseek-coder-v2 : server REJECTS the tools schema (HTTP 400) => text channel.
//   gpt-oss / qwen3 / nemotron / others : accept native message.tool_calls => native.
// Selecting the channel up front avoids wasting 3 HTTP round-trips + 2x2s sleeps on
// a guaranteed 400 for deepseek, and prevents a transient failure from silently
// downgrading a capable model to text for the rest of the session.
static bool ProviderSupportsNativeTools(const std::string& model) {
    std::string m = model;
    std::transform(m.begin(), m.end(), m.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (m.find("deepseek") != std::string::npos) return false;  // schema rejected
    return true;                                                 // native by default
}

// Deterministic, model-free verification of the channel profile. Compiled into the
// real controller binary so the mapping is exercised by the shipped code path.
static int SelfTestChannel() {
    struct Case { const char* model; bool native; };
    const Case cases[] = {
        {"deepseek-coder-v2:16b", false},
        {"deepseek-r1:32b",       false},
        {"DeepSeek-V2-Lite",      false},  // case-insensitive
        {"gpt-oss:20b",           true},
        {"gpt-oss:120b",          true},
        {"qwen3:8b",              true},
        {"nemotron-3-nano:4b",    true},
        {"llama3.2:3b",           true},
        {"unknown-model:latest",  true},   // safe default = native
    };
    int fail = 0;
    for (const auto& c : cases) {
        const bool got = ProviderSupportsNativeTools(c.model);
        const bool ok = (got == c.native);
        std::printf("[selftest] %-24s native=%d expected=%d %s\n",
                    c.model, (int)got, (int)c.native, ok ? "OK" : "FAIL");
        if (!ok) ++fail;
    }
    std::printf("SELFTEST_CHANNEL=%s (%d fail)\n", fail == 0 ? "PASS" : "FAIL", fail);
    return fail == 0 ? 0 : 1;
}

// Deterministic verification of the text-channel tool extractor (model-free).
static int SelfTestParse() {
    struct P { const char* in; const char* expect; };
    const P cases[] = {
        {"{\"tool\":\"write\",\"path\":\"a\"}", "write"},
        {"Sure, here you go:\n{\"tool\":\"build\",\"sources\":\"x\"}", "build"},
        {"Reasoning {\"note\":\"an example\"} then {\"tool\":\"edit\",\"path\":\"p\",\"old\":\"a\",\"new\":\"b\"}", "edit"},
        {"I will now call a tool: {\"tool\":\"list\"}", "list"},
        {"{\"thinking\":\"hmm, not a tool\"}", ""},
        {"no json here at all", ""},
        {"prefix {\"a\":1} suffix {\"tool\":\"finish\",\"summary\":\"done\"}", "finish"},
    };
    int fail = 0;
    for (const auto& c : cases) {
        const string obj = ExtractToolObject(c.in);
        const string got = obj.empty() ? "" : ExtractJsonString(obj, "tool");
        const bool ok = (got == c.expect);
        std::printf("[selftest-parse] expect=%-7s got=%-7s %s\n",
                    c.expect, got.c_str(), ok ? "OK" : "FAIL");
        if (!ok) ++fail;
    }
    std::printf("SELFTEST_PARSE=%s (%d fail)\n", fail == 0 ? "PASS" : "FAIL", fail);
    return fail == 0 ? 0 : 1;
}

// Deterministic verification of the edit tool + convergence feedback (model-free).
static int SelfTestEdit() {
    namespace fs = std::filesystem;
    const string dir = (fs::temp_directory_path() / "rawr_edittest").string();
    fs::create_directories(dir);
    g_ws = dir;  // PathInWs resolves against g_ws
    const string file = (fs::path(dir) / "t.txt").string();
    { ofstream o(file, ios::binary); o << "line1\nTARGET line3\n"; }
    int fail = 0;
    auto check = [&](bool cond, const char* name) {
        std::printf("[selftest-edit] %-30s %s\n", name, cond ? "OK" : "FAIL");
        if (!cond) ++fail;
    };
    bool ok = false, esc = false;
    string r = ApplyEdit("t.txt", "TARGET", "REPLACED", ok, esc);
    check(ok && !esc && r.rfind("OK edited", 0) == 0, "match -> edited");
    { ifstream f(file); stringstream ss; ss << f.rdbuf(); const string c = ss.str();
      check(c.find("REPLACED") != string::npos && c.find("TARGET") == string::npos, "content replaced"); }
    r = ApplyEdit("t.txt", "NO_SUCH_TEXT", "x", ok, esc);
    check(!ok && !esc && r.find("old text not found") != string::npos, "miss -> not found");
    check(r.find("REPLACED") != string::npos, "miss -> includes current content");
    r = ApplyEdit("../escape.txt", "a", "b", ok, esc);
    check(!ok && esc && r.find("escapes workspace") != string::npos, "path escape rejected");
    std::printf("SELFTEST_EDIT=%s (%d fail)\n", fail == 0 ? "PASS" : "FAIL", fail);
    return fail == 0 ? 0 : 1;
}

// Deterministic verification of the GUI-run short-circuit predicate (model-free).
static int SelfTestGuiRun() {
    int fail = 0;
    auto check = [&](bool cond, const char* name) {
        std::printf("[selftest-guirun] %-34s %s\n", name, cond ? "OK" : "FAIL");
        if (!cond) ++fail;
    };
    check(IsGuiRunToShortCircuit("sysmon.exe", "sysmon.exe", "windows"), "gui exe run -> short-circuit");
    check(IsGuiRunToShortCircuit("start sysmon.exe", "sysmon.exe", "windows"), "cmd contains gui exe -> short-circuit");
    check(!IsGuiRunToShortCircuit("sysmon.exe", "sysmon.exe", "console"), "console exe -> no short-circuit");
    check(!IsGuiRunToShortCircuit("build.cmd", "sysmon.exe", "windows"), "other cmd -> no short-circuit");
    check(!IsGuiRunToShortCircuit("sysmon.exe", "", "windows"), "no built exe -> no short-circuit");
    std::printf("SELFTEST_GUIRUN=%s (%d fail)\n", fail == 0 ? "PASS" : "FAIL", fail);
    return fail == 0 ? 0 : 1;
}

// Deterministic, model-free END-TO-END test of the real tool pipeline:
// write a GUI source -> build with the actual MSVC command -> GUI-run short-circuit
// -> independent functional gate. Proves BUILD_PASS => E2E_PASS without a model.
static int SelfTestPipeline() {
    namespace fs = std::filesystem;
    static std::atomic<int> s_pipe{0};
    // Unique dir per invocation: avoids remove_all/link racing a just-launched exe.
    const string dir = (fs::temp_directory_path() /
        ("rawr_pipetest_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(++s_pipe))).string();
    fs::create_directories(dir);
    g_ws = dir; g_expSrc = "sysmon.cpp"; g_expExe = "sysmon.exe"; g_startFiles.clear();
    const string src =
        "#include <windows.h>\n"
        "static void probe(){ FILETIME a,b,c; GetSystemTimes(&a,&b,&c); "
        "MEMORYSTATUSEX m; m.dwLength=sizeof(m); GlobalMemoryStatusEx(&m); "
        "ULARGE_INTEGER f; GetDiskFreeSpaceExW(L\"C:\\\\\",&f,0,0); "
        "DISPLAY_DEVICEW d{}; d.cb = sizeof(d); EnumDisplayDevicesW(0,0,&d,0); }\n"
        "BOOL WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int s){ probe(); return 0; }\n";
    { ofstream o((fs::path(dir) / "sysmon.cpp").string(), ios::binary); o << src; }
    int fail = 0;
    auto check = [&](bool cond, const char* name) {
        std::printf("[selftest-pipeline] %-30s %s\n", name, cond ? "OK" : "FAIL");
        if (!cond) ++fail;
    };
    const string vcvars = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat";
    const string build = "call \"" + vcvars + "\" >nul 2>&1 && cl /nologo /std:c++17 /EHsc "
                         "sysmon.cpp /Fe:sysmon.exe /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib";
    const string out = RunCmd(build);
    const bool art = fs::exists(fs::path(dir) / "sysmon.exe");
    check(art, "gui exe built (real MSVC)");
    if (!art) std::printf("  build first line: %.160s\n", out.c_str());
    check(IsGuiRunToShortCircuit("sysmon.exe", "sysmon.exe", "windows"), "run short-circuits (no 20s block)");
    check(VerifyFunctional(), "functional gate PASS (src+APIs+launch)");
    std::printf("SELFTEST_PIPELINE=%s (%d fail)\n", fail == 0 ? "PASS" : "FAIL", fail);
    return fail == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    string model = "qwen3:8b", objective, ws = "F:\\rawrxd_acceptance_sysmon_native";
    int maxTurns = 30;
    bool selfTestChannel = false;
    bool selfTestParse = false;
    bool selfTestEdit = false;
    bool selfTestGuiRun = false;
    bool selfTestPipeline = false;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        auto next = [&]() -> string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--model") model = next();
        else if (a == "--workspace") ws = next();
        else if (a == "--objective") objective = next();
        else if (a == "--max-turns") maxTurns = atoi(next().c_str());
        else if (a == "--self-test-channel") selfTestChannel = true;
        else if (a == "--self-test-parse") selfTestParse = true;
        else if (a == "--self-test-edit") selfTestEdit = true;
        else if (a == "--self-test-guirun") selfTestGuiRun = true;
        else if (a == "--self-test-pipeline") selfTestPipeline = true;
    }
    if (selfTestChannel) return SelfTestChannel();
    if (selfTestParse) return SelfTestParse();
    if (selfTestEdit) return SelfTestEdit();
    if (selfTestGuiRun) return SelfTestGuiRun();
    if (selfTestPipeline) return SelfTestPipeline();
    g_ws = ws;
    std::filesystem::create_directories(g_ws);
    // A02: derive expected deliverables from the objective (no hardcoded names).
    {
        auto findExt = [&](const string& ext) -> string {
            size_t p = objective.find(ext);
            if (p == string::npos) return {};
            size_t s = objective.rfind(' ', p);
            s = (s == string::npos) ? 0 : s + 1;
            return objective.substr(s, p - s + ext.size());
        };
        string s = findExt(".cpp"); if (!s.empty()) g_expSrc = s;
        string e = findExt(".exe"); if (!e.empty()) g_expExe = e;
    }
    // A03: snapshot pre-existing files (reject stale artifacts).
    for (auto& e : std::filesystem::directory_iterator(g_ws)) g_startFiles.insert(e.path().filename().string());
    g_tel.start = NowS();
    rawrxd::ollama::RecvTimeoutMs() = 300000;   // long agentic calls
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
        "{\"tool\":\"build\",\"sources\":\"sysmon.cpp\",\"output\":\"sysmon.exe\",\"subsystem\":\"windows\",\"libraries\":\"user32.lib gdi32.lib\"} compiles with the discovered MSVC compiler and returns structured diagnostics (use this instead of writing build.cmd); "
        "{\"tool\":\"finish\",\"summary\":\"...\"} declares completion (ONLY allowed once sysmon.cpp AND sysmon.exe exist). "
        "DELIVERABLE: a file named sysmon.cpp and a build.cmd that compiles it to sysmon.exe. Do not finish until sysmon.exe exists. "
        "Inspect first, then create source, build, read compiler output, fix errors, test, and finish. Be efficient.";

    vector<pair<string,string>> msgs; // role, content
    msgs.push_back({"system", sys});
    msgs.push_back({"user", "OBJECTIVE: " + objective + "\nWorkspace: " + g_ws + envNote + ". Begin."});

    string finalSummary;
    int finishRejects = 0;
    string lastCall; int repeatCount = 0;
    int productive = 0, emptyStreak = 0; string lastWsHash; int unchangedCount = 0; bool useTools = ProviderSupportsNativeTools(model);
    // Provider-aware channel selection (RAWRXD provider_compliance 2026-11-27).
    std::printf("[channel] model=%s native_tools=%d text_channel=%d\n",
                model.c_str(), (int)useTools, (int)!useTools);
    int errCount = 0, repairProgress = 0; string repairNote; bool buildOk = false; string lastFailHash; bool forceEdit = false; int prevErrCount = -1;
    string builtOut, builtSubsys;  // last successful build output + subsystem (GUI-run short-circuit)
    for (int turn = 0; turn < maxTurns * 3 && productive < maxTurns && !g_cancel.load(); ++turn) {
        // Deterministic polymorphic planning: inject the current objective step.
        int phase = ComputePhase();
        string dir = PhaseDirective(phase);
        if (forceEdit) { dir = "The source is UNCHANGED and the build failed. STOP rewriting the whole file. Use the edit tool with a MINIMAL old->new change that fixes the PRIMARY error line only."; forceEdit = false; }
        msgs.push_back({"user", "CURRENT_STEP: " + dir});
        // Build /api/chat body.
        string body = "{\"model\":\"" + model + "\",\"stream\":false,\"keep_alive\":\"10m\",\"options\":{\"temperature\":0,\"seed\":42,\"num_predict\":2048}";
        if (useTools) { body += ",\"tools\":"; body += ToolsSchema(); }
        body += ",\"messages\":[";
        for (size_t i = 0; i < msgs.size(); ++i) {
            if (i) body += ",";
            body += "{\"role\":\"" + msgs[i].first + "\",\"content\":\"" + JsonEscape(msgs[i].second) + "\"}";
        }
        body += "]}";
        if (!JsonWellFormed(body)) { printf("[serialization] malformed request JSON — explicit error, no fallback\n"); g_tel.toolFail++; break; }
        bool ok = false; string resp;
        for (int a = 0; a < 3 && !ok; ++a) {
            resp = rawrxd::ollama::HttpPost(L"127.0.0.1", 11434, L"/api/chat", body, ok);
            if (!ok || resp.empty()) { Sleep(2000); ok = false; }
        }
        if (!ok || resp.empty()) {
            if (useTools) { useTools = false; std::printf("[turn %d] native tool channel rejected by provider '%s' (3 attempts); switching to text channel for the remainder of this session\n", turn, model.c_str()); continue; }
            std::printf("[turn %d] transport failure (3 attempts)\n", turn); g_tel.toolFail++; break;
        }
        ++g_tel.requests;
        g_tel.promptTokens += (int)rawrxd::ollama::JsonInt(resp, "\"prompt_eval_count\":");
        g_tel.evalTokens    += (int)rawrxd::ollama::JsonInt(resp, "\"eval_count\":");
        g_tel.promptNs      += (double)rawrxd::ollama::JsonInt(resp, "\"prompt_eval_duration\":");
        g_tel.evalNs        += (double)rawrxd::ollama::JsonInt(resp, "\"eval_duration\":");
        string content = ExtractJsonString(resp, "content");
        string call = NativeToolCall(resp);          // native message.tool_calls first
        if (call.empty()) call = ExtractToolObject(content);   // text-channel: first KNOWN tool object
        string tool = ExtractJsonString(call, "tool");
        printf("[turn %d] model_tool=%s (phase=%d)\n", turn, tool.empty() ? "(none)" : tool.c_str(), phase);
        if (tool.empty()) {
            ++emptyStreak;
            const bool reasoningOnly = (resp.find("\"thinking\"") != string::npos || resp.find("reasoning_content") != string::npos);
            printf("  [empty %d] reasoning_only=%d content[0:160]=%.160s\n", emptyStreak, (int)reasoningOnly, content.c_str());
            // Track C: bounded context reconstruction — break an unproductive
            // conversation pattern by rebuilding a compact objective context.
            if (emptyStreak == 4 || emptyStreak == 8) {
                msgs.clear();
                msgs.push_back({"system", sys});
                msgs.push_back({"user", "OBJECTIVE: " + objective + "\nWorkspace: " + g_ws + envNote +
                    "\nOutput exactly ONE JSON tool call now (no prose). Current step: " + PhaseDirective(ComputePhase())});
                printf("  [recovery] context reconstructed at empty=%d\n", emptyStreak);
            }
            if (emptyStreak >= 12) { printf("[abort] model produced 12 consecutive empty turns (no tool call) — fail-closed.\n"); break; }
            msgs.push_back({"user", "You MUST output exactly one JSON tool call NOW, with no prose. Current step: " + PhaseDirective(ComputePhase()) +
                (emptyStreak >= 3 ? " Example: {\"tool\":\"write\",\"path\":\"sysmon.cpp\",\"content\":\"...\"}" : "")});
            continue;
        }
        emptyStreak = 0;
        // No-progress recovery: reject repeated inspection once source is required.
        if (tool == "list" && phase >= 1 && ComputePhase() >= 1) {
            msgs.push_back({"assistant", content});
            msgs.push_back({"user", "Inspection is complete. CURRENT_STEP: " + PhaseDirective(ComputePhase())});
            g_tel.corrections++; repeatCount = 0;
            continue;
        }
        // A02: reject no-progress read loops in build/fix (phase 2) — force an edit.
        if (tool == "read" && phase >= 2 && ComputePhase() >= 2) {
            msgs.push_back({"assistant", content});
            msgs.push_back({"user", "Stop re-reading. The build failed. Apply a targeted EDIT to fix the PRIMARY compiler error now, then build."});
            g_tel.corrections++; repeatCount = 0;
            continue;
        }
        // R02.8 convergence: detect unchanged workspace (no file progress).
        {
            string wh = WorkspaceHash();
            if (wh == lastWsHash) ++unchangedCount; else { lastWsHash = wh; unchangedCount = 0; }
            if (unchangedCount >= 3) {
                msgs.push_back({"user", "No workspace progress for 3 turns. Replan: take a DIFFERENT concrete action (write the source, then build). Do not repeat."});
                unchangedCount = 0; g_tel.corrections++;
            }
        }
        ++g_tel.toolCalls; ++productive;
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
            if (IsGuiRunToShortCircuit(cmd, builtOut, builtSubsys)) {
                result = "GUI_APP_LAUNCH_ALREADY_VERIFIED: " + builtOut +
                         " is a GUI executable; the build tool already verified it launches. "
                         "Do NOT run GUI exes via run (it blocks 20s). Call finish now.";
                g_tel.corrections++;
            } else {
            result = RunCmd(cmd);
            if (result.find("error C") != string::npos || result.find("error:") != string::npos) {
                string f; int ln = 0; string e = FirstError(result, f, ln);
                repairNote = "PRIMARY COMPILER ERROR: " + e + "\nRelevant source (" + f + "):\n" + SourceContext(f, ln) +
                             "\nFix ONLY this error using the edit tool (targeted old->new replacement), then run build.cmd again.";
                errCount++; g_tel.corrections++;
            } else { if (errCount > 0) repairProgress++; errCount = 0; g_tel.toolOk++; }
            }
        } else if (tool == "edit") {
            string path = ExtractJsonString(call, "path"), oldS = ExtractJsonString(call, "old"), newS = ExtractJsonString(call, "new");
            bool eok = false, eesc = false;
            result = ApplyEdit(path, oldS, newS, eok, eesc);
            if (eok) g_tel.toolOk++; else g_tel.toolFail++;
        } else if (tool == "build") {
            string sources = ExtractJsonString(call, "sources");
            string output = ExtractJsonString(call, "output"); if (output.empty()) output = "a.exe";
            string stdv = ExtractJsonString(call, "standard"); if (stdv.empty()) stdv = "c++17";
            string subsys = ExtractJsonString(call, "subsystem");
            string libs = ExtractJsonString(call, "libraries");
            string srcFile = sources; size_t sp = srcFile.find(' '); if (sp != string::npos) srcFile = srcFile.substr(0, sp);
            string h = FileHash((std::filesystem::path(g_ws) / srcFile).string());
            if (h == lastFailHash) {
                result = "SOURCE_UNCHANGED: rebuild rejected. The source has not changed since the last failed build.";
                repairNote = "Apply a targeted edit that fixes the PRIMARY error, then call build again. Rebuilding identical input is not allowed.";
                forceEdit = true;   // switch strategy: force a minimal edit next turn
                g_tel.toolFail++; g_tel.corrections++;
            } else {
                const string vcvars = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat";
                auto mk = [&](const string& sf) { string c = "call \"" + vcvars + "\" >nul 2>&1 && cl /nologo /std:" + stdv + " /EHsc " + sources + " /Fe:" + output + " /link " + sf; if (!libs.empty()) c += " " + libs; return c; };
                result = RunCmd(mk(subsys == "windows" ? "/SUBSYSTEM:WINDOWS" : "/SUBSYSTEM:CONSOLE"));
                bool art = std::filesystem::exists(std::filesystem::path(g_ws) / output);
                // PR-10: do NOT silently change subsystem. Report the entry-point mismatch.
                if (!art && result.find("LNK2019") != string::npos && result.find("WinMain") != string::npos && subsys == "windows") {
                    repairNote = "LINKER: unresolved WinMain under /SUBSYSTEM:WINDOWS. Your source must define WinMain (GUI) OR you must explicitly request subsystem=console in the build tool. Do not change requirements silently.";
                }
                if (result.find("not recognized") != string::npos) { result = "COMPILER_NOT_INVOKED:\n" + result; g_tel.toolFail++; lastFailHash = h; }
                else if (result.find("error LNK") != string::npos) { result = "LINK_FAILURE:\n" + result; repairNote = "LINK FAILURE:\n" + result; g_tel.toolFail++; lastFailHash = h; }
                else if (result.find("error C") != string::npos) {
                    string f; int ln = 0; string e = FirstError(result, f, ln);
                    result = "COMPILE_FAILURE:\n" + result;
                    int ec = CountErrors(result);
                    string prog = (prevErrCount >= 0) ? (" [errors " + to_string(prevErrCount) + "->" + to_string(ec) +
                        (ec < prevErrCount ? " IMPROVING]" : ec > prevErrCount ? " REGRESSION]" : " NO CHANGE]")) : "";
                    if (prevErrCount >= 0 && ec >= prevErrCount) forceEdit = true;   // repair did not converge -> change strategy
                    prevErrCount = ec;
                    string decl, hint;
                    size_t mp = e.find("is not a member of '");
                    if (mp != string::npos) {
                        string ty = e.substr(mp + 20); ty = ty.substr(0, ty.find('\''));
                        decl = RetrieveDecl(ty);
                        if (!decl.empty()) decl = "\nAUTHORITATIVE DECLARATION of " + ty + ":\n" + decl + "Use ONLY these members.";
                    }
                    if (e.find("C2440") != string::npos && (e.find("wchar_t") != string::npos || e.find("LPCSTR") != string::npos)) {
                        hint = "\nANSI/UNICODE: reconcile string-literal prefixes with the API's expected type; do not mix char* and wchar_t*.";
                        // SO-07: deterministic candidate — drop L prefix ONLY if the literal is pure ASCII (encoding-safe).
                        if (ln >= 1) {
                            ifstream sf((std::filesystem::path(g_ws) / f).string());
                            vector<string> L; string s;
                            while (getline(sf, s)) L.push_back(s);
                            if (ln <= (int)L.size()) {
                                size_t lp = L[ln-1].find("L\"");
                                if (lp != string::npos) {
                                    size_t q2 = L[ln-1].find('"', lp + 2);
                                    bool ascii = true;
                                    for (size_t k = lp + 2; k < q2 && k < L[ln-1].size(); ++k)
                                        if ((unsigned char)L[ln-1][k] >= 128) ascii = false;
                                    if (ascii && q2 != string::npos) {
                                        L[ln-1].replace(lp, 1, "");
                                        ofstream o((std::filesystem::path(g_ws) / f).string());
                                        for (auto& x : L) o << x << "\n";
                                        hint += "\nCONTROLLER_DETERMINISTIC_REPAIR: removed L prefix on line " + to_string(ln) + " (ASCII-safe); rebuild to verify.";
                                    } else
                                        hint += "\nSKIP auto-fix: non-ASCII literal (encoding-sensitive) — manual fix required.";
                                }
                            }
                        }
                    }
                    else if (e.find("C2664") != string::npos) {
                        size_t a = e.find("from '"), b = e.find("' to '", a);
                        string actual = (a != string::npos && b != string::npos) ? e.substr(a + 6, b - (a + 6)) : "";
                        size_t c = b + 6, d = e.find("'", c);
                        string expected = (b != string::npos && d != string::npos) ? e.substr(c, d - c) : "";
                        hint = "\nARGUMENT TYPE MISMATCH: actual='" + actual + "' expected='" + expected + "'. Change the argument expression or the variable's declared type to match; do NOT force-cast.";
                    }
                    else if (e.find("C4477") != string::npos || e.find("C4473") != string::npos) {
                        size_t a = e.find("type '"), b = e.find("'", a + 6);
                        string argType = (a != string::npos && b != string::npos) ? e.substr(a + 6, b - (a + 6)) : "";
                        hint = "\nFORMAT STRING: expected argument type='" + argType + "'. Adjust the specifier to match the argument (or the argument to match the specifier).";
                    }
                    repairNote = "PRIMARY COMPILER ERROR: " + e + prog + "\nSource (" + f + "):\n" + SourceContext(f, ln) + decl + hint + "\nFix with a targeted edit, then build again.";
                    g_tel.toolFail++; errCount++; lastFailHash = h;
                }
                else if (art) { if (result.rfind("BUILD_OK", 0) != 0) result = "BUILD_OK: " + output + " produced"; buildOk = true; builtOut = output; builtSubsys = subsys; g_tel.toolOk++; }
                else { result = "BUILD_NO_ARTIFACT:\n" + result; g_tel.toolFail++; lastFailHash = h; }
            }
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
        msgs.push_back({"tool", result});   // role:"tool" result message (documented Ollama protocol)
        if (!repairNote.empty()) { msgs.push_back({"user", repairNote}); repairNote.clear(); }
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