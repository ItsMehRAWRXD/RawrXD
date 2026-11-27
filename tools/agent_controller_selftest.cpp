// Deterministic, model-free tests for the PRODUCTION shared agent controller
// (src/agent/agent_controller.cpp) — the loop used by both the CLI and the IDE.
// The model is replaced by a scripted completeFn; tools are real (write to a temp
// workspace). No network, no model, no Ollama.
//
// Build:
//   cl /nologo /std:c++17 /EHsc /I include /I src \
//      tools\agent_controller_selftest.cpp src\agent\agent_controller.cpp \
//      /Fe:bin\agent_controller_selftest.exe /link winhttp.lib
#include "agent/agent_controller.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

// ── Minimal ToolRegistry method definitions (avoid linking the 70KB rawr_core.cpp).
// Workspace / ModeProfile / ToolContext / InferenceResult are header-inline. ──
namespace rawr {

void ToolRegistry::registerTool(const std::string& name, const std::string& description,
                                const std::string& argsSchema, unsigned requiredCaps,
                                Handler handler) {
    Entry e; e.name = name; e.description = description; e.argsSchema = argsSchema;
    e.caps = requiredCaps; e.handler = std::move(handler);
    tools_[name] = std::move(e);
}

std::vector<std::string> ToolRegistry::names() const {
    std::vector<std::string> v;
    for (const auto& kv : tools_) v.push_back(kv.first);
    return v;
}

const json& ToolRegistry::describe(const std::string& name) const {
    static const json empty = json::object();
    auto it = tools_.find(name);
    if (it == tools_.end()) return empty;
    static thread_local json parsed;
    try { parsed = json::parse(it->second.argsSchema); } catch (...) { parsed = json::object(); }
    return parsed;
}

ToolResult ToolRegistry::dispatch(const std::string& name, const json& args,
                                  const ToolContext& ctx) const {
    ToolResult r; r.tool = name; r.argsJson = args.dump();
    auto it = tools_.find(name);
    if (it == tools_.end()) { r.output = "ERROR: unknown tool " + name; return r; }
    // Capability gate (same contract as production): a mode lacking a required cap is denied.
    if (ctx.mode && (it->second.caps & ctx.mode->caps) != it->second.caps) {
        r.denied = true; r.output = "DENIED: capability"; return r;
    }
    return it->second.handler(args, ctx);
}

}  // namespace rawr

namespace {

int g_fail = 0;
void Expect(const char* name, bool cond) {
    std::printf("[%s] %s\n", cond ? "OK" : "FAIL", name);
    if (!cond) ++g_fail;
}

std::string ReadFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}

// A scripted model: returns canned contents in order, then repeats the last.
struct Script {
    std::vector<rawr::InferenceResult> turns;
    size_t idx = 0;
    std::function<rawr::InferenceResult(const std::vector<json>&, int)> fn() {
        return [this](const std::vector<json>&, int) -> rawr::InferenceResult {
            rawr::InferenceResult r;
            r.ok = true;
            r.content = turns[idx < turns.size() ? idx : turns.size() - 1].content;
            ++idx;
            return r;
        };
    }
};

void RegisterFakeTools(rawr::ToolRegistry& reg) {
    // write_file: real write under the workspace (so completion verification passes).
    reg.registerTool("write_file", "write", "{}", rawr::CAP_WRITE,
        [](const json& a, const rawr::ToolContext& ctx) -> rawr::ToolResult {
            rawr::ToolResult r; r.tool = "write_file"; r.argsJson = a.dump();
            const std::string path = a.value("path", std::string());
            const std::string content = a.value("content", std::string());
            const std::string full = ctx.ws->root() + "/" + path;
            std::ofstream o(full, std::ios::binary); o << content;
            r.ok = o.good(); r.output = r.ok ? "OK wrote " + path : "ERROR: write failed";
            return r;
        });
    // run_build: deterministic success (no real compiler needed).
    reg.registerTool("run_build", "build", "{}", rawr::CAP_EXEC,
        [](const json&, const rawr::ToolContext&) -> rawr::ToolResult {
            rawr::ToolResult r; r.tool = "run_build"; r.ok = true; r.output = "BUILD_OK";
            r.exitCode = 0; return r;
        });
}

rawr::Workspace MakeWs(const std::string& dir) {
    rawr::Workspace ws; ws.setRoot(dir); return ws;
}

// Scenario 1: happy path — write, build, then a truthful final => completed.
bool TestHappyPath() {
    const std::string dir = (std::filesystem::temp_directory_path() /
        "rawr_ctrl_happy").string();
    std::filesystem::create_directories(dir);
    rawr::Workspace ws = MakeWs(dir);
    rawr::ToolRegistry reg; RegisterFakeTools(reg);
    Script s;
    s.turns = {
        {true, false, "{\"action\":\"tool\",\"tool\":\"write_file\",\"args\":{\"path\":\"out.txt\",\"content\":\"hello\"}}"},
        {true, false, "{\"action\":\"tool\",\"tool\":\"run_build\",\"args\":{}}"},
        {true, false, "{\"action\":\"final\",\"summary\":\"created out.txt and built successfully\",\"findings\":[],\"next_actions\":[]}"},
    };
    rawr::AgentConfig cfg; cfg.goal = "create a file out.txt and build it"; cfg.modeName = "code";
    cfg.sourceEditsAllowed = true; cfg.executeByDefault = true; cfg.maxTurns = 6;
    rawr::AgentResult res = rawr::runAgentController(s.fn(), reg, ws, cfg, nullptr, nullptr);
    Expect("happy: completed", res.completed);
    Expect("happy: file written", std::filesystem::exists(std::filesystem::path(dir) / "out.txt"));
    Expect("happy: write+build receipts", res.results.size() >= 2);
    std::filesystem::remove_all(dir);
    return res.completed;
}

// Scenario 2: no tool / no final => bounded no-progress termination (not completed).
bool TestNoProgress() {
    const std::string dir = (std::filesystem::temp_directory_path() /
        "rawr_ctrl_noprogress").string();
    std::filesystem::create_directories(dir);
    rawr::Workspace ws = MakeWs(dir);
    rawr::ToolRegistry reg; RegisterFakeTools(reg);
    Script s;
    s.turns = { {true, false, "I am just chatting with no tool call"} };
    rawr::AgentConfig cfg; cfg.goal = "create a file and build it"; cfg.modeName = "code";
    cfg.maxTurns = 6;
    rawr::AgentResult res = rawr::runAgentController(s.fn(), reg, ws, cfg, nullptr, nullptr);
    Expect("noprogress: not completed", !res.completed);
    Expect("noprogress: no tool results", res.results.empty());
    std::filesystem::remove_all(dir);
    return !res.completed;
}

// Scenario 3: a bare final with no real work => completion REJECTED (not completed).
bool TestCompletionRejected() {
    const std::string dir = (std::filesystem::temp_directory_path() /
        "rawr_ctrl_reject").string();
    std::filesystem::create_directories(dir);
    rawr::Workspace ws = MakeWs(dir);
    rawr::ToolRegistry reg; RegisterFakeTools(reg);
    Script s;
    s.turns = { {true, false, "{\"action\":\"final\",\"summary\":\"all done, created the file\"}"} };
    rawr::AgentConfig cfg; cfg.goal = "create a file and build it"; cfg.modeName = "code";
    cfg.maxTurns = 6;
    rawr::AgentResult res = rawr::runAgentController(s.fn(), reg, ws, cfg, nullptr, nullptr);
    Expect("reject: not completed", !res.completed);
    Expect("reject: no write happened", res.results.empty());
    std::filesystem::remove_all(dir);
    return !res.completed;
}

// Scenario 4: source changed AFTER a successful build => completion REJECTED
// (F04-V17 staleness gate: a build/test receipt is invalid if sources changed).
bool TestStalenessRejected() {
    const std::string dir = (std::filesystem::temp_directory_path() /
        "rawr_ctrl_stale").string();
    std::filesystem::create_directories(dir);
    rawr::Workspace ws = MakeWs(dir);
    rawr::ToolRegistry reg; RegisterFakeTools(reg);
    Script s;
    s.turns = {
        {true, false, "{\"action\":\"tool\",\"tool\":\"write_file\",\"args\":{\"path\":\"a.cpp\",\"content\":\"int x=1;\"}}"},
        {true, false, "{\"action\":\"tool\",\"tool\":\"run_build\",\"args\":{}}"},
        {true, false, "{\"action\":\"tool\",\"tool\":\"write_file\",\"args\":{\"path\":\"a.cpp\",\"content\":\"int x=2;\"}}"},
        {true, false, "{\"action\":\"final\",\"summary\":\"created a.cpp and built it\"}"},
    };
    rawr::AgentConfig cfg; cfg.goal = "create a.cpp and build it"; cfg.modeName = "code";
    cfg.maxTurns = 8;
    rawr::AgentResult res = rawr::runAgentController(s.fn(), reg, ws, cfg, nullptr, nullptr);
    Expect("stale: not completed (source changed after build)", !res.completed);
    std::filesystem::remove_all(dir);
    return !res.completed;
}

}  // namespace

int main() {
    std::printf("=== agent_controller_selftest ===\n");
    TestHappyPath();
    TestNoProgress();
    TestCompletionRejected();
    TestStalenessRejected();
    std::printf("AGENT_CONTROLLER_SELFTEST=%s (%d fail)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}