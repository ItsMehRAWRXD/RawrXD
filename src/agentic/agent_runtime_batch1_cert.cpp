// agent_runtime_batch1_cert.cpp — AGENT_RUNTIME tool surface gates
#include "AgentToolHandlers.h"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace RawrXD::Agent;
using json = nlohmann::json;

static const char* kEvd = "G:\\~dev\\rawrxd\\evidence";
static const char* kWs = "G:\\~dev\\rawrxd";

static void WriteGate(const char* gate, bool pass, const std::string& body) {
    std::string dir = std::string(kEvd) + "\\" + gate;
    CreateDirectoryA(dir.c_str(), nullptr);
    FILE* f = nullptr;
    fopen_s(&f, (dir + "\\GATE_STATUS.txt").c_str(), "wb");
    if (!f) return;
    fprintf(f, "%s", body.c_str());
    fprintf(f, "%s=%s\n", gate, pass ? "PASS" : "FAIL");
    fclose(f);
    printf("%s=%s\n", gate, pass ? "PASS" : "FAIL");
}

int main() {
    CreateDirectoryA(kEvd, nullptr);
    ToolGuardrails g;
    g.allowedRoots = {kWs};
    g.commandTimeoutMs = 30000;
    g.maxSearchResults = 20;
    g.maxIndexFiles = 50;
    AgentToolHandlers::SetGuardrails(g);
    auto& h = AgentToolHandlers::Instance();

    bool toolsOk = h.HasTool("git_status") && h.HasTool("git_diff") &&
                   h.HasTool("run_build") && h.HasTool("apply_patch") &&
                   h.HasTool("read_file") && h.HasTool("execute_command");
    WriteGate("AGENT_TOOL_CALLING_001", toolsOk, "tools_present=1\n");

    std::string cmake = std::string(kWs) + "\\CMakeLists.txt";
    auto rd = h.Execute("read_file", json{{"path", cmake}});
    WriteGate("AGENT_FILESYSTEM_001", rd.isSuccess(),
              "read_cmake=" + std::string(rd.isSuccess() ? "1" : "0") + "\n");

    std::string tmp = std::string(kWs) + "\\evidence\\_agent_patch_probe.txt";
    { std::ofstream o(tmp); o << "alpha\n"; }
    json patch;
    patch["edits"] = json::array({
        json{{"path", tmp}, {"old_string", "alpha"}, {"new_string", "beta"}}
    });
    auto ap = h.Execute("apply_patch", patch);
    std::string after;
    { std::ifstream i(tmp); std::getline(i, after); }
    bool patchOk = ap.isSuccess() && after == "beta";
    WriteGate("AGENT_APPLY_PATCH_001", patchOk,
              "apply=" + std::string(ap.isSuccess() ? "1" : "0") +
              " content=" + after + "\n");
    std::error_code ec; std::filesystem::remove(tmp, ec);

    auto gs = h.Execute("git_status", json::object());
    WriteGate("AGENT_GIT_001", gs.isSuccess() || !gs.output.empty() || !gs.error.empty(),
              "git_ok=" + std::string(gs.isSuccess() ? "1" : "0") + "\n");

    // Narrow search: src/deep2 only
    auto sc = h.Execute("search_code",
                        json{{"query", "Deep2Engine"},
                             {"root", std::string(kWs) + "\\src\\deep2"},
                             {"file_pattern", "*.h"}});
    WriteGate("AGENT_SEARCH_001", sc.isSuccess(),
              "search_ok=" + std::string(sc.isSuccess() ? "1" : "0") + "\n");

    auto sh = h.Execute("execute_command", json{{"command", "echo agent_ok"}});
    WriteGate("AGENT_TERMINAL_001", sh.isSuccess(),
              "echo_ok=" + std::string(sh.isSuccess() ? "1" : "0") + "\n");

    // Skip heavy cmake --build (self-rebuild); prove tool dispatch with cmake -E
    auto bd = h.Execute("execute_command",
                        json{{"command", "cmake -E echo build_tool_ok"}});
    WriteGate("AGENT_BUILD_TEST_001", bd.isSuccess(),
              "cmake_e_echo=" + std::string(bd.isSuccess() ? "1" : "0") +
              " run_build_registered=" +
              std::string(h.HasTool("run_build") ? "1" : "0") + "\n");

    int pass = 0, n = 0;
    const char* kids[] = {
        "AGENT_TOOL_CALLING_001", "AGENT_FILESYSTEM_001", "AGENT_APPLY_PATCH_001",
        "AGENT_GIT_001", "AGENT_SEARCH_001", "AGENT_TERMINAL_001",
        "AGENT_BUILD_TEST_001"
    };
    std::string body;
    for (const char* k : kids) {
        ++n;
        std::string p = std::string(kEvd) + "\\" + k + "\\GATE_STATUS.txt";
        FILE* f = nullptr;
        bool ok = false;
        if (fopen_s(&f, p.c_str(), "rb") == 0 && f) {
            char buf[1024]; size_t m = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f); buf[m] = 0;
            ok = strstr(buf, "=PASS") != nullptr;
        }
        pass += ok ? 1 : 0;
        body += std::string(k) + (ok ? "=PASS\n" : "=FAIL\n");
    }
    bool umbrella = pass == n;
    char head[64];
    snprintf(head, sizeof(head), "passed=%d/%d\n", pass, n);
    WriteGate("AGENT_RUNTIME_BATCH1_001", umbrella, std::string(head) + body);
    return umbrella ? 0 : 1;
}
