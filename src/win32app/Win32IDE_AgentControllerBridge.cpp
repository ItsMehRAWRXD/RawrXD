// Win32IDE_AgentControllerBridge.cpp — A5 native IDE integration.
//
// Routes the IDE agent panel through the SAME shared controller the CLI uses
// (rawr::runAgentController). Inference runs on a worker thread (never the UI
// thread); transcript updates are marshalled back to the UI thread with
// synchronous SendMessage on the transcript edit control.
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "agent/agent_controller.hpp"
#include "rawr_core.hpp"

namespace {
std::atomic<bool> g_agentCancel{false};
std::string g_e2eReceipt;  // when set, worker writes receipt + ExitProcess

void appendToTranscript(HWND h, const std::string& s) {
    if (!h || !IsWindow(h)) return;
    // Move caret to end, then replace selection (append). Synchronous so the
    // worker can return and the string stays valid for the duration.
    SendMessageA(h, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageA(h, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
}
}  // namespace

// A5 E2E: bind a receipt path. When set, the worker writes an execution
// receipt (real tool results + host verdict) and ExitProcess with 0/2.
void RawrXD_IDE_SetE2EReceipt(const char* path) {
    g_e2eReceipt = path ? path : std::string();
}

// Free-function entry so Win32IDE_AgentPanel.cpp does not need a new member.
// transcriptHwnd: the agent transcript edit control. root: workspace root.
void RawrXD_IDE_RunAgenticTask(HWND transcriptHwnd, const std::string& goal,
                               const std::string& root) {
    g_agentCancel = false;
    std::thread([transcriptHwnd, goal, root]() {
        auto log = [transcriptHwnd](const std::string& s) {
            appendToTranscript(transcriptHwnd, s + "\r\n");
        };
        log("[agent] starting task: " + goal);

        rawr::InferenceClient client;
        client.setEndpoint(11434);          // Ollama (ROCm) backend
        // Resolve the model dynamically -- never hardcode an absent model.
        // The IDE sets RAWRXD_AGENT_MODEL from the model dropdown/settings;
        // otherwise fall back to an installed default. An unavailable model is
        // reported explicitly (below), not silently turned into empty inference.
        std::string model;
        if (const char* env = std::getenv("RAWRXD_AGENT_MODEL")) {
            if (*env) model = env;
        }
        if (model.empty()) model = "llama3.2:3b";  // fast, native tool-capable
        client.setModel(model);

        rawr::Workspace ws;
        ws.setRoot(root);
        rawr::ToolRegistry reg;
        registerDefaultTools(reg, ws);

        rawr::AgentConfig cfg;
        cfg.goal = goal;
        cfg.modeName = "code";
        cfg.modeDescription = "IDE agent";
        cfg.sourceEditsAllowed = true;
        cfg.executeByDefault = true;
        cfg.maxTurns = 12;
        cfg.maxTokensPerTurn = 1024;

        auto completeFn = [&client](const std::vector<json>& msgs,
                                    int budget) -> rawr::InferenceResult {
            return client.complete(msgs, budget, 0.2);
        };

        rawr::AgentResult r = rawr::runAgentController(
            completeFn, reg, ws, cfg, log,
            []() { return g_agentCancel.load(); });

        log(std::string("=== verdict: ") +
            (r.completed ? "SUCCESS" : "INCOMPLETE") + " ===\n");
        if (!r.summary.empty()) log(r.summary + "\r\n");

        if (!g_e2eReceipt.empty()) {
            std::ofstream rec(g_e2eReceipt, std::ios::trunc);
            if (rec) {
                rec << "COMPLETED=" << (r.completed ? "PASS" : "FAIL") << "\n";
                if (!r.completed && r.results.empty())
                    rec << "REASON=MODEL_UNAVAILABLE_OR_NO_TOOL_CALL model="
                        << model << "\n";
                rec << "TURNS=" << r.turns << "\n";
                rec << "TOOL_CALLS=" << r.toolCalls << "\n";
                rec << "DENIED=" << r.denied << "\n";
                for (const auto& t : r.results)
                    rec << "TOOL=" << t.tool << " OK=" << (t.ok ? 1 : 0)
                        << " DENIED=" << (t.denied ? 1 : 0)
                        << " EXIT=" << t.exitCode << " ARGS=" << t.args
                        << " OUT=" << t.output.substr(0, 200) << "\n";
                rec << "SUMMARY=" << r.summary << "\n";
            }
            ::ExitProcess(r.completed ? 0u : 2u);
        }
        log("[agent] done.\r\n");
    }).detach();
}