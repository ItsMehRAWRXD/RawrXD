// Win32IDE_AgentControllerBridge.cpp — A5 native IDE integration.
//
// Routes the IDE agent panel through the SAME shared controller the CLI uses
// (rawr::runAgentController). Inference runs on a worker thread (never the UI
// thread); transcript updates are marshalled back to the UI thread with
// synchronous SendMessage on the transcript edit control.
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "agent/agent_controller.hpp"
#include "rawr_core.hpp"

namespace {
std::atomic<bool> g_agentCancel{false};

void appendToTranscript(HWND h, const std::string& s) {
    if (!h || !IsWindow(h)) return;
    // Move caret to end, then replace selection (append). Synchronous so the
    // worker can return and the string stays valid for the duration.
    SendMessageA(h, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageA(h, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
}
}  // namespace

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
        client.setModel("llama3.2:3b");

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
            (r.completed ? "SUCCESS" : "INCOMPLETE") + " ===");
        if (!r.summary.empty()) log(r.summary);
        log("[agent] done.");
    }).detach();
}