// Win32IDE_AgenticBridge.cpp — wires Deep2 agentic engine to IDE UI
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdio>
#include "Win32IDE_ChatPanel.h"

namespace RawrXD::IDE {

// ── Forward declarations ──────────────────────────────────────────────────────
void StreamingUX_Begin(const std::string& modelName);
void StreamingUX_Token(const std::string& token);
void StreamingUX_End();
void StreamingUX_Cancel();
bool StreamingUX_IsCancelled();

// ── Bridge state ──────────────────────────────────────────────────────────────
static std::atomic<bool>  g_running{false};
static std::thread        g_workerThread;
static std::string        g_modelPath;
static std::string        g_pendingPrompt;
static HWND               g_notifyWnd = nullptr;

#define WM_AGENT_TOKEN    (WM_APP + 200)
#define WM_AGENT_DONE     (WM_APP + 201)
#define WM_AGENT_ERROR    (WM_APP + 202)

void AgenticBridge_Init(HWND notifyWnd, const std::string& modelPath)
{
    g_notifyWnd = notifyWnd;
    g_modelPath = modelPath;
}

void AgenticBridge_SetModel(const std::string& path) { g_modelPath = path; }

bool AgenticBridge_IsRunning() { return g_running.load(); }

void AgenticBridge_Cancel()
{
    StreamingUX_Cancel();
    g_running.store(false);
}

// ── Submit a prompt — runs inference on a background thread ──────────────────
void AgenticBridge_Submit(const std::string& prompt)
{
    if (g_running.load()) return;
    g_running.store(true);
    g_pendingPrompt = prompt;

    StreamingUX_Begin(g_modelPath.empty() ? "local" : g_modelPath);

    g_workerThread = std::thread([prompt]() {
        // Try to use the real Deep2 agentic gate if a model is configured.
        // If no model is present, emit a diagnostic response so the UI is live.
        if (g_modelPath.empty()) {
            // No model configured — emit a helpful message token by token
            std::string resp =
                "No model loaded. Set RAWRXD_AGENT_MODEL or use Model > Local Inference Test "
                "to configure a GGUF model path. Once loaded, I can answer questions, "
                "read files, edit code, and run agentic loops end-to-end.";
            for (char c : resp) {
                if (StreamingUX_IsCancelled()) break;
                StreamingUX_Token(std::string(1, c));
                Sleep(2);
            }
        } else {
            // RAWRXD_AGENTIC_BRIDGE_NO_FAKE_OUTPUT_001
            //
            // This branch used to fabricate agent output:
            //
            //   // For now emit a live echo so the UI pipeline is exercised end-to-end.
            //   std::string resp = "[Agent] Prompt received: " + prompt + "\n"
            //       "[Agent] Model: " + g_modelPath + "\n"
            //       "[Agent] Invoking Deep2 engine...\n";
            //
            // It typed that literal one character at a time with Sleep(1) and
            // never invoked inference, so the UI showed agent text that the
            // model never produced. That is exactly the synthetic-output class
            // the receipt gates forbid, so it is removed rather than patched.
            //
            // This bridge holds no Deep2Engine handle -- g_modelPath is a path,
            // not an engine, and the live engine is the file-static
            // g_chatEngine owned by main_win32.cpp:435. Streaming real tokens
            // here would require a second engine and double inference.
            //
            // The real stream is Deep2Engine::generateStream driven from
            // chatWorkerThread (main_win32.cpp), routed through the agentic
            // pipeline: StreamingInferenceEngine -> StreamingResultChannel ->
            // AgenticModelStreamerBridge -> AgentToolAuthority, orchestrated by
            // BP1BraidStreamer::runSession. See ide_agentic_gate.cpp:217-263
            // for the working reference wiring.
            //
            // Fail closed: say the bridge is unbound rather than invent output.
            const std::string note =
                "[Agent] Bridge has no engine binding; it will not fabricate output. "
                "Use the chat panel (chatWorkerThread) for real streaming.";
            StreamingUX_Token(note);
        }

        StreamingUX_End();
        g_running.store(false);

        if (g_notifyWnd)
            PostMessage(g_notifyWnd, WM_AGENT_DONE, 0, 0);
    });
    g_workerThread.detach();
}

// ── Tool result injection ─────────────────────────────────────────────────────
void AgenticBridge_InjectToolResult(const std::string& toolName, const std::string& result)
{
    std::string msg = "[Tool:" + toolName + "] " + result;
    ChatPanel_AddMessage(MsgRole::Tool, msg);
}

} // namespace RawrXD::IDE
