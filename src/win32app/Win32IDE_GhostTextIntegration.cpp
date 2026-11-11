#include "Win32IDE.h"
#include "RequestACtrlDiag.hpp"
#include <richedit.h>
#include "../backend/ollama_client.h"

void Win32IDE::initializeNativeGhostText() {
    if (!m_hwndMain || !m_hwndEditor) return;
    const NativeGhostTextController::Request request =
        [this](const std::string& prompt,
               std::function<void(const std::string&, bool, bool)> callback) {
            if (m_ghostTextMode == GhostTextMode::Disabled) {
                callback("", true, false);
                return;
            }
            ChatModelEntry route;
            if (m_ghostTextMode == GhostTextMode::Independent) {
                // The independent selector stores an identifier across async
                // catalog refreshes. Resolve it against the current catalog
                // before dispatching so a stale row can never silently fall
                // back to another model.
                const auto found = std::find_if(
                    m_availableModels.begin(), m_availableModels.end(),
                    [this](const ChatModelEntry& candidate) {
                        return candidate.source == m_ghostTextModel.source &&
                            candidate.identifier == m_ghostTextModel.identifier &&
                            !candidate.identifier.empty();
                    });
                if (found == m_availableModels.end()) {
                    logWarning("GhostText", "Selected GhostText model is no longer available; request rejected.");
                    callback("", true, false);
                    return;
                }
                route = *found;
            } else if (m_ghostTextMode == GhostTextMode::FollowChat) {
                route = m_selectedChatModel;
            } else {
                // Auto Local follows the currently selected chat model when
                // it is an Ollama route.  Previously it always chose the
                // first catalog row, which pinned every completion to the
                // discovery-order default (often
                // bigdaddyg-productivity-local:latest) even after the user
                // selected GPT-OSS or Nemotron in the model selector.
                if (m_selectedChatModel.source == ChatModelEntry::Source::Ollama &&
                    !m_selectedChatModel.identifier.empty()) {
                    route = m_selectedChatModel;
                } else {
                    // If chat is on a native GGUF or cloud route, choose the
                    // first currently available Ollama model. Never invent a
                    // model ID and never silently use a stale entry.
                    for (const auto& candidate : m_availableModels) {
                        if (candidate.source == ChatModelEntry::Source::Ollama &&
                            !candidate.identifier.empty()) {
                            route = candidate;
                            break;
                        }
                    }
                }
            }
            if (route.identifier.empty()) {
                logWarning("GhostText", "No eligible GhostText model route is available.");
                callback("", true, false);
                return;
            }
            if (route.source == ChatModelEntry::Source::KiloFree && !m_allowCloudGhostText) {
                logWarning("GhostText", "Cloud route selected but session cloud consent is disabled.");
                callback("", true, false);
                return;
            }
            m_pendingInferenceModel = route;
            const char* backend = route.source == ChatModelEntry::Source::Ollama
                ? "ollama" : (route.source == ChatModelEntry::Source::LocalFile
                    ? "native" : "cloud");
            logInfo("GhostText inference route: " + route.identifier +
                    " backend=" + backend);
            requestNativeGhostText(prompt, std::move(callback));
        };

    if (!m_ghostText) m_ghostText = std::make_unique<NativeGhostTextController>();
    const bool attached = m_ghostText->attach(
        m_hwndMain, m_hwndEditor, request,
        "Complete the following code. Return only the completion text, no markdown:",
        [this](const std::string& event) {
            // Controller traces are emitted only from the UI message/timer
            // path; keeping this sink on the UI thread avoids racing the
            // native output controls while preserving raw lifecycle evidence.
            appendNativeDebugOutput("[GhostText] " + event + "\n");
        });
    appendNativeDebugOutput(std::string("[GhostText] native controller ") +
                            (attached ? "READY\n" : "FAILED\n"), !attached);

    // GhostText is useful on every native text-entry surface, not only the
    // code editor. Each surface gets its own controller so its snapshot,
    // timer, cancellation generation, and inline hint cannot interfere with
    // another input or chat session.
    m_ghostTextInputs.clear();
    struct InputSurface { HWND hwnd; const char* prompt; };
    const InputSurface surfaces[] = {
        {m_hwndCopilotChatInput,
         "Suggest a helpful continuation to the following user message. Return only the completion text, no markdown:"},
        {m_hwndPowerShellInput,
         "Complete the following PowerShell command. Return only the command continuation, no markdown:"},
        {m_hwndCommandInput,
         "Suggest the next part of this RawrXD command. Return only the continuation, no markdown:"},
        {m_hwndSearchInput,
         "Complete the following search query. Return only the query continuation, no markdown:"},
        {m_hwndIncludePattern,
         "Complete the following file include pattern. Return only the continuation, no markdown:"},
        {m_hwndExcludePattern,
         "Complete the following file exclude pattern. Return only the continuation, no markdown:"},
        {m_hwndSCMMessageBox,
         "Suggest a concise Git commit message for the following text. Return only the continuation, no markdown:"},
        {m_hwndDebuggerInput,
         "Complete the following debugger command or expression. Return only the continuation, no markdown:"},
        {m_hwndExtensionSearch,
         "Complete the following extension search query. Return only the continuation, no markdown:"}
        , {m_hwndFindInput,
           "Complete the following find query. Return only the continuation, no markdown:"}
        , {m_hwndReplaceInput,
           "Complete the following replacement text. Return only the continuation, no markdown:"}
    };
    for (const auto& surface : surfaces) {
        if (!surface.hwnd || surface.hwnd == m_hwndEditor) continue;
        auto controller = std::make_unique<NativeGhostTextController>();
        if (controller->attach(m_hwndMain, surface.hwnd, request, surface.prompt,
                               [this](const std::string& event) {
                                   appendNativeDebugOutput("[GhostText] " + event + "\n");
                               })) {
            m_ghostTextInputs.push_back(std::move(controller));
        }
    }
    appendNativeDebugOutput("[GhostText] attached input surfaces=" +
                            std::to_string(m_ghostTextInputs.size()) + "\n");
}

bool Win32IDE::handleNativeGhostTextMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    if (m_ghostText && m_ghostText->ownsMessage(message, lParam)) {
        return m_ghostText->handleMessage(message, wParam, lParam);
    }
    for (auto& controller : m_ghostTextInputs) {
        if (controller && controller->ownsMessage(message, lParam)) {
            return controller->handleMessage(message, wParam, lParam);
        }
    }
    if (message == WM_APP + 73) {
        NativeGhostTextController::discardMessage(message, lParam);
        return true;
    }
    return false;
}

void Win32IDE::invalidateNativeGhostText() {
    m_pendingInferenceModel = {};
    if (m_ghostText) m_ghostText->dismiss();
    for (auto& controller : m_ghostTextInputs) {
        if (controller) controller->dismiss();
    }
}

void Win32IDE::pauseNativeGhostTextAdmission(bool paused) {
    if (m_ghostText) m_ghostText->setAdmissionPaused(paused);
    for (auto& controller : m_ghostTextInputs) {
        if (controller) controller->setAdmissionPaused(paused);
    }
    // KillTimer does not dequeue an already-posted WM_TIMER. Drain only
    // kGhostTimer=0x5247 from GhostText surfaces; leave caret/other timers.
    if (paused) {
        auto drainGhostTimer = [](HWND hwnd) {
            if (!hwnd || !IsWindow(hwnd)) return;
            for (;;) {
                MSG msg{};
                if (!PeekMessageA(&msg, hwnd, WM_TIMER, WM_TIMER, PM_NOREMOVE)) {
                    break;
                }
                if (msg.wParam != 0x5247) break;
                PeekMessageA(&msg, hwnd, WM_TIMER, WM_TIMER, PM_REMOVE);
            }
        };
        if (m_hwndEditor) drainGhostTimer(m_hwndEditor);
        if (m_hwndCopilotChatInput) drainGhostTimer(m_hwndCopilotChatInput);
        if (m_hwndPowerShellInput) drainGhostTimer(m_hwndPowerShellInput);
        if (m_hwndCommandInput) drainGhostTimer(m_hwndCommandInput);
        if (m_hwndSearchInput) drainGhostTimer(m_hwndSearchInput);
        if (m_hwndIncludePattern) drainGhostTimer(m_hwndIncludePattern);
        if (m_hwndExcludePattern) drainGhostTimer(m_hwndExcludePattern);
        if (m_hwndSCMMessageBox) drainGhostTimer(m_hwndSCMMessageBox);
        if (m_hwndDebuggerInput) drainGhostTimer(m_hwndDebuggerInput);
        if (m_hwndExtensionSearch) drainGhostTimer(m_hwndExtensionSearch);
        if (m_hwndFindInput) drainGhostTimer(m_hwndFindInput);
        if (m_hwndReplaceInput) drainGhostTimer(m_hwndReplaceInput);
    }
}

void Win32IDE::detachNativeGhostTextInputs() {
    // Destructor → detach() restores the original EDIT WndProc so Request A
    // Send/Stop cannot CallWindowProc into comctl32 via editorProc.
    rawrxd::request_a_diag::event("REQA_DETACH_GHOSTTEXT_ENTER", m_hwndCopilotChatInput);
    pauseNativeGhostTextAdmission(true);
    if (m_ghostText) {
        m_ghostText->detach();
        m_ghostText.reset();
    }
    m_ghostTextInputs.clear();
    rawrxd::request_a_diag::event("REQA_DETACH_GHOSTTEXT_EXIT", m_hwndCopilotChatInput);
}

void Win32IDE::notifyGhostTextInputChanged(HWND input) {
    if (!input) return;
    if (m_ghostText && m_ghostText->attachedTo(input)) {
        m_ghostText->onEditorChanged();
        return;
    }
    for (auto& controller : m_ghostTextInputs) {
        if (controller && controller->attachedTo(input)) {
            controller->onEditorChanged();
            return;
        }
    }
}

void Win32IDE::runNativeCodexPrompt(const std::string& prompt) {
    if (prompt.empty()) {
        appendNativeDebugOutput("[Codex] select or enter code first.\n");
        return;
    }
    generateResponseAsync(prompt, [this](const std::string& result, bool done, bool) {
        if (!done) return;
        appendNativeDebugOutput("[Codex]\n" + result + "\n");
    });
}

void Win32IDE::requestNativeGhostText(
    const std::string& prompt,
    std::function<void(const std::string&, bool, bool)> callback)
{
    // GhostText requests are independently fenced by the controller. Allow a
    // newer request to run while an older one is still in flight; the older
    // response is discarded by generation/identity checks on the UI thread.
    const ChatModelEntry ghostRoute =
        std::exchange(m_pendingInferenceModel, ChatModelEntry{});
    if (ghostRoute.source == ChatModelEntry::Source::Ollama &&
        !ghostRoute.identifier.empty()) {
        static std::atomic<uint64_t> nextGhostRuntimeRequest{1};
        const uint64_t requestId = nextGhostRuntimeRequest.fetch_add(
            1, std::memory_order_relaxed);
        const std::string baseUrl = m_ollamaBaseUrl;
        const int maxTokens = effectiveMaxTokensForPrompt(prompt);
        const int contextTokens = m_currentContextTokens;
        const ReasoningMode reasoningMode = m_reasoningMode;
        std::thread([baseUrl, model = ghostRoute.identifier, prompt,
                     maxTokens, contextTokens, reasoningMode,
                     requestId, callback = std::move(callback)]() mutable {
            try {
                (void)reasoningMode;
                const std::string started =
                    "[GHOSTTEXT_RUNTIME] request_started request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " backend=ollama\n";
                OutputDebugStringA(started.c_str());
                RawrXD::Backend::OllamaGenerateRequest request;
                request.model = model;
                request.prompt = prompt;
                request.stream = false;
                request.options["num_predict"] = std::to_string(maxTokens);
                request.options["num_ctx"] = std::to_string(contextTokens);
                RawrXD::Backend::OllamaClient client(baseUrl);
                client.setTimeoutSeconds(120);
                const RawrXD::Backend::OllamaResponse result = client.generateSync(request);
                const std::string response = result.response.empty()
                    ? result.message : result.response;
                const std::string completed =
                    "[GHOSTTEXT_RUNTIME] response request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " success=" + (response.empty() ? "0" : "1") + "\n";
                OutputDebugStringA(completed.c_str());
                if (callback) callback(response, true, !response.empty());
            } catch (...) {
                const std::string failed =
                    "[GHOSTTEXT_RUNTIME] response request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " success=0\n";
                OutputDebugStringA(failed.c_str());
                if (callback) callback("", true, false);
            }
        }).detach();
        return;
    }
    generateResponseAsync(prompt, std::move(callback));
}

void Win32IDE::appendNativeDebugOutput(const std::string& text, bool error)
{
    appendToOutput(text, "Debug", error ? OutputSeverity::Error : OutputSeverity::Info);
}

