#include "Win32IDE.h"
#include <richedit.h>

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
        "Complete the following code. Return only the completion text, no markdown:");
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
        if (controller->attach(m_hwndMain, surface.hwnd, request, surface.prompt)) {
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
    generateResponseAsync(prompt, std::move(callback));
}

void Win32IDE::appendNativeDebugOutput(const std::string& text, bool error)
{
    appendToOutput(text, "Debug", error ? OutputSeverity::Error : OutputSeverity::Info);
}

