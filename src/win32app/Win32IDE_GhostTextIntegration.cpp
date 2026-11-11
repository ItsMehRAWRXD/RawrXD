#include "Win32IDE.h"
#include <richedit.h>

void Win32IDE::initializeNativeGhostText() {
    if (!m_hwndMain || !m_hwndEditor) return;
    const NativeGhostTextController::Request request =
        [this](const std::string& prompt,
               std::function<void(const std::string&, bool)> callback) {
            if (m_ghostTextMode == GhostTextMode::Disabled) {
                callback("", true);
                return;
            }
            ChatModelEntry route;
            if (m_ghostTextMode == GhostTextMode::Independent) {
                route = m_ghostTextModel;
            } else if (m_ghostTextMode == GhostTextMode::FollowChat) {
                route = m_selectedChatModel;
            } else {
                // Auto Local must use the stable, independently validated
                // local service before attempting an experimental native
                // GGUF route.  The native route remains available through
                // an explicit GhostText model selection, but it must not be
                // selected implicitly while an editor change is in flight.
                // Cloud Kilo is never selected by Auto Local.
                for (const auto& candidate : m_availableModels) {
                    if (candidate.source == ChatModelEntry::Source::Ollama) {
                        route = candidate;
                        break;
                    }
                }
                // Do not silently fall back to a native GGUF route.  The
                // native agent has a separate lifecycle and may be loading a
                // large model or running a tool transaction; using it from a
                // 250 ms GhostText timer can corrupt that lifecycle.  When
                // Ollama is unavailable, GhostText is intentionally inert
                // until the user explicitly selects a certified route.
            }
            if (route.identifier.empty()) {
                logWarning("GhostText", "No eligible GhostText model route is available.");
                callback("", true);
                return;
            }
            if (route.source == ChatModelEntry::Source::KiloFree && !m_allowCloudGhostText) {
                logWarning("GhostText", "Cloud route selected but session cloud consent is disabled.");
                callback("", true);
                return;
            }
            m_pendingInferenceModel = route;
            logInfo("GhostText inference route: " + route.identifier);
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
    bool handled = m_ghostText && m_ghostText->handleMessage(message, wParam, lParam);
    for (auto& controller : m_ghostTextInputs) {
        if (controller) handled = controller->handleMessage(message, wParam, lParam) || handled;
    }
    return handled;
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
    generateResponseAsync(prompt, [this](const std::string& result, bool done) {
        if (!done) return;
        appendNativeDebugOutput("[Codex]\n" + result + "\n");
    });
}

void Win32IDE::requestNativeGhostText(
    const std::string& prompt,
    std::function<void(const std::string&, bool)> callback)
{
    generateResponseAsync(prompt, std::move(callback));
}

void Win32IDE::appendNativeDebugOutput(const std::string& text, bool error)
{
    appendToOutput(text, "Debug", error ? OutputSeverity::Error : OutputSeverity::Info);
}

