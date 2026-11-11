#include "Win32IDE.h"
#include <richedit.h>

void Win32IDE::initializeNativeGhostText() {
    if (!m_hwndMain || !m_hwndEditor) return;
    if (!m_ghostText) m_ghostText = std::make_unique<NativeGhostTextController>();
    const bool attached = m_ghostText->attach(m_hwndMain, m_hwndEditor,
        [this](const std::string& prompt, std::function<void(const std::string&, bool)> callback) {
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
                // Prefer a validated native GGUF/blob route, then use the
                // local Ollama service. Both remain local; cloud Kilo is
                // never selected by Auto Local.
                for (size_t i = 0; i < m_availableModels.size(); ++i) {
                    const auto& candidate = m_availableModels[i];
                    if (candidate.source != ChatModelEntry::Source::LocalFile) continue;
                    route = candidate;
                    break;
                }
                if (route.identifier.empty()) {
                    for (const auto& candidate : m_availableModels) {
                        if (candidate.source == ChatModelEntry::Source::Ollama) {
                            route = candidate;
                            break;
                        }
                    }
                }
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
            generateResponseAsync(prompt, std::move(callback));
        });
    appendToOutput(std::string("[GhostText] native controller ") + (attached ? "READY\n" : "FAILED\n"),
                   "Debug", attached ? OutputSeverity::Info : OutputSeverity::Error);
}

bool Win32IDE::handleNativeGhostTextMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    return m_ghostText && m_ghostText->handleMessage(message, wParam, lParam);
}

void Win32IDE::runNativeCodexPrompt(const std::string& prompt) {
    if (prompt.empty()) {
        appendToOutput("[Codex] select or enter code first.\n", "Debug", OutputSeverity::Warning);
        return;
    }
    generateResponseAsync(prompt, [this](const std::string& result, bool done) {
        if (!done) return;
        appendToOutput("[Codex]\n" + result + "\n", "Debug", OutputSeverity::Info);
    });
}
