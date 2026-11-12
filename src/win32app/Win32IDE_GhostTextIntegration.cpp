#include "Win32IDE.h"
#include <richedit.h>
#include <chrono>
#include <memory>
#include <fstream>
#include <cstdlib>
#include "../backend/ollama_client.h"

namespace {
// Debounce (ms) lives in NativeGhostTextController. This is the Ollama HTTP
// deadline in seconds (30–120). Never pass debounce ms into WinHTTP.
constexpr int kGhostTextTimeoutSeconds = 120;
constexpr int kGhostTextDebounceMsLog = 250;

bool PreferGhostTextModel(const ChatModelEntry& a, const ChatModelEntry& b) {
    // Prefer small local coder models for inline latency; never invent IDs.
    auto score = [](const ChatModelEntry& e) -> int {
        if (e.source != ChatModelEntry::Source::Ollama || e.identifier.empty())
            return -1;
        int s = 0;
        const std::string& id = e.identifier;
        if (id.find("coder") != std::string::npos) s += 40;
        if (id.find("1.5b") != std::string::npos) s += 30;
        if (id.find("3b") != std::string::npos) s += 20;
        if (id.find("4b") != std::string::npos) s += 15;
        if (id.find("8b") != std::string::npos) s += 10;
        if (id.find("productivity") != std::string::npos) s -= 50;
        if (id.find("cloud") != std::string::npos) s -= 100;
        return s;
    };
    return score(a) > score(b);
}

void AppendGhostRuntimeEvidence(const std::string& line)
{
    const char* configured = std::getenv("RAWRXD_LOG_DIR");
    const std::string path = (configured && *configured)
        ? std::string(configured) + "\\chat_runtime.log"
        : std::string("chat_runtime.log");
    std::ofstream out(path, std::ios::app);
    if (out) out << line << std::endl;
}

std::atomic<uint64_t> g_nextGhostRuntimeRequest{1};
}

void Win32IDE::initializeNativeGhostText() {
    if (!m_hwndMain || !m_hwndEditor) return;
    const NativeGhostTextController::Request request =
        [this](const std::string& prompt,
               NativeGhostTextController::RequestCallback callback)
        -> NativeGhostTextController::RequestCancel {
            auto reject = [callback](const char* reason)
                -> NativeGhostTextController::RequestCancel {
                NativeGhostTextController::Response response;
                response.done = true;
                response.success = false;
                response.failureReason = reason;
                if (callback) callback(response);
                return {};
            };
            if (m_ghostTextMode == GhostTextMode::Disabled) {
                return reject("DISABLED");
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
                    return reject("MODEL_UNAVAILABLE");
                }
                route = *found;
            } else if (m_ghostTextMode == GhostTextMode::FollowChat) {
                route = m_selectedChatModel;
            } else {
                // Auto Local: prefer a small local coder for inline latency.
                // Do not pin GhostText to a heavy chat model (e.g. productivity).
                // Env RAWRXD_GHOSTTEXT_MODEL wins when present in the live catalog.
                const char* envModel = std::getenv("RAWRXD_GHOSTTEXT_MODEL");
                if (envModel && *envModel) {
                    for (const auto& candidate : m_availableModels) {
                        if (candidate.source == ChatModelEntry::Source::Ollama &&
                            candidate.identifier == envModel) {
                            route = candidate;
                            break;
                        }
                    }
                }
                if (route.identifier.empty()) {
                    for (const auto& candidate : m_availableModels) {
                        if (candidate.source != ChatModelEntry::Source::Ollama ||
                            candidate.identifier.empty()) {
                            continue;
                        }
                        if (route.identifier.empty() ||
                            PreferGhostTextModel(candidate, route)) {
                            route = candidate;
                        }
                    }
                }
                if (route.identifier.empty() &&
                    m_selectedChatModel.source == ChatModelEntry::Source::Ollama &&
                    !m_selectedChatModel.identifier.empty()) {
                    route = m_selectedChatModel;
                }
            }
            if (route.identifier.empty()) {
                logWarning("GhostText", "No eligible GhostText model route is available.");
                return reject("NO_ROUTE");
            }
            if (route.source == ChatModelEntry::Source::KiloFree && !m_allowCloudGhostText) {
                logWarning("GhostText", "Cloud route selected but session cloud consent is disabled.");
                return reject("CLOUD_CONSENT_REQUIRED");
            }
            m_pendingInferenceModel = route;
            const char* backend = route.source == ChatModelEntry::Source::Ollama
                ? "ollama" : (route.source == ChatModelEntry::Source::LocalFile
                    ? "native" : "cloud");
            logInfo("GhostText inference route: " + route.identifier +
                    " backend=" + backend +
                    " timeout_s=" + std::to_string(kGhostTextTimeoutSeconds) +
                    " debounce_ms=" + std::to_string(kGhostTextDebounceMsLog));
            return requestNativeGhostText(prompt, std::move(callback));
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
            AppendGhostRuntimeEvidence(event);
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
                                   AppendGhostRuntimeEvidence(event);
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

NativeGhostTextController::RequestCancel Win32IDE::requestNativeGhostText(
    const std::string& prompt,
    NativeGhostTextController::RequestCallback callback)
{
    // GhostText requests are independently fenced by the controller. Allow a
    // newer request to run while an older one is still in flight; the older
    // response is discarded by generation/identity checks on the UI thread.
    //
    // Only consume m_pendingInferenceModel for the Ollama branch. The
    // non-Ollama path (native GGUF/cloud) adapts generateResponseAsync, which
    // reads m_pendingInferenceModel to consume the resolved route; exchanging
    // it here would discard the route and force fallback to m_selectedChatModel.
    ChatModelEntry ghostRoute = m_pendingInferenceModel;
    if (ghostRoute.source == ChatModelEntry::Source::Ollama &&
        !ghostRoute.identifier.empty()) {
        m_pendingInferenceModel = ChatModelEntry{};
        const std::string baseUrl = m_ollamaBaseUrl;
        const int maxTokens = effectiveMaxTokensForPrompt(prompt);
        const int contextTokens = m_currentContextTokens;
        const ReasoningMode reasoningMode = m_reasoningMode;
        const uint64_t requestId =
            g_nextGhostRuntimeRequest.fetch_add(1, std::memory_order_relaxed);
        // One client per request gives request-specific cancellation: closing
        // this request's WinHTTP handle cannot disturb a newer request that is
        // using a different client. The worker holds a strong reference so the
        // client always outlives the detached thread; the cancel handle holds
        // only a weak reference and is a no-op once the worker finishes.
        auto client = std::make_shared<RawrXD::Backend::OllamaClient>(baseUrl);
        client->setTimeoutSeconds(kGhostTextTimeoutSeconds);
        std::weak_ptr<RawrXD::Backend::OllamaClient> weakClient = client;
        std::thread([model = ghostRoute.identifier, prompt,
                     maxTokens, contextTokens, reasoningMode, client,
                     requestId,
                     callback = std::move(callback)]() mutable {
            const auto start = std::chrono::steady_clock::now();
            auto elapsedMs = [&]() -> uint64_t {
                return static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count());
            };
            try {
                (void)reasoningMode;
                AppendGhostRuntimeEvidence(
                    "GHOSTTEXT_RUNTIME request_started request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " backend=ollama");
                RawrXD::Backend::OllamaGenerateRequest request;
                request.model = model;
                request.prompt = prompt;
                request.stream = false;
                request.options["num_predict"] = std::to_string(maxTokens);
                request.options["num_ctx"] = std::to_string(contextTokens);
                const RawrXD::Backend::OllamaResponse result =
                    client->generateSync(request);
                const std::string response = result.response.empty()
                    ? result.message : result.response;

                NativeGhostTextController::Response gr;
                gr.done = true;
                gr.httpStatus = static_cast<unsigned int>(result.http_status);
                gr.elapsedMs = elapsedMs();
                if (!response.empty()) {
                    gr.success = true;
                    gr.text = response;
                } else {
                    gr.success = false;
                    // Preserve the transport/model distinction instead of
                    // collapsing every empty result into a bare failure.
                    if (!result.transport_error.empty()) {
                        gr.failureReason = result.transport_error;
                    } else if (result.done_reason == "error") {
                        gr.failureReason = "MODEL_ERROR";
                    } else {
                        gr.failureReason = "EMPTY_OUTPUT";
                    }
                }
                if (callback) callback(gr);
                AppendGhostRuntimeEvidence(
                    "GHOSTTEXT_RUNTIME response request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " success=" + (gr.success ? "1" : "0") +
                    " http_status=" + std::to_string(gr.httpStatus) +
                    " elapsed_ms=" + std::to_string(gr.elapsedMs) +
                    " response_bytes=" + std::to_string(gr.text.size()) +
                    " failure_reason=" +
                        (gr.failureReason.empty() ? "NONE" : gr.failureReason));
            } catch (...) {
                NativeGhostTextController::Response gr;
                gr.done = true;
                gr.elapsedMs = elapsedMs();
                gr.failureReason = "EXCEPTION";
                if (callback) callback(gr);
                AppendGhostRuntimeEvidence(
                    "GHOSTTEXT_RUNTIME response request_id=" +
                    std::to_string(requestId) + " model=" + model +
                    " success=0 failure_reason=EXCEPTION elapsed_ms=" +
                    std::to_string(gr.elapsedMs));
            }
        }).detach();

        // Non-blocking: cancelActiveRequest() only closes the WinHTTP handle
        // that unblocks the worker's synchronous receive. It never joins the
        // worker, so the UI thread is not held while inference unwinds.
        return [weakClient]() {
            if (auto locked = weakClient.lock()) locked->cancelActiveRequest();
        };
    }

    // Non-Ollama routes (native GGUF / cloud) share the chat inference lane,
    // which has its own generation-based admission. Adapt its 3-argument
    // callback to the GhostText response contract.
    generateResponseAsync(prompt,
        [callback = std::move(callback)](
            const std::string& text, bool done, bool success) mutable {
            NativeGhostTextController::Response gr;
            gr.done = done;
            gr.text = text;
            gr.success = success && !text.empty();
            if (!gr.success) {
                gr.failureReason = text.empty()
                    ? "INFERENCE_UNAVAILABLE" : "INFERENCE_FAILED";
            }
            if (callback) callback(gr);
        });
    return {};
}

void Win32IDE::appendNativeDebugOutput(const std::string& text, bool error)
{
    appendToOutput(text, "Debug", error ? OutputSeverity::Error : OutputSeverity::Info);
}

