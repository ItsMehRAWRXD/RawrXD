#include "Win32IDE.h"
#include "agentic/agentic_composer_ux.h"
#include "../product/gateway/product_deep2_infer.hpp"
#include <windows.h>
#include <cstdlib>
#include <cstdio>
#include <string>

// Handler for agentic composer UX feature
// E1: session ID passed to composer for provenance tracking
// E2: model name from loaded path / ProductOpen session — never "default-model"
// E3: output callback wired to IDE appendToOutput for streaming
// E4: session title auto-generated from timestamp if empty
// E5: composer initialized once; host pointer refreshed each entry (lifecycle)
// E6: session start logged to IDE output panel (MessageBox != product success)
// E7: error from Initialize / missing model logged to IDE output panel
// Fail-closed: no model => ShowError + return; no StartSession; no fake PASS

namespace {

// Static composer callbacks capture this host, not a stack `ide` by value.
// HandleAgenticComposerUX refreshes it each entry; null-check before use.
// Residual: if Win32IDE is destroyed without clearing this pointer, a late
// callback could still dangle — callers must not invoke after IDE teardown.
Win32IDE* g_composerUxIdeHost = nullptr;

std::string ResolveActiveComposerModel(Win32IDE* ide) {
    if (!ide) return {};
    std::string model = ide->getLoadedModelPath();
    if (!model.empty()) return model;
    // ProductOpen session may own the model without IDE path mirror yet.
    if (rawr::ProductSessionOpen()) {
        if (const char* env = std::getenv("RAWRXD_PRODUCT_MODEL")) {
            if (env[0] != '\0') return std::string(env);
        }
    }
    return {};
}

} // namespace

void HandleAgenticComposerUX(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;

    g_composerUxIdeHost = ide;

    static RawrXD::Agentic::AgenticComposerUX composer;
    static bool initialized = false;

    if (!initialized) {
        RawrXD::Agentic::ComposerUICallbacks callbacks;
        // E3: wire output/status to IDE panel via onStatusChange (host null-check)
        callbacks.onStatusChange = [](const std::string& status, const std::string& detail) {
            Win32IDE* host = g_composerUxIdeHost;
            if (!host) return;
            host->appendToOutput("[ComposerUX] " + status + (detail.empty() ? "" : ": " + detail),
                                 "Agent", Win32IDE::OutputSeverity::Info);
        };
        callbacks.onError = [](const std::string& error, const std::string& suggestion) {
            Win32IDE* host = g_composerUxIdeHost;
            if (!host) return;
            host->appendToOutput("[ComposerUX] Error: " + error +
                                 (suggestion.empty() ? "" : " — " + suggestion),
                                 "Errors", Win32IDE::OutputSeverity::Error);
        };
        composer.Initialize(callbacks);
        initialized = true;
    }

    // E2: resolve real active local / ProductOpen session model — refuse default-model
    const std::string model = ResolveActiveComposerModel(ide);
    if (model.empty()) {
        const char* err = "No active local model / ProductOpen session model";
        const char* sug = "Load a GGUF via ProductOpenSession before Agentic Composer UX";
        composer.ShowError(err, sug);
        ide->appendToOutput(std::string("[ComposerUX] FAIL_CLOSED: ") + err + " — " + sug,
                            "Errors", Win32IDE::OutputSeverity::Error);
        // No StartSession, no MessageBox, no default-model PASS
        return;
    }

    // E4: auto-generate title from timestamp
    char titleBuf[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(titleBuf, sizeof(titleBuf), "Session %04d-%02d-%02d %02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

    const uint64_t sessionId = composer.StartSession(titleBuf, model);

    const auto* session = composer.GetCurrentSession();
    const std::string& modelName =
        (session && !session->modelName.empty()) ? session->modelName : model;

    // E6: status via output panel only — MessageBox refused as product success
    ide->appendToOutput("[ComposerUX] Session started id=" + std::to_string(sessionId) +
                            " model=" + modelName,
                        "Agent", Win32IDE::OutputSeverity::Info);
}
