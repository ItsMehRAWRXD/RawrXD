#include "Win32IDE.h"
#include "../streamer/LocalStreamReverseParser.hpp"

#include <string>

bool Win32IDE::ensureStreamingGgufLoader() {
    if (m_ggufLoader) {
        return true;
    }
    m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
    if (!m_ggufLoader) {
        appendToOutput("[NativeOnly] Streaming GGUF loader allocation failed.");
        return false;
    }
    appendToOutput("[NativeOnly] Streaming GGUF loader created (local files/blobs only).");
    return true;
}

void Win32IDE::reportMissingLoadArtifacts(const std::string& kind, const std::string& path) {
    appendToOutput("[NativeOnly] Reverse-parsing local artifact (no remote fallback).");
    const auto report = rawrxd::streamer::parseLocalArtifact(kind, path);
    const std::string text = rawrxd::streamer::formatReverseParseReport(report);
    appendToOutput(text);
    showModelLoadError(text);
    logError("reportMissingLoadArtifacts", text);
}
