#pragma once
/*
===============================================================================
 LocalOnlyPolicy — LOCAL_ONLY_001 fail-closed helpers
===============================================================================
 Deep2/GGUF only. No Ollama HTTP client. No :11434 resurrection.
 Soft / stub "AI" text on network miss is forbidden.
===============================================================================
*/
#include <string>
#include <cstdint>

#ifndef RAWRXD_LOCAL_ONLY
#define RAWRXD_LOCAL_ONLY 1
#endif

namespace RawrXD {
namespace LocalOnly {

inline constexpr bool kEnabled = (RAWRXD_LOCAL_ONLY != 0);

inline constexpr const char* kHardDiagnostic =
    "LOCAL_ONLY_001: FAIL_CLOSED — Ollama/HTTP inference is forbidden. "
    "Load a local GGUF and use Deep2/GGUF only.";

inline constexpr const char* kNetworkForbidden =
    "LOCAL_ONLY_001: NETWORK_FALLBACK=FORBIDDEN";

inline constexpr uint16_t kForbiddenOllamaPort = 11434;

inline bool isForbiddenOllamaPort(uint16_t port) {
    return kEnabled && port == kForbiddenOllamaPort;
}

inline bool looksLikeOllamaBaseUrl(const std::string& url) {
    if (!kEnabled) return false;
    if (url.empty()) return false;
    if (url.find(":11434") != std::string::npos) return true;
    if (url.find("11434") != std::string::npos) return true;
    return false;
}

/** Empty or forbidden URL must never become localhost:11434. */
inline std::string sanitizeBaseUrl(const std::string& url) {
    if (!kEnabled) return url;
    if (url.empty() || looksLikeOllamaBaseUrl(url)) return std::string();
    return url;
}

inline bool allowOllamaHttpClient() {
    return !kEnabled;
}

} // namespace LocalOnly
} // namespace RawrXD
