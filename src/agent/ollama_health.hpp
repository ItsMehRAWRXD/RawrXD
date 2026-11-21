// ollama_health.hpp -- RAWRXD_OLLAMA_HEALTH_001
//
// Classifies an Ollama /api/tags probe into a registry health value.
//
// Health is deliberately independent of capability verification: a reachable
// server never promotes chat, streaming, tool calling or repair. Capability
// claims must come from their own tests.
//
// The classifier is a pure function over already-captured probe facts so it can
// be tested against mocks (refused, timeout, malformed, unexpected status)
// without a network.

#pragma once

#include <string>
#include <string_view>

namespace rawrxd {

enum class OllamaHealth : std::uint8_t {
    Available = 0,    // HTTP 200 with a valid /api/tags body
    Unavailable = 1,  // connection refused, DNS failure, or timeout
    Degraded = 2,     // reached the server but the response was invalid
};

inline std::string_view ToString(OllamaHealth h) noexcept
{
    switch (h) {
        case OllamaHealth::Available:   return "available";
        case OllamaHealth::Unavailable: return "unavailable";
        case OllamaHealth::Degraded:    return "degraded";
    }
    return "unavailable";
}

// Facts a probe must capture. `httpStatus` is 0 when no response was received.
struct OllamaProbeFacts {
    bool connected = false;    // TCP/TLS connection established
    bool timedOut = false;     // bounded deadline exceeded
    int httpStatus = 0;        // HTTP status code, 0 if none
    bool validTagsJson = false;// body parsed and contains a "models" array
};

inline OllamaHealth ClassifyOllamaProbe(const OllamaProbeFacts& f) noexcept
{
    if (f.timedOut) return OllamaHealth::Unavailable;
    if (!f.connected || f.httpStatus == 0) return OllamaHealth::Unavailable;
    if (f.httpStatus != 200) return OllamaHealth::Degraded;
    if (!f.validTagsJson) return OllamaHealth::Degraded;
    return OllamaHealth::Available;
}

}  // namespace rawrxd