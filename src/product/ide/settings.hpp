#pragma once
#include <cstring>
#include <string>
namespace rawr::product {

enum class LatencyMode : uint8_t { Fast = 0, Balanced = 1, Quality = 2 };
enum class PrivacyMode : uint8_t { Local = 0, Audit = 1 };

struct ProductSettings {
    LatencyMode latency = LatencyMode::Fast;
    PrivacyMode privacy = PrivacyMode::Local;
    uint32_t debounceMs = 80;
    uint32_t maxCtxTokens = 4096;
    const char* modelAlias = "default";
    int repoScope = 1;
};

inline uint32_t DebounceFor(LatencyMode m) {
    if (m == LatencyMode::Fast) return 50;
    if (m == LatencyMode::Quality) return 150;
    return 80;
}

inline const char* LatencyName(LatencyMode m) {
    if (m == LatencyMode::Fast) return "fast";
    if (m == LatencyMode::Quality) return "quality";
    return "balanced";
}

} // namespace rawr::product
