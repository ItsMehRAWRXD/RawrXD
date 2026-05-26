#pragma once
#include <string>
#include <functional>

namespace RawrXD {
namespace HexMag {

struct HexMagResponse {
    std::string answer;
    std::string error;
    bool success{false};
};

inline bool tryLaunchService() { return true; }
inline bool healthCheck() { return true; }
inline std::string resolveBaseUrl() { return "http://localhost:8000"; }
inline HexMagResponse askWithAutoStart(const std::string& question, const std::string& context) {
    return {"", "", true};
}

struct StreamResult {
    std::string error;
    bool success{false};
};

inline StreamResult streamAgentWithAutoStart(const std::string& goal, std::function<void(const std::string&)> onChunk, float timeout) {
    return {"", true};
}

} // namespace HexMag
} // namespace RawrXD
