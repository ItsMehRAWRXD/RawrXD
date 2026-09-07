#pragma once
#include <cstring>
#include <string>
namespace rawr::product {

enum class FailKind : uint8_t {
    None = 0,
    Compile = 1,
    Test = 2,
    Timeout = 3,
    Denied = 4,
    Hallucinate = 5
};

inline FailKind ClassifyFail(const std::string& log) {
    if (log.find("error C") != std::string::npos ||
        log.find("undefined reference") != std::string::npos)
        return FailKind::Compile;
    if (log.find("FAILED") != std::string::npos ||
        log.find("ASSERT") != std::string::npos)
        return FailKind::Test;
    if (log.find("timeout") != std::string::npos) return FailKind::Timeout;
    if (log.find("denied") != std::string::npos) return FailKind::Denied;
    if (log.find("NO_EVIDENCE") != std::string::npos)
        return FailKind::Hallucinate;
    return FailKind::None;
}

inline const char* FailName(FailKind k) {
    switch (k) {
    case FailKind::Compile: return "compile";
    case FailKind::Test: return "test";
    case FailKind::Timeout: return "timeout";
    case FailKind::Denied: return "denied";
    case FailKind::Hallucinate: return "hallucinate";
    default: return "none";
    }
}

} // namespace rawr::product
