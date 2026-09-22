#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd::closure {

enum class Status : uint8_t { pass, fail, skipped };

struct GateReceipt {
    std::string name;
    Status status{Status::fail};
    std::string detail;
    std::chrono::milliseconds elapsed{0};
};

inline const char* to_string(Status s) noexcept {
    switch (s) {
        case Status::pass: return "PASS";
        case Status::fail: return "FAIL";
        case Status::skipped: return "SKIP";
    }
    return "FAIL";
}

inline std::string json_escape(std::string_view in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) >= 0x20) out += c;
                break;
        }
    }
    return out;
}

inline uint64_t fnv1a64(std::string_view s) noexcept {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

} // namespace rawrxd::closure
