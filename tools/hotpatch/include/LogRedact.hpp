#pragma once
// Fail-closed log redaction for routing/hotpatch evidence logs.
#include <cctype>
#include <string>

namespace rawrxd::hotpatch {

inline bool IsSecretKeyToken(const std::string& keyLower) {
    return keyLower.find("api_key") != std::string::npos ||
           keyLower.find("apikey") != std::string::npos ||
           keyLower.find("authorization") != std::string::npos ||
           keyLower.find("bearer") != std::string::npos ||
           keyLower.find("password") != std::string::npos ||
           keyLower.find("secret") != std::string::npos ||
           keyLower.find("token") != std::string::npos;
}

inline std::string RedactSecrets(std::string msg) {
    // Bearer tokens
    const char* markers[] = {"Bearer ", "bearer ", "api_key=", "api-key=",
                             "Authorization: ", "password=", "secret="};
    for (const char* m : markers) {
        size_t pos = 0;
        const size_t mlen = std::char_traits<char>::length(m);
        while ((pos = msg.find(m, pos)) != std::string::npos) {
            size_t start = pos + mlen;
            size_t end = start;
            while (end < msg.size() && !std::isspace(static_cast<unsigned char>(msg[end])) &&
                   msg[end] != '"' && msg[end] != ',' && msg[end] != '}') {
                ++end;
            }
            if (end > start) msg.replace(start, end - start, "[REDACTED]");
            pos = start + 10;
        }
    }
    // Long hex-ish secrets (32+)
    size_t i = 0;
    while (i < msg.size()) {
        if (std::isxdigit(static_cast<unsigned char>(msg[i]))) {
            size_t j = i;
            while (j < msg.size() && std::isxdigit(static_cast<unsigned char>(msg[j]))) ++j;
            if (j - i >= 32) {
                msg.replace(i, j - i, "[REDACTED_HEX]");
                i += 14;
                continue;
            }
            i = j;
        } else {
            ++i;
        }
    }
    return msg;
}

}  // namespace rawrxd::hotpatch
