#pragma once
// Shared, strict parser for the Deep2 F32 private-residency opt-in.
// Invalid, partial, non-finite, negative, and out-of-range values fail closed.
#include <cerrno>
#include <cmath>
#include <cstdlib>

namespace Deep2 {

inline bool TryParseF32CompressionMaxAbsError(const char* text,
                                               float& value) noexcept {
    if (!text || !*text) return false;

    errno = 0;
    char* end = nullptr;
    const float parsed = std::strtof(text, &end);
    if (end == text || !end || *end != '\0' || errno == ERANGE ||
        !std::isfinite(parsed) || parsed < 0.0f) {
        return false;
    }

    value = parsed;
    return true;
}

} // namespace Deep2
