#pragma once
/* RxNoDeps — MSVC/x64, no third-party deps. ≤99. */
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rxow {

inline void Zmem(void* p, size_t n) noexcept {
    if (p && n) std::memset(p, 0, n);
}
inline void CopyStr(char* dst, size_t cap, const char* src) noexcept {
    if (!dst || cap == 0) return;
    dst[0] = 0;
    if (!src) return;
    std::snprintf(dst, cap, "%s", src);
}

} // namespace rxow
