#pragma once
/* Unlimited token law — stub-style: no artificial cap; EOS/cancel/context stop.
 * CHRONO=LUKEWARM — not hot-unpatch; not number-sided-only.
 * Engine GenerationOptions: 0 or UINT32_MAX = unlimited (context-bounded).
 * ProductRequest: 0 = product default (256) unless DEEP2_UNLIMITED_TOKENS=1. */
#include <cstdint>
#include <cstdlib>
#ifdef _WIN32
#include <stdlib.h>
#endif

namespace rawr::unlimited {

inline constexpr uint32_t kSentinel = 0xFFFFFFFFu;

inline bool EnvArmed() noexcept {
    const char* e = std::getenv("DEEP2_UNLIMITED_TOKENS");
    if (e && e[0] == '1' && e[1] == '\0') return true;
    e = std::getenv("DEEP2_MAX_TOKENS");
    if (e && e[0] == '0' && e[1] == '\0') return true;
    e = std::getenv("RAWR_MAX_TOKENS");
    return e && e[0] == '0' && e[1] == '\0';
}

/* Engine path: 0 and UINT32_MAX are unlimited. */
inline bool IsUnlimited(uint32_t requested) noexcept {
    return requested == 0 || requested == kSentinel;
}

/* Product path: 0 alone is NOT unlimited unless env armed. */
inline bool ProductUnlimited(uint32_t requested) noexcept {
    return requested == kSentinel || (requested == 0 && EnvArmed());
}

inline uint32_t ResolveCap(uint32_t requested, uint32_t remainingCtx) noexcept {
    if (remainingCtx == 0) remainingCtx = 1u;
    if (IsUnlimited(requested)) return remainingCtx;
    return requested < remainingCtx ? requested : remainingCtx;
}

inline void ArmEnv() noexcept {
#ifdef _WIN32
    _putenv_s("DEEP2_UNLIMITED_TOKENS", "1");
#else
    setenv("DEEP2_UNLIMITED_TOKENS", "1", 1);
#endif
}

} // namespace rawr::unlimited
