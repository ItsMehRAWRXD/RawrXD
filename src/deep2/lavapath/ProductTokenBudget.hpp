#pragma once
/* Product token budget — 0 = unlimited (stub-generator style). ≤55 lines. */
#include "UnlimitedTokenLaw.hpp"
#include <cstdint>
namespace rawr::product_run {

inline constexpr uint32_t kDefaultMaxTokens = 256;
inline constexpr uint32_t kUnlimitedTokens = rawr::unlimited::kSentinel;

enum class MaxTokensSource : uint8_t {
    Unlimited = 0,
    ProductDefault = 1,
    CallerOverride = 2,
    EnvOverride = 3
};

inline const char* MaxTokensSourceName(MaxTokensSource s) noexcept {
    if (s == MaxTokensSource::CallerOverride) return "CALLER_OVERRIDE";
    if (s == MaxTokensSource::EnvOverride) return "ENV_OVERRIDE";
    if (s == MaxTokensSource::ProductDefault) return "PRODUCT_DEFAULT";
    return "UNLIMITED";
}

struct TokenBudget {
    uint32_t requested = 0;
    uint32_t effective = kUnlimitedTokens;
    MaxTokensSource source = MaxTokensSource::Unlimited;
};

/* requestedOrZero: 0 = unlimited until EOS/cancel (stub-style).
   envOverride>0 forces a finite cap (bench/IDE pin). */
inline TokenBudget ResolveTokenBudget(uint32_t requestedOrZero,
                                      int envOverride = 0) noexcept {
    TokenBudget b{};
    if (envOverride > 0) {
        b.requested = (uint32_t)envOverride;
        b.effective = (uint32_t)envOverride;
        b.source = MaxTokensSource::EnvOverride;
        return b;
    }
    if (requestedOrZero) {
        b.requested = requestedOrZero;
        b.effective = requestedOrZero;
        b.source = MaxTokensSource::CallerOverride;
        return b;
    }
    b.requested = 0;
    b.effective = kUnlimitedTokens;
    b.source = MaxTokensSource::Unlimited;
    return b;
}

} // namespace rawr::product_run
