// ============================================================================
// K2LivePolicy_Hysteresis.cpp — sticky-arm state + hysteresis
// ============================================================================
#include "K2LivePolicy.hpp"
#include <atomic>
#include <string>

namespace Deep2 {
namespace {

std::atomic<K2LivePolicyMode> g_stickyMode{K2LivePolicyMode::Off};
std::atomic<char> g_stickyArm[64]{}; // 64 chars for arm name

} // namespace

void K2LivePolicy_SetSticky(K2LivePolicyMode m) {
    g_stickyMode.store(m, std::memory_order_relaxed);
}

void K2LivePolicy_SetStickyArm(K2LivePolicyMode m, const char* arm) {
    g_stickyMode.store(m, std::memory_order_relaxed);
    if (arm) {
        size_t i = 0;
        for (; i < 63 && arm[i]; ++i) {
            g_stickyArm[i].store(arm[i], std::memory_order_relaxed);
        }
        for (; i < 64; ++i) {
            g_stickyArm[i].store('\0', std::memory_order_relaxed);
        }
    }
}

uint32_t K2LivePolicy_HysteresisHold() {
    // Return 0 when no sticky arm is active; callers can check mode() != Off
    return g_stickyMode.load(std::memory_order_relaxed) != K2LivePolicyMode::Off ? 1u : 0u;
}

void K2LivePolicy_ClearSticky() {
    g_stickyMode.store(K2LivePolicyMode::Off, std::memory_order_relaxed);
    for (int i = 0; i < 64; ++i) {
        g_stickyArm[i].store('\0', std::memory_order_relaxed);
    }
}

} // namespace Deep2