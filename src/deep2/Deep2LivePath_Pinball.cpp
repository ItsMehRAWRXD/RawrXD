// Live Pinball: bounce/earned_bits from residual energy (not hardcoded)
#include "Deep2LivePath.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>

namespace Deep2 {
namespace {

std::atomic<uint32_t> g_samples{0};
std::atomic<uint32_t> g_bounce{0};
std::atomic<uint32_t> g_earnedBitsX1000{0};
std::atomic<uint32_t> g_active{0};

} // namespace

void LivePath_PinballReset() {
    g_samples.store(0, std::memory_order_relaxed);
    g_bounce.store(0, std::memory_order_relaxed);
    g_earnedBitsX1000.store(0, std::memory_order_relaxed);
}

void LivePath_PinballArm() {
    g_active.store(1, std::memory_order_release);
    LivePath_PinballReset();
}

void LivePath_PinballDisarm() {
    g_active.store(0, std::memory_order_release);
}

void LivePath_RecordPinball(float residualL2, float scale) {
    if (!g_active.load(std::memory_order_acquire)) return;
    if (!(scale > 0.f) || !std::isfinite(residualL2) || !std::isfinite(scale))
        return;

    const float ratio = residualL2 / scale;
    // Higher residual → more bounce passes still earning precision.
    float bounceF = 32.f + 224.f * std::min(1.f, std::max(0.f, ratio));
    float bits = std::min(16.f, std::max(0.f, -std::log2f(std::max(ratio, 1e-6f))));

    g_samples.fetch_add(1, std::memory_order_relaxed);
    g_bounce.store(static_cast<uint32_t>(bounceF), std::memory_order_relaxed);
    g_earnedBitsX1000.store(static_cast<uint32_t>(bits * 1000.f),
                            std::memory_order_relaxed);
}

uint16_t LivePath_PinballBounce() {
    return static_cast<uint16_t>(g_bounce.load(std::memory_order_relaxed));
}

float LivePath_PinballEarnedBits() {
    return g_earnedBitsX1000.load(std::memory_order_relaxed) / 1000.f;
}

uint32_t LivePath_PinballSamples() {
    return g_samples.load(std::memory_order_relaxed);
}

bool LivePath_PinballActive() {
    return g_active.load(std::memory_order_acquire) != 0;
}

} // namespace Deep2
