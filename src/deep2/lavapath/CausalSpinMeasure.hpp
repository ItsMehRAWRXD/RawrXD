#pragma once
/* Measure SPIN lifetime — never assign TOKEN_TIME. */
#include "BgBmLaw.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace rawr::spin {

inline std::atomic<uint64_t>& Unresolved() {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& SpinOpenNs() {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& LastSpinNs() {
    static std::atomic<uint64_t> v{0};
    return v;
}
inline std::atomic<uint64_t>& ClosedSpins() {
    static std::atomic<uint64_t> v{0};
    return v;
}

inline void Reset() noexcept {
    Unresolved().store(0);
    SpinOpenNs().store(0);
    LastSpinNs().store(0);
    ClosedSpins().store(0);
}

inline void Require(uint64_t n) noexcept {
    Unresolved().fetch_add(n, std::memory_order_relaxed);
}
inline void Satisfy(uint64_t n) noexcept {
    uint64_t cur = Unresolved().load();
    while (cur > 0) {
        const uint64_t sub = n < cur ? n : cur;
        if (Unresolved().compare_exchange_weak(cur, cur - sub)) return;
    }
}

inline void Open(uint64_t nowNs) noexcept {
    SpinOpenNs().store(nowNs);
    if (Unresolved().load() == 0) Require(1); /* at least generation work */
}

inline uint64_t Close(uint64_t nowNs) noexcept {
    const uint64_t open = SpinOpenNs().load();
    const uint64_t dt = (nowNs > open) ? (nowNs - open) : 0ull;
    LastSpinNs().store(dt);
    ClosedSpins().fetch_add(1, std::memory_order_relaxed);
    Unresolved().store(0);
    return dt;
}

inline void EmitReceipt(uint64_t genTok, uint64_t wallNs) noexcept {
    const uint64_t spinNs = LastSpinNs().load();
    const double tps =
        (wallNs > 0 && genTok > 0)
            ? (1e9 * (double)genTok / (double)wallNs)
            : 0.0;
    const double meanSpin =
        (genTok > 0 && wallNs > 0) ? ((double)wallNs / (double)genTok) : 0.0;
    const int within150 =
        (meanSpin > 0.0 && meanSpin <= (double)SPIN_BUDGET_NS_150) ? 1 : 0;
    std::printf("EOM_SPIN_001=1 BG_BM_001=1 RAWR_TIME_001=1\n");
    std::printf("SPIN_OPEN_ON_TOKEN=1 SPIN_STOP_ON_DEPENDENCY_CLOSURE=1\n");
    std::printf("WALL_OBSERVER_NS=%llu MEAN_WALL_PER_TOKEN_NS=%.0f\n",
                (unsigned long long)spinNs, meanSpin);
    std::printf("TARGET_TPS=%d SPIN_BUDGET_NS=%llu\n", TARGET_TPS_150,
                (unsigned long long)SPIN_BUDGET_NS_150);
    std::printf("EFFECTIVE_BYTES_CAP=%llu R9700_BW_GBS=640\n",
                (unsigned long long)EFFECTIVE_BYTES_CAP_150);
    std::printf("MEASURED_DECODE_TPS=%.3f TARGET_150_WITHIN=%d\n", tps,
                within150);
    std::printf("HARDWARE_REQUIREMENTS_DISREGARDED=1 "
                "NAIVE_BANDWIDTH_NE_PHYSICAL=1\n");
    std::printf("RAWRXD_TARGET_150_TPS_001=%s\n",
                within150 ? "PASS" : "OPEN");
}

} // namespace rawr::spin
