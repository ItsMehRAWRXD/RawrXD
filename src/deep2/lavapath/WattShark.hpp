#pragma once
/* WattShark — observe watts/TPS; never owns authority or blocks generate. */
#include <cstdint>
#include <cstdio>

namespace rawr::watt {

enum class PerfClass : uint8_t {
    UnderOccupied = 0,
    HotButWasteful = 1,
    ValidHighBurn = 2,
    Efficient = 3,
    Unknown = 4
};

struct Sample {
    double idleW = 0.0;
    double avgGenW = 0.0;
    double peakGenW = 0.0;
    uint64_t wallNs = 0;
    uint64_t tokens = 0;
    double tps = 0.0;
    bool powerCaptured = false;
    const char* wallOwner = "UNKNOWN";
};

inline double JoulesPerToken(const Sample& s) noexcept {
    if (!s.tokens || s.wallNs == 0 || s.avgGenW <= 0.0) return 0.0;
    const double sec = double(s.wallNs) / 1e9;
    return (s.avgGenW * sec) / double(s.tokens);
}

inline PerfClass Classify(const Sample& s, double tpsFloor = 5.0) noexcept {
    if (!s.powerCaptured || s.tps <= 0.0) return PerfClass::Unknown;
    const bool lowT = s.tps < tpsFloor;
    const bool highW = s.avgGenW > (s.idleW + 80.0);
    if (lowT && !highW) return PerfClass::UnderOccupied;
    if (lowT && highW) return PerfClass::HotButWasteful;
    if (!lowT && highW) return PerfClass::ValidHighBurn;
    return PerfClass::Efficient;
}

inline const char* ClassName(PerfClass c) noexcept {
    switch (c) {
    case PerfClass::UnderOccupied: return "UNDER_OCCUPIED";
    case PerfClass::HotButWasteful: return "HOT_BUT_WASTEFUL";
    case PerfClass::ValidHighBurn: return "VALID_HIGH_BURN";
    case PerfClass::Efficient: return "EFFICIENT";
    default: return "UNKNOWN";
    }
}

inline void Emit(const Sample& s) noexcept {
    const PerfClass c = Classify(s);
    std::printf("WATTSHARK_BEGIN\n");
    std::printf("WATTSHARK_OBSERVES=1 WATTSHARK_OWNS_AUTHORITY=0\n");
    std::printf("WATTSHARK_CAN_BLOCK_GENERATE=0 "
                "WATTSHARK_CAN_SELECT_PERF_SPEND=1\n");
    std::printf("POWER_CAPTURED=%d IDLE_W=%.1f AVG_GEN_W=%.1f PEAK_W=%.1f\n",
                s.powerCaptured ? 1 : 0, s.idleW, s.avgGenW, s.peakGenW);
    std::printf("WALL_NS=%llu TOKENS=%llu DECODE_TPS=%.3f "
                "JOULES_PER_TOKEN=%.6f\n",
                (unsigned long long)s.wallNs, (unsigned long long)s.tokens,
                s.tps, JoulesPerToken(s));
    std::printf("CURRENT_WALL_OWNER=%s WATT_TPS_CLASS=%s\n", s.wallOwner,
                ClassName(c));
    std::printf("WATTSHARK_END\n");
}

} // namespace rawr::watt
