#pragma once
/* Bandwidth/capacity are measured facts — never product gates. */
#include <cstdint>
#include <cstdio>

#define MEMORY_SPEED_TRICK_001 1
#define CAPACITY_REQUIREMENT_IS_BYTES 1
#define BANDWIDTH_REQUIREMENT_IS_WALL_ENVELOPE 1
#define BANDWIDTH_DEFICIT_NE_BYTE_DEFICIT 1
#define BYTE_FIT_IGNORES_MEMORY_SPEED 1
#define WALL_BUDGET_OBSERVES_MEMORY_SPEED 1
#define NO_RAM_TIER_TABLE 1
#define NO_MT_S_PRESET 1

namespace rawr::mem {

struct Facts {
    uint64_t hostAvailBytes = 0;
    uint64_t deviceFreeBytes = 0;
    uint64_t hostBwHintBps = 0; // 0 = unknown
    bool byteFit = true;
};

inline void Emit(const Facts& f) noexcept {
    std::printf("GE_MEMORY_BEGIN\n");
    std::printf("NO_TODAY_PATH=1 NO_TOMORROW_PATH=1 NO_RAM_TIER_TABLE=1\n");
    std::printf("HOST_AVAIL_BYTES=%llu DEVICE_FREE_BYTES=%llu\n",
                (unsigned long long)f.hostAvailBytes,
                (unsigned long long)f.deviceFreeBytes);
    std::printf("HOST_BW_HINT_BPS=%llu\n",
                (unsigned long long)f.hostBwHintBps);
    std::printf("BYTE_REQUIREMENT_MET=%u BANDWIDTH_REQUIREMENT_PRODUCT=0\n",
                f.byteFit ? 1u : 0u);
    std::printf("BANDWIDTH_REQUIREMENT_PERFORMANCE=1\n");
    std::printf("THE_SPEED_TRICK=fewer_bytes_crossing_wrong_boundary\n");
    std::printf("GE_MEMORY_END\n");
}

} // namespace rawr::mem
