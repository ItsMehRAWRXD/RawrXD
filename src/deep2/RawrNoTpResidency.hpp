// RawrNoTpResidency.hpp — live working set vs assigned lane space.
// MODEL_SIZE is not residency. VRAM is not a gate.
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {

struct ByteRange {
    uint64_t off = 0;
    uint64_t len = 0;
};

struct WeightLease {
    uint32_t tensorId = 0;
    ByteRange range{};
    int deviceId = -1;
    uint64_t generation = 0;
    const void* bytes = nullptr;
    int fromTier = 0;
};

struct RawrWorkingSet {
    uint64_t weightBytes = 0;
    uint64_t activationBytes = 0;
    uint64_t kvHotBytes = 0;
    uint64_t scratchBytes = 0;
};

struct RawrSpaceState {
    uint64_t capacityBytes = 0;
    uint64_t occupiedBytes = 0;
    uint64_t reclaimableBytes = 0;
    uint64_t reserveBytes = 0;
};

inline uint64_t RawrWorkingSetBytes(const RawrWorkingSet& w) noexcept {
    return w.weightBytes + w.activationBytes + w.kvHotBytes + w.scratchBytes;
}

inline bool RawrSpaceSufficient(const RawrWorkingSet& w,
                                const RawrSpaceState& s) noexcept {
    const uint64_t usable = s.capacityBytes > s.reserveBytes
        ? s.capacityBytes - s.reserveBytes : 0;
    const uint64_t occ = s.occupiedBytes > s.reclaimableBytes
        ? s.occupiedBytes - s.reclaimableBytes : 0;
    const uint64_t freeNow = usable > occ ? usable - occ : 0;
    return RawrWorkingSetBytes(w) <= freeNow;
}

inline bool RawrNoTpWanted() {
    const char* e = std::getenv("RAWRXD_NO_TP");
    return !(e && e[0] == '0');
}

inline bool RawrBoundedResidencyWanted() {
    const char* e = std::getenv("RAWRXD_BOUNDED_RESIDENCY");
    return !(e && e[0] == '0');
}

} // namespace Deep2

#include "RawrNoTpEmit.hpp"
