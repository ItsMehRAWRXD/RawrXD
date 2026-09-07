// RKCNegativeKnowledge.hpp — formal absence catalog (gaps stay gaps)
#pragma once
#include "RKCWorld.hpp"
#include <cstdint>
#include <string>

namespace RawrXD {
namespace RKC {

struct AbsenceStats {
    uint32_t atoms = 0;
    uint32_t kindsPresent = 0; // bitmask / count of distinct negative kinds seen
    uint32_t notPresent = 0;
    uint32_t notReachable = 0;
    uint32_t notObserved = 0;
    uint32_t notSupported = 0;
    uint32_t notConnected = 0;
    uint32_t notActive = 0;
};

// Probe known absence sources into world as Negative atoms.
AbsenceStats ObserveAbsenceCatalog(World& world, const WorldObserveConfig& cfg,
                                   const std::string& repoRoot);

// Recount negative kinds currently in world.
AbsenceStats TallyAbsence(const World& world);

} // namespace RKC
} // namespace RawrXD
