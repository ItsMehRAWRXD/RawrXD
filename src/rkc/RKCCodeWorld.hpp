// RKCCodeWorld.hpp — live-path code graph (symbols + call edges as REAL)
#pragma once
#include "RKCWorld.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace RKC {

struct CodeWorldStats {
    uint32_t files = 0;
    uint32_t symbols = 0;
    uint32_t callEdges = 0;
    uint32_t reachable = 0;
    uint32_t notReachable = 0;
};

// Ingest bounded live-path sources under repoRoot (…/rawrxd).
// Puts REAL atoms: symbol_defined.<name>, call.<from>.<to>,
// and Derived: symbol_reachable_from_generate / NotReachable gaps.
CodeWorldStats ObserveCodeWorld(World& world, const std::string& repoRoot);

bool CodeWorldReachable(const World& world, const std::string& from,
                        const std::string& to);

} // namespace RKC
} // namespace RawrXD
