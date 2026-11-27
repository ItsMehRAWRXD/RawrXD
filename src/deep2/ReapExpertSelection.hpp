#pragma once
// RAWRXD REAP V01: storage-independent retained-expert selection.
//
// Extracted from ReapMoETransformer.cpp (Selection type + the post-parse
// validation in loadSelection) so Physical, Virtual and Streaming share one
// authoritative selection contract. The JSON manifest parse stays file-coupled in
// the offline writer; an in-memory producer (Virtual/Streaming) builds a Selection
// and validates it with the SAME predicate. No file I/O here.
#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

namespace RawrXD {
namespace Reap {

// layer -> retained expert indices in ORIGINAL order.
using Selection = std::map<uint32_t, std::vector<uint32_t>>;

// Validate a selection (fail-closed):
//  - non-empty;
//  - each layer has no duplicate expert ids;
//  - when activeExperts>0, each layer retains exactly activeExperts experts;
//  - (topology/group-order preservation is enforced separately against the
//     router geometry, which is storage-independent and already reusable).
inline bool ValidateSelection(const Selection& selection, uint32_t activeExperts,
                              std::string& error) {
    error.clear();
    if (selection.empty()) { error = "selection is empty"; return false; }
    for (const auto& entry : selection) {
        std::unordered_set<uint32_t> seen;
        for (const uint32_t expert : entry.second) {
            if (!seen.insert(expert).second) {
                error = "selection layer contains duplicate expert IDs";
                return false;
            }
        }
        if (entry.second.empty() || (activeExperts && entry.second.size() != activeExperts)) {
            error = "selection layer has invalid expert count";
            return false;
        }
    }
    return true;
}

}  // namespace Reap
}  // namespace RawrXD