#pragma once
// RAWRXD REAP (Streaming track): bounded expert residency.
//
// Demand-driven expert residency with a hard byte budget, LRU eviction and explicit
// completion. Never holds the full expert bank: resident bytes <= budget. Consumes
// the shared ReapExpertSlice (V02) for per-expert sizes and ReapExpertProvider for
// demand acquisition. Storage-independent; CPU-testable.
#include "deep2/ReapExpertSlice.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace Reap {

class StreamResidency {
public:
    explicit StreamResidency(uint64_t budgetBytes) : budget_(budgetBytes) {}

    // Admit expert `id` (resident by demand). Returns false if a single expert
    // exceeds the budget (fail-closed). Evicts LRU non-pinned experts as needed.
    bool Admit(uint32_t id, uint64_t expertBytes, std::string& error) {
        error.clear();
        if (expertBytes == 0) { error = "ZERO_EXPERT_BYTES"; return false; }
        if (expertBytes > budget_) { error = "EXPERT_EXCEEDS_BUDGET"; return false; }
        auto it = slots_.find(id);
        if (it != slots_.end()) { it->second.lastUsed = ++seq_; return true; }  // already resident
        // Evict LRU unpinned until it fits.
        while (residentBytes_ + expertBytes > budget_) {
            uint32_t victim = 0; uint64_t oldest = UINT64_MAX; bool found = false;
            for (const auto& kv : slots_) {
                if (kv.second.pinned) continue;
                if (kv.second.lastUsed < oldest) { oldest = kv.second.lastUsed; victim = kv.first; found = true; }
            }
            if (!found) { error = "BUDGET_FULL_ALL_PINNED"; return false; }
            residentBytes_ -= slots_[victim].bytes;
            slots_.erase(victim);
        }
        slots_.emplace(id, Slot{expertBytes, ++seq_, false});
        residentBytes_ += expertBytes;
        return true;
    }

    void SetPinned(uint32_t id, bool pinned) {
        auto it = slots_.find(id);
        if (it != slots_.end()) it->second.pinned = pinned;
    }
    // Fence completion: expert `id` finished loading (kept resident; LRU stamp).
    void Complete(uint32_t id) { auto it = slots_.find(id); if (it != slots_.end()) it->second.lastUsed = ++seq_; }

    bool Resident(uint32_t id) const { return slots_.count(id) != 0; }
    uint64_t ResidentBytes() const { return residentBytes_; }
    uint64_t Budget() const { return budget_; }
    size_t Count() const { return slots_.size(); }

private:
    struct Slot { uint64_t bytes; uint64_t lastUsed; bool pinned; };
    uint64_t budget_;
    uint64_t residentBytes_ = 0;
    uint64_t seq_ = 0;
    std::unordered_map<uint32_t, Slot> slots_;
};

}  // namespace Reap
}  // namespace RawrXD