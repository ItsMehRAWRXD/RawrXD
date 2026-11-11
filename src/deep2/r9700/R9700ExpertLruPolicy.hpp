// r9700/R9700ExpertLruPolicy.hpp
//
// Deep2-side port of the deterministic expert-cache policy from the r9700-stack
// project's vendored LRU kernels (upstream: https://github.com/bkvargyas/r9700-stack,
// file kernels/third_party/davetha/r4d_lru.hip, itself vendored unmodified from
// https://github.com/davetha/r9700-lru-expert-cache @ 3743f13, Apache-2.0).
//
// This header is a HOST-SIDE re-implementation of the same policy so Deep2's
// residency managers (src/deep2/ElasticResidencyManager.hpp, ResidencyLease,
// ResidencyManager, K2TensorResidencyBridge) can share one deterministic
// eviction contract with the device kernels upstream runs. It contains no HIP
// code and no third-party expression; it implements the documented semantics:
//
//   1. Stamps refresh for every expert routed in the current step.
//   2. Victim selection: argmin over (stamp, slot) among resident slots whose
//      expert is NOT routed this step, so nothing needed now is ever evicted.
//   3. Miss list is emitted in expert-id order (no atomics, no ordering
//      nondeterminism): every TP rank with identical routing evolves identically.
//   4. Free slots are consumed before any victim is evicted.
//
// Licensing: Apache-2.0. See 3rdparty/r9700-stack/LICENSE and
// 3rdparty/r9700-stack/kernels/third_party/davetha/LICENSE for the originals.
#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>

namespace rawrxd {
namespace r9700 {

// One step of MoE routing: a sorted list of expert ids (duplicates allowed).
// The policy treats duplicates idempotently (an expert routed twice still
// refreshes one stamp, exactly like the upstream kernel's mark pass).
class ExpertLruPolicy {
public:
    struct Config {
        uint32_t num_experts = 0;   // total experts the model owns
        uint32_t num_slots   = 0;   // device slots the cache can hold
        uint32_t max_misses_per_step = 0; // upstream MAXS guard; 0 = no cap
    };

    // Full observable state: exactly what the device kernels keep on GPU
    // (table[] / slots[] / stamps[] / map_cold[]).
    struct State {
        std::vector<uint32_t> expert_of_slot;  // slot -> expert (UINT32_MAX = free)
        std::vector<uint32_t> slot_of_expert;  // expert -> slot (UINT32_MAX = absent)
        std::vector<uint64_t> stamp_of_slot;   // slot -> last step it was routed
        uint64_t step = 0;
    };

    explicit ExpertLruPolicy(const Config& cfg) : cfg_(cfg), state_() {
        state_.expert_of_slot.assign(cfg.num_slots, kNone);
        state_.slot_of_expert.assign(cfg.num_experts, kNone);
        state_.stamp_of_slot.assign(cfg.num_slots, 0);
    }

    const State& state() const { return state_; }
    uint64_t step() const { return state_.step; }

    // Advance one routing step. `routed` MUST be sorted ascending with unique
    // ids (the caller, e.g. MoERouter's top-k, is expected to sort; passing an
    // unsorted list returns false and does not mutate state).
    //
    // Writes: `misses` = expert ids routed this step that were not resident
    // before the update, ascending, in the order the gatherer must fill them;
    // `evicted` = expert ids that lost their slot to make room (ascending).
    // Returns false only on contract violation.
    bool Step(const std::vector<uint32_t>& sorted_routed,
              std::vector<uint32_t>& misses,
              std::vector<uint32_t>& evicted);

    // Number of experts currently resident.
    uint32_t ResidentCount() const;

private:
    static constexpr uint32_t kNone = 0xFFFFFFFFu;
    friend class ExpertLruPolicyTest;

    // Picks the victim for a miss: free slot first, else argmin (stamp, slot)
    // over slots whose expert is not routed this step. UINT32_MAX = none.
    uint32_t PickVictim(const uint8_t* routed_marks);

    Config cfg_;
    State  state_;
};

// Deterministic: same inputs and same eviction state always produce identical
// outputs on any TP rank.
inline bool ExpertLruPolicy::Step(const std::vector<uint32_t>& sorted_routed,
                                    std::vector<uint32_t>& misses,
                                    std::vector<uint32_t>& evicted) {
    misses.clear();
    evicted.clear();
    if (sorted_routed.size() && !std::is_sorted(sorted_routed.begin(), sorted_routed.end())) {
        return false;
    }
    if (sorted_routed.size() && std::adjacent_find(sorted_routed.begin(), sorted_routed.end()) != sorted_routed.end()) {
        return false;
    }

    const uint32_t S = cfg_.num_slots;
    if (S == 0) {
        return false;
    }

    ++state_.step;

    // 1) Mark routed set (duplicates rejected above, so marks are unambiguous).
    std::vector<uint8_t> routed(cfg_.num_experts ? cfg_.num_experts : 1, 0);
    for (uint32_t e : sorted_routed) {
        if (e >= cfg_.num_experts) return false;
        routed[e] = 1;
    }

    // 2) Refresh stamps of the resident routed experts (no-op marks for absent).
    for (uint32_t e : sorted_routed) {
        const uint32_t slot = state_.slot_of_expert[e];
        if (slot != kNone) {
            state_.stamp_of_slot[slot] = state_.step;
        }
    }

    // 3) Miss list in expert-id order.
    for (uint32_t e : sorted_routed) {
        if (state_.slot_of_expert[e] == kNone) {
            misses.push_back(e);
        }
    }
    // 4) Allocatable slots: free slots + resident-slots holding non-routed
    // experts (which PickVictim may legally evict). Routed-this-step experts
    // are pinned by the policy, so they count against capacity.
    uint32_t resident_routed = 0;
    for (uint32_t e : sorted_routed) {
        if (state_.slot_of_expert[e] != kNone) ++resident_routed;
    }
    const uint32_t miss_want = (uint32_t)misses.size();
    const uint32_t allocatable = S - resident_routed;
    uint32_t miss_apply = std::min(miss_want, allocatable);
    if (cfg_.max_misses_per_step && miss_apply > cfg_.max_misses_per_step) {
        miss_apply = cfg_.max_misses_per_step;
    }

    // 4) Fill misses: victims chosen so routed-this-step experts are never evicted.
    for (uint32_t i = 0; i < miss_apply; ++i) {
        const uint32_t expert = misses[i];
        const uint32_t victim_slot = PickVictim(routed.data());
        if (victim_slot == kNone) {
            miss_apply = i;  // no legal victim left (shouldn't happen)
            break;
        }
        const uint32_t old_expert = state_.expert_of_slot[victim_slot];
        if (old_expert != kNone) {
            state_.slot_of_expert[old_expert] = kNone;
            evicted.push_back(old_expert);
        }
        state_.expert_of_slot[victim_slot] = expert;
        state_.slot_of_expert[expert] = victim_slot;
        state_.stamp_of_slot[victim_slot] = state_.step;
    }
    misses.resize(miss_apply);
    std::sort(evicted.begin(), evicted.end());
    return true;
}

inline uint32_t ExpertLruPolicy::PickVictim(const uint8_t* routed_marks) {
    const uint32_t S = (uint32_t)state_.expert_of_slot.size();
    // 4a) Free slots first (lowest slot index).
    for (uint32_t s = 0; s < S; ++s) {
        if (state_.expert_of_slot[s] == kNone) return s;
    }
    // 4b) argmin (stamp, slot) over slots holding a NOT-routed expert.
    uint32_t best = kNone;
    uint64_t best_stamp = 0;
    for (uint32_t s = 0; s < S; ++s) {
        const uint32_t e = state_.expert_of_slot[s];
        if (routed_marks[e]) continue;
        if (best == kNone || state_.stamp_of_slot[s] < best_stamp) {
            best = s;
            best_stamp = state_.stamp_of_slot[s];
        }
    }
    return best;
}

inline uint32_t ExpertLruPolicy::ResidentCount() const {
    uint32_t n = 0;
    for (uint32_t e : state_.expert_of_slot) {
        if (e != kNone) ++n;
    }
    return n;
}

}  // namespace r9700
}  // namespace rawrxd
