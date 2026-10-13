// ============================================================================
// StrataExpertResidency.hpp  --  RAWRXD_DEEP2_STRATA_S01
// ============================================================================
// Native MoE expert residency ledger for the Deep2 runtime graph executor.
//
// The backend's device-local weight cache (vulkan_compute.cpp,
// EnsureQuantWeight) already provides budgeted, fingerprint-validated VRAM
// residency for every dispatched weight - including MoE expert slices. What
// the Strata gates require ON TOP of that is an EXPERT-LEVEL view:
//
//   S01  real expert placement and eviction TRACES (which expert of which
//        block/bank was placed, hit, evicted, and when);
//   S02  measured cache hit/miss rates attributable to experts;
//   S08  per-expert hotness accounting so the eviction policy can be steered
//        (and compared against the LRU baseline on a real router trace).
//
// This ledger is pure accounting + policy state: it dispatches nothing, it
// allocates no GPU resources, and it can never change a numerical result. It
// is written from the single executor thread that runs OpMoEExecute, and read
// by certification harnesses after the run.
//
// No external dependencies; header-only; C++17-compatible subset of C++20.
// ============================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace RawrXD {
namespace Deep2 {
namespace Strata {

// Bank identifies which expert projection a slice belongs to.
enum class ExpertBank : uint8_t { Gate = 0, Up = 1, Down = 2 };

inline const char* BankName(ExpertBank b)
{
    switch (b) {
    case ExpertBank::Gate: return "gate";
    case ExpertBank::Up:   return "up";
    case ExpertBank::Down: return "down";
    }
    return "?";
}

// Residency lifecycle events recorded per expert slice.
enum class ResidencyEvent : uint8_t {
    Hit = 0,       // slice found device-resident; no upload happened
    Miss = 1,      // slice was staged into VRAM (first use / after eviction)
    Evicted = 2,   // slice left the residency budget (observed via counters)
    Prefetch = 3,  // slice was prefetched ahead of its dependent dispatch
    PrefetchHit = 4, // prefetch found it already resident
};

// One placement/eviction trace record. `t_ns` is a monotonic timestamp so
// placement ORDER is provable, not just counts.
struct ResidencyRecord {
    uint64_t seq = 0;       // monotonically increasing ledger sequence
    uint64_t t_ns = 0;      // steady_clock nanoseconds
    int32_t  block = -1;
    int32_t  expert = -1;
    uint8_t  bank = 0;      // ExpertBank
    uint8_t  event = 0;     // ResidencyEvent
    size_t   bytes = 0;     // slice bytes placed/observed
};

class ExpertResidencyLedger {
public:
    ExpertResidencyLedger() = default;

    // Record a residency observation for one expert slice. `hit` mirrors the
    // backend cache outcome the dispatch actually got. A Miss for a slice
    // that was previously observed resident is itself evidence of an
    // eviction: the ledger emits the Evicted trace first, so placement AND
    // eviction traces stay causally ordered.
    void Observe(int block, int expert, ExpertBank bank, bool hit, size_t bytes)
    {
        Key3 k3{block, expert, (uint8_t)bank};
        auto prev = resident_.find(k3);
        const bool was_resident = (prev != resident_.end()) && prev->second;
        if (!hit && was_resident) {
            ResidencyRecord ev;
            ev.seq = ++seq_;
            ev.t_ns = NowNs();
            ev.block = block;
            ev.expert = expert;
            ev.bank = (uint8_t)bank;
            ev.event = (uint8_t)ResidencyEvent::Evicted;
            ev.bytes = bytes;
            records_.push_back(ev);
            ++evictions_;
            hot_[Key{block, expert}] = 0;   // no longer covered by the resident set
        }
        resident_[k3] = true;   // hit: still resident; miss: re-placed now
        ResidencyRecord r;
        r.seq = ++seq_;
        r.t_ns = NowNs();
        r.block = block;
        r.expert = expert;
        r.bank = (uint8_t)bank;
        r.event = (uint8_t)(hit ? ResidencyEvent::Hit : ResidencyEvent::Miss);
        r.bytes = bytes;
        records_.push_back(r);
        if (records_.size() > kMaxRecords)
            records_.erase(records_.begin(), records_.begin() + (records_.size() - kMaxRecords));
        if (hit)
            ++hits_;
        else
            ++misses_;
        // Hotness signal (S08): every routed expert touch ages the counters
        // and increments the touched (block, expert) frequency.
        AgeHotness();
        hot_[Key{block, expert}] += 1;
    }

    // Record a prefetch outcome (S03).
    void ObservePrefetch(int block, int expert, ExpertBank bank, bool already_resident, size_t bytes)
    {
        ResidencyRecord r;
        r.seq = ++seq_;
        r.t_ns = NowNs();
        r.block = block;
        r.expert = expert;
        r.bank = (uint8_t)bank;
        r.event = (uint8_t)(already_resident ? ResidencyEvent::PrefetchHit : ResidencyEvent::Prefetch);
        r.bytes = bytes;
        records_.push_back(r);
        if (already_resident)
            ++prefetch_hits_;
        else
            ++prefetch_submits_;
    }

    // Record an eviction, attributed to the expert that was the victim when
    // the caller knows it; pass block=-1 for a backend-level observation.
    void ObserveEviction(int block, int expert, ExpertBank bank, size_t bytes)
    {
        ResidencyRecord r;
        r.seq = ++seq_;
        r.t_ns = NowNs();
        r.block = block;
        r.expert = expert;
        r.bank = (uint8_t)bank;
        r.event = (uint8_t)ResidencyEvent::Evicted;
        r.bytes = bytes;
        records_.push_back(r);
        ++evictions_;
        if (block >= 0 && expert >= 0)
            hot_[Key{block, expert}] = 0;   // resident set no longer covers it
    }

    // Hotness prediction (S08): the top-N hottest (block, expert) pairs by
    // aged frequency. Used to compare a hotness-steered policy against the
    // LRU baseline over a real router trace.
    struct HotEntry {
        int block = -1;
        int expert = -1;
        uint32_t freq = 0;
    };
    std::vector<HotEntry> HottestExperts(size_t n) const
    {
        std::vector<HotEntry> all;
        all.reserve(hot_.size());
        for (const auto& kv : hot_) {
            HotEntry e;
            e.block = kv.first.block;
            e.expert = kv.first.expert;
            e.freq = kv.second;
            all.push_back(e);
        }
        std::sort(all.begin(), all.end(), [](const HotEntry& a, const HotEntry& b) {
            return a.freq != b.freq ? a.freq > b.freq : (a.block != b.block ? a.block < b.block
                                                                           : a.expert < b.expert);
        });
        if (all.size() > n)
            all.resize(n);
        return all;
    }

    struct Summary {
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t evictions = 0;
        uint64_t prefetch_submits = 0;
        uint64_t prefetch_hits = 0;
        uint64_t observations = 0;
        double hit_rate = 0.0;         // hits / (hits + misses)
        uint64_t distinct_experts = 0; // (block, expert) pairs the router used
    };

    Summary Snapshot() const
    {
        Summary s;
        s.hits = hits_;
        s.misses = misses_;
        s.evictions = evictions_;
        s.prefetch_submits = prefetch_submits_;
        s.prefetch_hits = prefetch_hits_;
        s.observations = (uint64_t)records_.size();
        const uint64_t total = hits_ + misses_;
        s.hit_rate = total ? (double)hits_ / (double)total : 0.0;
        s.distinct_experts = (uint64_t)hot_.size();
        return s;
    }

    // The full placement/eviction trace (S01 evidence). Bounded: the ledger
    // keeps at most kMaxRecords records, oldest first, so a long run cannot
    // grow memory without bound.
    const std::vector<ResidencyRecord>& Trace() const { return records_; }

    void Reset()
    {
        records_.clear();
        hot_.clear();
        resident_.clear();
        hits_ = misses_ = evictions_ = prefetch_submits_ = prefetch_hits_ = 0;
        seq_ = 0;
    }

    static uint64_t NowNs()
    {
        return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

private:
    static constexpr size_t kMaxRecords = 1u << 20;   // 1M records cap
    struct Key {
        int block;
        int expert;
        bool operator<(const Key& o) const
        {
            return block != o.block ? block < o.block : expert < o.expert;
        }
        bool operator==(const Key& o) const { return block == o.block && expert == o.expert; }
    };
    // (block, expert, bank) identity for resident-set tracking.
    struct Key3 {
        int block;
        int expert;
        uint8_t bank;
        bool operator<(const Key3& o) const
        {
            if (block != o.block) return block < o.block;
            if (expert != o.expert) return expert < o.expert;
            return bank < o.bank;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const
        {
            return (size_t)((uint64_t)(uint32_t)k.block << 32) ^ (uint32_t)k.expert;
        }
    };

    // Exponential aging (S08): every kAgePeriod observations the frequency
    // counters halve, so a hot expert from early in the run decays if the
    // router stops selecting it. This is what makes the counter a PREDICTION
    // signal rather than a lifetime total.
    void AgeHotness()
    {
        if (++obs_since_age_ >= kAgePeriod) {
            obs_since_age_ = 0;
            for (auto& kv : hot_)
                kv.second >>= 1;
        }
    }
    static constexpr uint32_t kAgePeriod = 4096;

    std::vector<ResidencyRecord> records_;
    // (block, expert) -> aged frequency. std::map keeps this header free of
    // external dependencies; MoE expert cardinalities are small enough that
    // the log-n factor is irrelevant next to the expert matmuls themselves.
    std::map<Key, uint32_t> hot_;
    // (block, expert, bank) -> last observed device residency. Drives eviction
    // attribution: a Miss for a previously-resident slice proves the budget
    // evicted it in between.
    std::map<Key3, bool> resident_;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0;
    uint64_t prefetch_submits_ = 0, prefetch_hits_ = 0;
    uint64_t seq_ = 0;
    uint32_t obs_since_age_ = 0;
};

}   // namespace Strata
}   // namespace Deep2
}   // namespace RawrXD
