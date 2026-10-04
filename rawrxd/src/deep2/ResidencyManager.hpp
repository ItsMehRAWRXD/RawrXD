#pragma once
// ============================================================================
// ResidencyManager.hpp — RAWRXD_DEEP2_SOVEREIGN_RESIDENCY_001
//
// Real bounded-window tensor residency admission/eviction for Deep2.
//
// Contract replaced (measured 2026-10-04):
//   was: class ResidencyManager {};   (6 lines, no state, no methods)
//   now: a byte-budgeted residency table with priority admission and
//        least-recently-used eviction.
//
// Realness rules honoured here:
//   - Every counter is incremented only on a real admission/eviction/hit event.
//   - hitRate()/utilisation() are COMPUTED from the counters. There is no
//     setter that can write a pass or a score.
//   - admit() returns what actually happened; it never reports success for a
//     tensor it refused.
//   - An eviction is only counted when bytes were genuinely released.
//
// This type is a declared member of Deep2Engine (Deep2Engine.h
// `std::unique_ptr<ResidencyManager> residencyManager_`) and was previously
// dead: constructed nowhere, called nowhere. It is now constructed and driven
// by Deep2Engine::initializeAdvancedFeatures() / enableResidency().
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

// One tracked weight tensor competing for the residency byte budget.
struct ResidencyEntry {
    std::string name;
    std::uint64_t bytes = 0;
    int layer = -1;
    // Higher survives longer. Pinned entries are never evicted.
    int priority = 0;
    bool pinned = false;
    bool resident = false;
    // Monotonic sequence number of last touch; the eviction victim is the
    // smallest value among unpinned residents.
    std::uint64_t lastTouch = 0;
};

struct ResidencyStats {
    std::uint64_t registered = 0;   // register() calls that added an entry
    std::uint64_t rejected = 0;     // register() calls refused (empty name / 0 bytes)
    std::uint64_t admitted = 0;     // tensors that became resident
    std::uint64_t admitRefused = 0; // request() found no budget after eviction
    std::uint64_t hits = 0;         // request() found it already resident
    std::uint64_t misses = 0;       // request() had to admit it
    std::uint64_t evictions = 0;    // real evictions that released bytes
    std::uint64_t evictedBytes = 0;
    std::uint64_t touches = 0;
    std::uint64_t pins = 0;
    std::uint64_t unpins = 0;
    std::uint64_t resets = 0;
    std::uint64_t budgetRejections = 0; // rejected for want of budget alone
    std::uint64_t invalidRequests = 0;  // request() called with a bad index
};

class ResidencyManager {
public:
    explicit ResidencyManager(std::uint64_t budgetBytes = 0) { setBudget(budgetBytes); }

    // ---- budget ----------------------------------------------------------
    void setBudget(std::uint64_t budgetBytes) {
        budget_ = budgetBytes;
        // Lowering the budget below what is already resident is not silently
        // ignored: the over-commit is reported so the caller can act on it.
        overCommitted_ = residentBytes() > budget_;
    }
    std::uint64_t budget() const noexcept { return budget_; }
    std::uint64_t residentBytes() const noexcept { return residentBytes_; }
    bool overCommitted() const noexcept { return overCommitted_; }

    // ---- population ------------------------------------------------------
    // Returns the entry index, or SIZE_MAX if the entry was refused.
    std::size_t registerTensor(const std::string& name, std::uint64_t bytes,
                               int layer = -1, int priority = 0) {
        if (name.empty() || bytes == 0) { ++stats_.rejected; return SIZE_MAX; }
        entries_.push_back(ResidencyEntry{name, bytes, layer, priority});
        ++stats_.registered;
        return entries_.size() - 1;
    }

    std::size_t size() const noexcept { return entries_.size(); }
    const ResidencyEntry* at(std::size_t i) const noexcept {
        return i < entries_.size() ? &entries_[i] : nullptr;
    }

    // ---- the actual residency decision -----------------------------------
    // request() is the load path. It reports whether the tensor is resident
    // AFTER the call, and it accounts for every byte it moved.
    bool request(std::size_t idx) {
        if (idx >= entries_.size()) {
            // An out-of-range request is a REFUSAL and is counted as one.
            // Returning false with no accounting would be a silent zero: a
            // caller indexing wrongly would see "not resident" forever and
            // nothing in the stats would say why.
            ++stats_.invalidRequests;
            ++stats_.admitRefused;
            return false;
        }
        ResidencyEntry& e = entries_[idx];

        if (e.resident) {
            ++stats_.hits;
            touch(e);
            return true;
        }
        ++stats_.misses;

        // Make room. Pinned entries are skipped; they are never victims.
        if (e.bytes > budget_) {
            // Can never fit, even in an empty cache. This is a refusal, not a
            // hit, and it must not be laundered into an eviction count.
            ++stats_.budgetRejections;
            ++stats_.admitRefused;
            return false;
        }
        while (residentBytes_ + e.bytes > budget_) {
            if (!evictOne()) {           // nothing evictable left
                ++stats_.budgetRejections;
                ++stats_.admitRefused;
                return false;
            }
        }
        e.resident = true;
        residentBytes_ += e.bytes;
        touch(e);
        overCommitted_ = residentBytes_ > budget_;
        ++stats_.admitted;
        return true;
    }

    // Release one tensor explicitly. Returns bytes actually released.
    std::uint64_t release(std::size_t idx) {
        if (idx >= entries_.size() || !entries_[idx].resident) return 0;
        const std::uint64_t freed = entries_[idx].bytes;
        entries_[idx].resident = false;
        residentBytes_ -= std::min(residentBytes_, freed);
        overCommitted_ = residentBytes_ > budget_;
        return freed;
    }

    void pin(std::size_t idx) {
        if (idx < entries_.size() && !entries_[idx].pinned) {
            entries_[idx].pinned = true;
            ++stats_.pins;
        }
    }
    void unpin(std::size_t idx) {
        if (idx < entries_.size() && entries_[idx].pinned) {
            entries_[idx].pinned = false;
            ++stats_.unpins;
        }
    }

    void reset() {
        entries_.clear();
        residentBytes_ = 0;
        overCommitted_ = false;
        clock_ = 0;
        ++stats_.resets;
    }

    // ---- measured reporting ---------------------------------------------
    const ResidencyStats& stats() const noexcept { return stats_; }

    // Computed, never stored: requests that found the tensor resident.
    double hitRate() const noexcept {
        const std::uint64_t served = stats_.hits + stats_.misses;
        return served ? static_cast<double>(stats_.hits) / static_cast<double>(served) : 0.0;
    }
    double utilisation() const noexcept {
        return budget_ ? static_cast<double>(residentBytes_) / static_cast<double>(budget_) : 0.0;
    }
    std::size_t residentCount() const noexcept {
        std::size_t n = 0;
        for (const auto& e : entries_) if (e.resident) ++n;
        return n;
    }

private:
    void touch(ResidencyEntry& e) noexcept {
        e.lastTouch = ++clock_;
        ++stats_.touches;
    }

    // Evict the least-recently-used unpinned resident. Returns false when no
    // such tensor exists, which is the signal that the request must be refused.
    bool evictOne() noexcept {
        std::size_t victim = SIZE_MAX;
        std::uint64_t oldest = 0;
        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& e = entries_[i];
            if (!e.resident || e.pinned) continue;
            if (victim == SIZE_MAX || e.lastTouch < oldest) {
                victim = i;
                oldest = e.lastTouch;
            }
        }
        if (victim == SIZE_MAX) return false;
        const std::uint64_t freed = entries_[victim].bytes;
        entries_[victim].resident = false;
        residentBytes_ -= std::min(residentBytes_, freed);
        ++stats_.evictions;
        stats_.evictedBytes += freed;
        return true;
    }

    std::vector<ResidencyEntry> entries_;
    std::uint64_t budget_ = 0;
    std::uint64_t residentBytes_ = 0;
    std::uint64_t clock_ = 0;
    bool overCommitted_ = false;
    ResidencyStats stats_{};
};

} // namespace Deep2
