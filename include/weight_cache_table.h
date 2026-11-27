#pragma once
// RAWRXD NP-05B/05D: device-independent stable residency cache table.
//
// Maps a stable logical WeightIdentity::Key -> physical allocation Entry, with
// explicit ownership: pin (in-flight), lease (generation hold), retirement
// (deferred destruction) and a physical allocation generation that is SEPARATE
// from logical identity. This is the collision-safe, host-pointer-independent
// lookup that the production VulkanCompute residency cache adopts; it is Vulkan-free
// so CPU regression tests exercise the SAME code (actual reuse + ownership), not a
// duplicated test-only copy.
#include "weight_identity.h"
#include <unordered_map>
#include <cstdint>

namespace RawrXD {
namespace Deep2 {
namespace WeightCache {

struct Entry {
    WeightIdentity::Key key;
    uint64_t generation = 0;    // physical allocation generation (NOT logical id)
    uint64_t pin_count = 0;     // in-flight references (eviction blocked while >0)
    uint64_t lease_count = 0;   // outstanding generation leases
    bool     retired = false;   // evicted, destruction deferred to the fence
    uint64_t retired_generation = 0;
};

class Table {
public:
    // Stable identity lookup: O(1), collision-safe (KeyHash + Key equality). A
    // relocated host buffer with identical content/model/tensor/format returns the
    // SAME entry (host-pointer-independent reuse).
    Entry* Find(const WeightIdentity::Key& k) {
        auto it = map_.find(k);
        return it == map_.end() ? nullptr : &it->second;
    }

    // Insert a new physical allocation for k. Returns the entry and bumps the
    // physical generation. Caller must have established k is not already resident.
    Entry* Insert(const WeightIdentity::Key& k) {
        Entry e;
        e.key = k;
        e.generation = ++next_generation_;
        return &map_.emplace(k, e).first->second;
    }

    bool Pin(const WeightIdentity::Key& k) {
        Entry* e = Find(k);
        if (!e || e->retired) return false;
        ++e->pin_count;
        return true;
    }
    void Unpin(const WeightIdentity::Key& k) {
        Entry* e = Find(k);
        if (e && e->pin_count) --e->pin_count;
    }

    uint64_t AcquireLease(const WeightIdentity::Key& k) {
        Entry* e = Find(k);
        if (!e || e->retired) return 0;
        uint64_t id = ++next_lease_;
        leases_.emplace(id, k);
        ++e->lease_count;
        return id;
    }
    void ReleaseLease(uint64_t id) {
        auto it = leases_.find(id);
        if (it == leases_.end()) return;          // stale/double release rejected
        Entry* e = Find(it->second);
        if (e && e->lease_count) --e->lease_count;
        leases_.erase(it);
    }

    // Evict an unpinned, unleased, non-retired entry. Returns true if evicted.
    bool Evict(const WeightIdentity::Key& k) {
        auto it = map_.find(k);
        if (it == map_.end()) return false;
        Entry& e = it->second;
        if (e.pin_count || e.lease_count || e.retired) return false;
        e.retired = true;
        e.retired_generation = e.generation;
        return true;
    }

    // Reap retired entries whose generation has completed on the fence.
    size_t Reap(uint64_t completed_generation) {
        size_t n = 0;
        for (auto it = map_.begin(); it != map_.end();) {
            if (it->second.retired && it->second.retired_generation <= completed_generation) {
                it = map_.erase(it);
                ++n;
            } else {
                ++it;
            }
        }
        return n;
    }

    size_t Size() const { return map_.size(); }

private:
    std::unordered_map<WeightIdentity::Key, Entry, WeightIdentity::KeyHash> map_;
    uint64_t next_generation_ = 0;
    uint64_t next_lease_ = 0;
    std::unordered_map<uint64_t, WeightIdentity::Key> leases_;
};

}  // namespace WeightCache
}  // namespace Deep2
}  // namespace RawrXD