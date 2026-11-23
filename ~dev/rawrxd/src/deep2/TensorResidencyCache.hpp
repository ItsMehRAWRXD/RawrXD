#pragma once
// Bounded, thread-safe cache for immutable compressed F32 tensor payloads.
// Leases hold shared ownership; eviction never reclaims an active payload.
#include "NativeTensorCompression.hpp"
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace Deep2 {
class TensorResidencyCache {
public:
    using Storage = RawrXD::TensorCompression::ChunkedF32Storage;
    class Lease {
    public:
        Lease() = default;
        explicit Lease(std::shared_ptr<const Storage> p) : payload_(std::move(p)) {}
        const Storage* operator->() const noexcept { return payload_.get(); }
        const Storage& operator*() const noexcept { return *payload_; }
        explicit operator bool() const noexcept { return bool(payload_); }
        std::shared_ptr<const Storage> share() const noexcept { return payload_; }
    private:
        std::shared_ptr<const Storage> payload_;
    };
    struct Stats {
        std::size_t capacityBytes=0, residentBytes=0, entries=0, pinnedEntries=0;
        std::uint64_t hits=0, misses=0, evictions=0;
    };
    explicit TensorResidencyCache(std::size_t capacity) : capacity_(capacity) {}
    TensorResidencyCache(const TensorResidencyCache&)=delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&)=delete;

    bool Insert(std::string key, std::shared_ptr<const Storage> payload) {
        if (key.empty() || !payload) return false;
        const auto bytes=payload->residentBytes();
        if (bytes>capacity_) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        auto old=entries_.find(key);
        std::size_t oldBytes=0;
        if (old!=entries_.end()) {
            if (old->second.payload==payload) { touch(old); return true; }
            if (old->second.payload.use_count()!=1) return false;
            oldBytes=old->second.bytes;
        }

        // Preflight before mutating the LRU. If pinned entries make the
        // insertion impossible, reject it without evicting unrelated entries.
        const std::size_t projected=resident_-oldBytes;
        if (projected>capacity_-bytes) {
            const std::size_t required=projected-(capacity_-bytes);
            std::size_t reclaimable=0;
            for (auto it=lru_.rbegin();it!=lru_.rend() && reclaimable<required;++it) {
                if (*it==key) continue;
                auto candidate=entries_.find(*it);
                if (candidate!=entries_.end() && candidate->second.payload.use_count()==1)
                    reclaimable+=candidate->second.bytes;
            }
            if (reclaimable<required) return false;
        }
        if (old!=entries_.end()) {
            resident_-=oldBytes;
            lru_.erase(old->second.lru);
            entries_.erase(old);
        }
        if (!makeRoom(bytes)) return false;
        lru_.push_front(key);
        Entry e; e.payload=std::move(payload); e.bytes=bytes; e.lru=lru_.begin();
        entries_.emplace(std::move(key),std::move(e));
        resident_+=bytes;
        return true;
    }

    Lease Acquire(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=entries_.find(key);
        if (it==entries_.end()) { ++misses_; return {}; }
        ++hits_; touch(it);
        return Lease(it->second.payload);
    }

    bool Erase(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=entries_.find(key);
        if (it==entries_.end() || it->second.payload.use_count()!=1) return false;
        resident_-=it->second.bytes; lru_.erase(it->second.lru); entries_.erase(it);
        return true;
    }

    std::size_t Trim(std::size_t target=0) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto before=resident_;
        auto it=lru_.rbegin();
        while (resident_>target && it!=lru_.rend()) {
            auto found=entries_.find(*it);
            if (found==entries_.end()) { ++it; continue; }
            if (found->second.payload.use_count()!=1) { ++it; continue; }
            auto eraseIt=std::next(it).base();
            resident_-=found->second.bytes; entries_.erase(found);
            it=std::make_reverse_iterator(lru_.erase(eraseIt)); ++evictions_;
        }
        return before-resident_;
    }

    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats s; s.capacityBytes=capacity_; s.residentBytes=resident_;
        s.entries=entries_.size(); s.hits=hits_; s.misses=misses_; s.evictions=evictions_;
        for (const auto& kv:entries_) if (kv.second.payload.use_count()>1) ++s.pinnedEntries;
        return s;
    }
private:
    struct Entry { std::shared_ptr<const Storage> payload; std::size_t bytes=0; std::list<std::string>::iterator lru; };
    using Map=std::unordered_map<std::string,Entry>;
    void touch(Map::iterator it) { lru_.splice(lru_.begin(),lru_,it->second.lru); it->second.lru=lru_.begin(); }
    bool makeRoom(std::size_t needed) {
        auto it=lru_.rbegin();
        while (resident_>capacity_-needed && it!=lru_.rend()) {
            auto found=entries_.find(*it);
            if (found==entries_.end()) { ++it; continue; }
            if (found->second.payload.use_count()!=1) { ++it; continue; }
            auto eraseIt=std::next(it).base();
            resident_-=found->second.bytes; entries_.erase(found);
            it=std::make_reverse_iterator(lru_.erase(eraseIt)); ++evictions_;
        }
        return resident_<=capacity_-needed;
    }
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::size_t resident_=0;
    std::uint64_t hits_=0,misses_=0,evictions_=0;
    std::list<std::string> lru_;
    Map entries_;
};
} // namespace Deep2
namespace gguf_shard_cache { using TensorResidencyCache=Deep2::TensorResidencyCache; }
