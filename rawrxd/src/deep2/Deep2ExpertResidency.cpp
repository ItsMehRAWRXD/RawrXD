#include "Deep2ExpertResidency.hpp"
#include <limits>

namespace Deep2::Roofline {

void ExpertResidency::reset(u64 capacityBytes) {
    entries_.clear();
    capacityBytes_ = capacityBytes;
    usedBytes_ = hits_ = misses_ = 0;
}

bool ExpertResidency::contains(const ExpertKey& key) const noexcept {
    return entries_.find(key) != entries_.end();
}

void ExpertResidency::touch(const ExpertKey& key, u64 token) noexcept {
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        it->second.lastTouch = token;
        ++it->second.hits;
    }
}

ResidencyResult ExpertResidency::ensure(const ExpertKey& key, u64 bytes, u64 token, bool pin) {
    ResidencyResult r{};
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        r.hit = true;
        ++hits_;
        it->second.lastTouch = token;
        ++it->second.hits;
        it->second.pinned = it->second.pinned || pin;
        return r;
    }

    ++misses_;
    if (!capacityBytes_ || bytes > capacityBytes_) return r;

    while (usedBytes_ + bytes > capacityBytes_) {
        auto victim = entries_.end();
        u64 oldest = std::numeric_limits<u64>::max();
        u64 fewestHits = std::numeric_limits<u64>::max();
        for (auto jt = entries_.begin(); jt != entries_.end(); ++jt) {
            if (jt->second.pinned) continue;
            if (jt->second.lastTouch < oldest ||
                (jt->second.lastTouch == oldest && jt->second.hits < fewestHits)) {
                oldest = jt->second.lastTouch;
                fewestHits = jt->second.hits;
                victim = jt;
            }
        }
        if (victim == entries_.end()) return r;
        r.evictedBytes += victim->second.bytes;
        ++r.evictions;
        usedBytes_ -= victim->second.bytes;
        entries_.erase(victim);
    }

    entries_.emplace(key, Entry{bytes, token, 0, pin});
    usedBytes_ += bytes;
    return r;
}

} // namespace Deep2::Roofline
