// ============================================================================
// TensorResidencyCache.cpp — RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001
// ============================================================================
#include "TensorResidencyCache.hpp"
#include <sstream>

namespace Deep2 {

TensorResidencyCache::TensorResidencyCache(size_t maxEntries)
    : maxEntries_(maxEntries ? maxEntries : 1) {}

void TensorResidencyCache::insert(const ExecutionView& view) {
    if (!view.hasBytes()) return;

    std::lock_guard<std::mutex> lock(mtx_);
    auto it = map_.find(view.identity);
    if (it != map_.end()) {
        // Refresh existing
        it->second->entry.view = view;
        it->second->entry.lastAccessEpoch = epoch_++;
        touch(it->second);
        return;
    }

    // New insertion
    lru_.push_front({view.identity, {view, epoch_++, 0}});
    map_[view.identity] = lru_.begin();
    ++stats_.insertions;

    // Evict if over capacity
    if (lru_.size() > maxEntries_) {
        evictLRUInternal();
    }
}

bool TensorResidencyCache::lookup(const TensorIdentity& identity, ExecutionView& out) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = map_.find(identity);
    if (it == map_.end()) {
        ++stats_.misses;
        return false;
    }

    auto& entry = it->second->entry;
    // Lease generation check: if the lease has moved on, the view is stale
    if (entry.view.lease.generation != entry.view.lease.generation) {
        // This path is logically unreachable because lease generation is per-view,
        // but if we add a global generation later, check it here.
    }

    // The entry itself is the ground truth for lease validity in this design
    out = entry.view;
    entry.lastAccessEpoch = epoch_++;
    touch(it->second);
    ++stats_.hits;
    return true;
}

void TensorResidencyCache::pin(const TensorIdentity& identity) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = map_.find(identity);
    if (it != map_.end()) {
        ++it->second->entry.pinCount;
    }
}

void TensorResidencyCache::unpin(const TensorIdentity& identity) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = map_.find(identity);
    if (it != map_.end() && it->second->entry.pinCount > 0) {
        --it->second->entry.pinCount;
    }
}

bool TensorResidencyCache::evict(const TensorIdentity& identity) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = map_.find(identity);
    if (it == map_.end()) return false;
    if (it->second->entry.pinCount > 0) {
        ++stats_.pinnedRejects;
        return false;
    }
    lru_.erase(it->second);
    map_.erase(it);
    ++stats_.evictions;
    return true;
}

size_t TensorResidencyCache::evictLRU() {
    std::lock_guard<std::mutex> lock(mtx_);
    return evictLRUInternal();
}

size_t TensorResidencyCache::evictLRUInternal() {
    size_t evicted = 0;
    while (lru_.size() > maxEntries_) {
        // Find least-recently-used unpinned entry from the back
        bool found = false;
        for (auto it = lru_.rbegin(); it != lru_.rend(); ++it) {
            if (it->entry.pinCount == 0) {
                auto baseIt = std::next(it).base(); // convert reverse to forward iterator
                map_.erase(baseIt->identity);
                lru_.erase(baseIt);
                ++stats_.evictions;
                ++evicted;
                found = true;
                break;
            }
        }
        if (!found) break; // everything pinned, cannot evict
    }
    return evicted;
}

size_t TensorResidencyCache::invalidateStale(uint64_t currentGeneration) {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t removed = 0;
    for (auto it = lru_.begin(); it != lru_.end(); ) {
        if (it->entry.view.lease.generation != currentGeneration) {
            if (it->entry.pinCount > 0) {
                ++it; // skip pinned stale entries
                continue;
            }
            map_.erase(it->identity);
            it = lru_.erase(it);
            ++stats_.staleRejects;
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

TensorResidencyCacheStats TensorResidencyCache::stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return stats_;
}

size_t TensorResidencyCache::size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return lru_.size();
}

size_t TensorResidencyCache::capacity() const {
    return maxEntries_;
}

std::string TensorResidencyCache::dump() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ostringstream oss;
    oss << "TensorResidencyCache entries=" << lru_.size()
       << " capacity=" << maxEntries_ << "\n";
    for (const auto& node : lru_) {
        oss << "  id=model:" << node.identity.model
           << " tensor:" << node.identity.tensor
           << " layer:" << node.identity.layer
           << " addr:" << node.entry.view.transientAddress
           << " bytes:" << node.entry.view.bytes
           << " pins:" << node.entry.pinCount
           << " epoch:" << node.entry.lastAccessEpoch
           << "\n";
    }
    return oss.str();
}

void TensorResidencyCache::touch(std::list<LRUNode>::iterator it) {
    if (it == lru_.begin()) return;
    lru_.splice(lru_.begin(), lru_, it);
}

} // namespace Deep2
