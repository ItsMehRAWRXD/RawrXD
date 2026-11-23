#pragma once

#include "native_resident_compressed_tensor.hpp"

#include <cstddef>
#include <functional>
#include <iterator>
#include <list>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace rawrxd::compression {

// Bounded LRU for immutable compressed tensors. A returned shared_ptr is a
// request lease: active entries are never evicted or removed from accounting.
// If every resident entry is leased, an incoming tensor remains request-scoped
// instead of making the shared-cache budget lie about live allocations.
class ResidentTensorCache {
public:
    using Tensor = ResidentCompressedTensor;
    using Ptr = std::shared_ptr<const Tensor>;
    using Loader = std::function<Ptr()>;

    explicit ResidentTensorCache(std::size_t budgetBytes = 256u * 1024u * 1024u)
        : budgetBytes_(budgetBytes) {}

    Ptr GetOrLoad(const std::string& key, const Loader& loader) {
        if (key.empty() || !loader)
            throw std::invalid_argument("compressed tensor cache requires key and loader");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = entries_.find(key);
            if (found != entries_.end()) {
                touch(found->second);
                return found->second.tensor;
            }
        }

        // File IO and compression are intentionally outside the cache mutex.
        // Concurrent misses may build duplicates, but only one is admitted.
        Ptr loaded = loader();
        if (!loaded)
            throw std::runtime_error("compressed tensor loader returned null");
        const std::size_t bytes = loaded->resident_bytes();

        std::lock_guard<std::mutex> lock(mutex_);
        const auto raced = entries_.find(key);
        if (raced != entries_.end()) {
            touch(raced->second);
            return raced->second.tensor;
        }
        if (bytes > budgetBytes_ ||
            bytes > (std::numeric_limits<std::size_t>::max)() - usedBytes_)
            return loaded;

        trimLocked(budgetBytes_ - bytes);
        if (usedBytes_ > budgetBytes_ - bytes)
            return loaded; // No evictable capacity; do not exceed shared budget.

        order_.push_front(key);
        entries_.emplace(key, Entry{loaded, order_.begin(), bytes});
        usedBytes_ += bytes;
        return loaded;
    }

    void SetBudget(std::size_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        budgetBytes_ = bytes;
        trimLocked(budgetBytes_);
    }

    // Clear all entries that are not currently leased by inference requests.
    // Pinned entries remain visible and accounted until their last lease ends.
    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        trimLocked(0);
    }

    std::size_t resident_bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return usedBytes_;
    }

    std::size_t entry_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    std::size_t budget_bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return budgetBytes_;
    }

private:
    struct Entry {
        Ptr tensor;
        std::list<std::string>::iterator position;
        std::size_t bytes = 0;
    };

    void touch(Entry& entry) {
        order_.splice(order_.begin(), order_, entry.position);
        entry.position = order_.begin();
    }

    void trimLocked(std::size_t targetBytes) {
        while (usedBytes_ > targetBytes) {
            auto victim = order_.end();
            for (auto it = order_.end(); it != order_.begin();) {
                --it;
                const auto found = entries_.find(*it);
                if (found != entries_.end() && found->second.tensor.use_count() == 1) {
                    victim = it;
                    break;
                }
            }
            if (victim == order_.end()) break;

            const auto found = entries_.find(*victim);
            if (found != entries_.end()) {
                usedBytes_ = found->second.bytes > usedBytes_
                    ? 0 : usedBytes_ - found->second.bytes;
                entries_.erase(found);
            }
            order_.erase(victim);
        }
    }

    mutable std::mutex mutex_;
    std::size_t budgetBytes_;
    std::size_t usedBytes_ = 0;
    std::list<std::string> order_;
    std::unordered_map<std::string, Entry> entries_;
};

} // namespace rawrxd::compression
