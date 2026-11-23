#pragma once
// Native compressed tensor residency primitives. No external dependencies.
// A decoder is supplied by the tensor format backend (GGUF Q*, FP16, etc.).
// Decoded blocks are bounded by budget; active leases keep data alive.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace RawrXD::Compression {
struct BlockKey {
    uint64_t tensor = 0;
    uint64_t block = 0;
    bool operator==(const BlockKey& rhs) const noexcept {
        return tensor == rhs.tensor && block == rhs.block;
    }
};
struct BlockKeyHash {
    size_t operator()(const BlockKey& k) const noexcept {
        uint64_t x = k.tensor ^ (k.block + 0x9e3779b97f4a7c15ULL +
                                  (k.tensor << 6) + (k.tensor >> 2));
        return static_cast<size_t>(x ^ (x >> 32));
    }
};

// Decoder must validate the compressed input and produce exactly expected_bytes.
// An active Lease is immutable and remains valid after cache eviction.
class BlockResidencyCache {
public:
    using Bytes = std::vector<uint8_t>;
    using Lease = std::shared_ptr<const Bytes>;
    using Decoder = std::function<bool(Bytes&)>;
    explicit BlockResidencyCache(size_t decoded_budget_bytes)
        : budget_(decoded_budget_bytes) {}

    // Does not hold the cache lock while decoding. Concurrent misses may
    // duplicate work, but only one decoded entry is installed.
    Lease acquire(BlockKey key, size_t expected_bytes, const Decoder& decode) {
        if (!decode || expected_bytes == 0 || expected_bytes > budget_)
            throw std::invalid_argument("invalid block decoder or size");
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto it = entries_.find(key);
            if (it != entries_.end()) {
                touch(it);
                return it->second.data;
            }
        }
        auto fresh = std::make_shared<Bytes>();
        if (!decode(*fresh) || fresh->size() != expected_bytes)
            throw std::runtime_error("tensor block decode failed or size mismatch");
        std::lock_guard<std::mutex> lock(mu_);
        auto existing = entries_.find(key);
        if (existing != entries_.end()) {
            touch(existing);
            return existing->second.data;
        }
        while (resident_ > budget_ - expected_bytes && !lru_.empty()) {
            const auto victim = lru_.back();
            auto it = entries_.find(victim);
            resident_ -= it->second.data->size();
            entries_.erase(it);
            lru_.pop_back();
        }
        lru_.push_front(key);
        entries_.emplace(key, Entry{fresh, lru_.begin()});
        resident_ += expected_bytes;
        return fresh;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mu_);
        entries_.clear();
        lru_.clear();
        resident_ = 0;
    }
    size_t resident_bytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return resident_;
    }
    size_t budget_bytes() const noexcept { return budget_; }
private:
    using Order = std::list<BlockKey>;
    struct Entry { Lease data; Order::iterator position; };
    using Index = std::unordered_map<BlockKey, Entry, BlockKeyHash>;
    void touch(Index::iterator it) {
        lru_.splice(lru_.begin(), lru_, it->second.position);
    }
    const size_t budget_;
    mutable std::mutex mu_;
    size_t resident_ = 0;
    Order lru_;
    Index entries_;
};
} // namespace RawrXD::Compression
