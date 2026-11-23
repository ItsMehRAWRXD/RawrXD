#pragma once
// Bounded, thread-safe compressed tensor block residency.
// C++17, no third-party dependencies. Codec is supplied by the caller.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace RawrXD {
namespace Compression {

struct BlockKey {
    uint64_t tensor = 0;
    uint64_t block = 0;
    bool operator==(const BlockKey& rhs) const noexcept {
        return tensor == rhs.tensor && block == rhs.block;
    }
};
struct BlockKeyHash {
    size_t operator()(const BlockKey& key) const noexcept {
        const uint64_t x = key.tensor ^ (key.block + 0x9e3779b97f4a7c15ULL
            + (key.tensor << 6) + (key.tensor >> 2));
        return static_cast<size_t>(x ^ (x >> 32));
    }
};
struct BlockDescriptor {
    uint64_t offset = 0;
    uint64_t compressed_bytes = 0;
    uint64_t decoded_bytes = 0;
};
// Read must return exactly the requested compressed bytes; decode must produce
// exactly decoded_bytes. Both functions may throw. Never silently zero-fill.
using ReadBlock = std::function<bool(uint64_t, size_t, std::vector<uint8_t>&)>;
using DecodeBlock = std::function<bool(const uint8_t*, size_t, size_t, std::vector<uint8_t>&)>;

class BlockResidency {
public:
    struct Stats {
        size_t resident_bytes = 0;
        size_t peak_resident_bytes = 0;
        size_t blocks = 0;
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t evictions = 0;
    };
    explicit BlockResidency(size_t capacity_bytes) : capacity_(capacity_bytes) {}

    // A returned shared_ptr pins decoded storage until the inference consumer
    // releases it. Cache eviction cannot invalidate outstanding references.
    std::shared_ptr<const std::vector<uint8_t>> acquire(
        BlockKey key, BlockDescriptor descriptor,
        const ReadBlock& read, const DecodeBlock& decode) {
        {
            std::lock_guard<std::mutex> guard(mutex_);
            auto it = entries_.find(key);
            if (it != entries_.end()) {
                if (it->second.descriptor.offset != descriptor.offset ||
                    it->second.descriptor.compressed_bytes != descriptor.compressed_bytes ||
                    it->second.descriptor.decoded_bytes != descriptor.decoded_bytes)
                    throw std::invalid_argument("block key metadata mismatch");
                ++hits_;
                lru_.splice(lru_.begin(), lru_, it->second.position);
                return it->second.data;
            }
            ++misses_;
        }
        if (!read || !decode || !descriptor.compressed_bytes || !descriptor.decoded_bytes ||
            descriptor.compressed_bytes > std::numeric_limits<size_t>::max() ||
            descriptor.decoded_bytes > std::numeric_limits<size_t>::max() ||
            descriptor.offset > UINT64_MAX - descriptor.compressed_bytes)
            throw std::invalid_argument("invalid compressed block descriptor");
        const auto packed_size = static_cast<size_t>(descriptor.compressed_bytes);
        const auto decoded_size = static_cast<size_t>(descriptor.decoded_bytes);
        std::vector<uint8_t> packed;
        if (!read(descriptor.offset, packed_size, packed) || packed.size() != packed_size)
            throw std::runtime_error("compressed block read failed");
        auto result = std::make_shared<std::vector<uint8_t>>();
        if (!decode(packed.data(), packed.size(), decoded_size, *result) ||
            result->size() != decoded_size)
            throw std::runtime_error("compressed block decode failed");
        packed.clear();
        packed.shrink_to_fit();

        std::lock_guard<std::mutex> guard(mutex_);
        auto existing = entries_.find(key);
        if (existing != entries_.end()) {
            if (existing->second.descriptor.offset != descriptor.offset ||
                existing->second.descriptor.compressed_bytes != descriptor.compressed_bytes ||
                existing->second.descriptor.decoded_bytes != descriptor.decoded_bytes)
                throw std::invalid_argument("block key metadata mismatch");
            lru_.splice(lru_.begin(), lru_, existing->second.position);
            return existing->second.data;
        }
        // Oversized blocks are returned uncached. The caller owns their lifetime.
        if (decoded_size > capacity_) return result;
        while (resident_ > capacity_ - decoded_size && !lru_.empty()) {
            auto oldest = std::prev(lru_.end());
            auto it = entries_.find(*oldest);
            resident_ -= it->second.data->size();
            entries_.erase(it);
            lru_.erase(oldest);
            ++evictions_;
        }
        lru_.push_front(key);
        entries_.emplace(key, Entry{descriptor, result, lru_.begin()});
        resident_ += decoded_size;
        peak_ = std::max(peak_, resident_);
        return result;
    }
    Stats stats() const {
        std::lock_guard<std::mutex> guard(mutex_);
        return Stats{resident_, peak_, entries_.size(), hits_, misses_, evictions_};
    }
    void clear() {
        std::lock_guard<std::mutex> guard(mutex_);
        entries_.clear();
        lru_.clear();
        resident_ = 0;
    }
private:
    struct Entry {
        BlockDescriptor descriptor;
        std::shared_ptr<const std::vector<uint8_t>> data;
        std::list<BlockKey>::iterator position;
    };
    const size_t capacity_;
    mutable std::mutex mutex_;
    std::list<BlockKey> lru_;
    std::unordered_map<BlockKey, Entry, BlockKeyHash> entries_;
    size_t resident_ = 0, peak_ = 0;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0;
};

} // namespace Compression
} // namespace RawrXD
