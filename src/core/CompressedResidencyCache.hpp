#pragma once
// Bounded, thread-safe compressed tensor block residency foundation.
// Stores encoded blocks; decodes only on acquire. No codec assumptions.
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
class CompressedResidencyCache {
public:
    using Bytes = std::vector<std::uint8_t>;
    using Decoder = std::function<Bytes(const Bytes&, std::size_t)>;
    struct Key {
        std::uint64_t tensor, block;
        bool operator==(const Key& b) const noexcept {
            return tensor == b.tensor && block == b.block;
        }
    };
    struct Hash {
        std::size_t operator()(const Key& k) const noexcept {
            auto a = std::hash<std::uint64_t>{}(k.tensor);
            auto b = std::hash<std::uint64_t>{}(k.block);
            return a ^ (b + std::size_t(0x9e3779b9) + (a << 6) + (a >> 2));
        }
    };
    // Shared ownership pins decoded data across eviction and concurrent readers.
    using Lease = std::shared_ptr<const Bytes>;
    explicit CompressedResidencyCache(std::size_t decoded_budget)
        : budget_(decoded_budget) {}

    void insert(Key key, Bytes encoded, std::size_t decoded_size, Decoder decoder) {
        if (!decoder || !decoded_size || decoded_size > budget_)
            throw std::invalid_argument("invalid decoder or decoded size/budget");
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(key);
        if (it != entries_.end()) {
            if (it->second.decoded && it->second.decoded.use_count() > 1)
                throw std::runtime_error("cannot replace pinned decoded block");
            dropDecoded(it->second);
            lru_.erase(it->second.lru);
            entries_.erase(it);
        }
        lru_.push_front(key);
        entries_.emplace(key, Entry{std::move(encoded), decoded_size,
                                    std::move(decoder), {}, lru_.begin()});
    }

    Lease acquire(Key key) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(key);
        if (it == entries_.end()) throw std::out_of_range("tensor block absent");
        auto& e = it->second;
        if (!e.decoded) {
            // Decode before eviction; on decoder failure, cache state is unchanged.
            auto bytes = std::make_shared<Bytes>(e.decoder(e.encoded, e.expected));
            if (bytes->size() != e.expected)
                throw std::runtime_error("decoder produced incorrect byte count");
            evictUntilFits(e.expected, key);
            e.decoded = std::move(bytes);
            resident_ += e.expected;
        }
        lru_.splice(lru_.begin(), lru_, e.lru);
        return e.decoded;
    }

    std::size_t decodedResidentBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return resident_;
    }
    std::size_t compressedStoredBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        std::size_t total = 0;
        for (const auto& kv : entries_) {
            if (kv.second.encoded.size() > std::numeric_limits<std::size_t>::max() - total)
                throw std::overflow_error("compressed byte counter overflow");
            total += kv.second.encoded.size();
        }
        return total;
    }
private:
    struct Entry {
        Bytes encoded;
        std::size_t expected;
        Decoder decoder;
        Lease decoded;
        std::list<Key>::iterator lru;
    };
    void dropDecoded(Entry& e) {
        if (e.decoded) {
            resident_ -= e.expected;
            e.decoded.reset();
        }
    }
    void evictUntilFits(std::size_t need, Key requested) {
        while (resident_ > budget_ - need) {
            bool freed = false;
            for (auto it = lru_.rbegin(); it != lru_.rend(); ++it) {
                if (*it == requested) continue;
                auto& e = entries_.at(*it);
                if (e.decoded && e.decoded.use_count() == 1) {
                    dropDecoded(e);
                    freed = true;
                    break;
                }
            }
            if (!freed) throw std::runtime_error("decoded residency budget exhausted by pinned blocks");
        }
    }
    const std::size_t budget_;
    mutable std::mutex mu_;
    std::size_t resident_ = 0;
    std::list<Key> lru_;
    std::unordered_map<Key, Entry, Hash> entries_;
};
} // namespace RawrXD
