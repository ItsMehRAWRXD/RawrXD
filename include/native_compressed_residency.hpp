#pragma once
// Native compressed residency: bounded, lossless block cache.
// Independent of GGUF parsing and GPU ownership. C++17.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <list>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::compression {
struct Block {
    std::vector<std::uint8_t> payload;
    std::size_t decoded_size = 0;
    bool rle = false;
    // Immutable content generation; callers must change it when a block is replaced.
    std::uint64_t generation = 0;
};

// Byte RLE is deliberately conservative: incompressible data is stored verbatim.
// It is not a replacement for GGML quantization or a GPU-native decoder.
inline Block encode(const std::uint8_t* data, std::size_t size) {
    if (size && !data) throw std::invalid_argument("null input");
    Block out;
    out.decoded_size = size;
    std::vector<std::uint8_t> rle;
    for (std::size_t i = 0; i < size;) {
        std::size_t run = 1;
        while (i + run < size && run < 255 && data[i + run] == data[i]) ++run;
        rle.push_back(static_cast<std::uint8_t>(run));
        rle.push_back(data[i]);
        i += run;
    }
    if (rle.size() < size) {
        out.payload = std::move(rle);
        out.rle = true;
    } else {
        if (size) out.payload.assign(data, data + size);
    }
    return out;
}
inline std::vector<std::uint8_t> decode(const Block& block) {
    if (!block.rle) {
        if (block.payload.size() != block.decoded_size)
            throw std::runtime_error("invalid raw block length");
        return block.payload;
    }
    if (block.payload.size() % 2) throw std::runtime_error("invalid RLE block");
    std::vector<std::uint8_t> out;
    out.reserve(block.decoded_size);
    for (std::size_t i = 0; i < block.payload.size(); i += 2) {
        const auto count = block.payload[i];
        if (!count || count > block.decoded_size - out.size())
            throw std::runtime_error("invalid RLE run");
        out.insert(out.end(), count, block.payload[i + 1]);
    }
    if (out.size() != block.decoded_size)
        throw std::runtime_error("truncated RLE block");
    return out;
}

// Returned bytes are owned by the caller. No raw pointer survives eviction.
// The cache never exceeds capacity; oversized blocks decode without caching.
class BoundedDecodeCache {
public:
    explicit BoundedDecodeCache(std::size_t capacity) : capacity_(capacity) {}
    std::vector<std::uint8_t> get(std::uint64_t id, const Block& block) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = entries_.find(id);
        if (found != entries_.end()) {
            if (found->second.generation == block.generation) {
                order_.splice(order_.begin(), order_, found->second.position);
                return found->second.bytes;
            }
            used_ -= found->second.bytes.size();
            order_.erase(found->second.position);
            entries_.erase(found);
        }
        auto bytes = decode(block);
        if (bytes.size() > capacity_) return bytes;
        while (used_ > capacity_ - bytes.size() && !order_.empty()) {
            auto victim = order_.back();
            auto it = entries_.find(victim);
            used_ -= it->second.bytes.size();
            entries_.erase(it);
            order_.pop_back();
        }
        order_.push_front(id);
        used_ += bytes.size();
        entries_.emplace(id, Entry{bytes, order_.begin(), block.generation});
        return bytes;
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        order_.clear();
        used_ = 0;
    }
    std::size_t resident_bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return used_;
    }
private:
    struct Entry {
        std::vector<std::uint8_t> bytes;
        std::list<std::uint64_t>::iterator position;
        std::uint64_t generation;
    };
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::size_t used_ = 0;
    std::list<std::uint64_t> order_;
    std::unordered_map<std::uint64_t, Entry> entries_;
};
} // namespace rawrxd::compression
