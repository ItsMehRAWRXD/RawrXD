#pragma once
// Request-local bounded decoded-block cache. Not thread safe: one cache per request.
// Compressed Tensor remains the source of truth; only requested blocks are materialized.
#include "TensorAwareLossless.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <stdexcept>
#include <unordered_map>
#include <vector>
namespace rawrxd::weights {
class DecodedBlockCache {
    struct Entry {
        std::vector<uint8_t> bytes;
        std::list<size_t>::iterator lru;
    };
    const Tensor* tensor_;
    size_t budget_;
    size_t used_ = 0;
    size_t hits_ = 0, misses_ = 0;
    size_t peak_resident_ = 0, decoded_total_ = 0, evictions_ = 0;
    std::list<size_t> order_;
    std::unordered_map<size_t, Entry> entries_;
public:
    explicit DecodedBlockCache(const Tensor& tensor, size_t budget_bytes)
        : tensor_(&tensor), budget_(budget_bytes) {
        if (!tensor.block_size) throw std::invalid_argument("invalid block size");
    }
    size_t resident_bytes() const { return used_; }
    size_t peak_resident_bytes() const { return peak_resident_; }
    size_t decoded_bytes_total() const { return decoded_total_; }
    size_t evictions() const { return evictions_; }
    size_t compressed_payload_bytes() const {
        size_t total=0;
        for (const auto& b:tensor_->blocks) {
            if (b.payload.size() > static_cast<size_t>(-1)-total)
                throw std::overflow_error("compressed payload total overflow");
            total+=b.payload.size();
        }
        return total;
    }
    size_t hits() const { return hits_; }
    size_t misses() const { return misses_; }
    void clear() {
        entries_.clear(); order_.clear(); used_ = 0;
    }
    // Returned reference is invalidated by subsequent cache access or clear().
    const std::vector<uint8_t>& get(size_t index) {
        auto it = entries_.find(index);
        if (it != entries_.end()) {
            ++hits_;
            order_.splice(order_.begin(), order_, it->second.lru);
            return it->second.bytes;
        }
        ++misses_;
        auto decoded = decode_block(*tensor_, index);
        if (decoded.size() > budget_)
            throw std::length_error("decoded block exceeds cache budget");
        while (used_ > budget_ - decoded.size()) {
            if (order_.empty()) throw std::logic_error("cache accounting invalid");
            const size_t victim = order_.back();
            auto victim_it = entries_.find(victim);
            used_ -= victim_it->second.bytes.size();
            ++evictions_;
            entries_.erase(victim_it);
            order_.pop_back();
        }
        order_.push_front(index);
        if (decoded_total_ > static_cast<size_t>(-1)-decoded.size())
            throw std::overflow_error("decoded byte counter overflow");
        decoded_total_ += decoded.size();
        used_ += decoded.size();
        peak_resident_ = std::max(peak_resident_, used_);
        auto inserted = entries_.emplace(index, Entry{std::move(decoded), order_.begin()});
        return inserted.first->second.bytes;
    }
    std::vector<uint8_t> read(uint64_t offset, size_t length) {
        if (offset > tensor_->plain_size || length > tensor_->plain_size - offset)
            throw std::out_of_range("tensor range out of bounds");
        std::vector<uint8_t> result(length);
        size_t copied = 0;
        while (copied < length) {
            const uint64_t position = offset + copied;
            const size_t index = static_cast<size_t>(position / tensor_->block_size);
            const size_t within = static_cast<size_t>(position % tensor_->block_size);
            const auto& bytes = get(index);
            if (within >= bytes.size()) throw std::runtime_error("inconsistent block metadata");
            const size_t count = std::min(length - copied, bytes.size() - within);
            std::memcpy(result.data() + copied, bytes.data() + within, count);
            copied += count;
        }
        return result;
    }
};
} // namespace rawrxd::weights
