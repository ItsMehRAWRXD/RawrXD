#pragma once
// Request-local, disk-backed decoded-block cache. C++17, no new dependencies.
// The compressed RWT1 payload remains on disk; only decoded blocks are cached.
#include "StreamingTensorFile.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <stdexcept>
#include <unordered_map>
#include <vector>
namespace rawrxd::weights {
class StreamingBlockCache {
    struct Entry {
        std::vector<uint8_t> bytes;
        std::list<size_t>::iterator lru;
    };
    StreamingTensorFile& source_;
    size_t budget_, resident_=0, peak_=0, hits_=0, misses_=0, evictions_=0;
    std::list<size_t> order_;
    std::unordered_map<size_t, Entry> blocks_;
public:
    explicit StreamingBlockCache(StreamingTensorFile& source, size_t budget_bytes)
        : source_(source), budget_(budget_bytes) {
        if (!budget_ || budget_ < source_.block_size())
            throw std::invalid_argument("cache budget must hold at least one block");
    }
    size_t resident_bytes() const { return resident_; }
    size_t peak_resident_bytes() const { return peak_; }
    size_t budget_bytes() const { return budget_; }
    size_t hits() const { return hits_; }
    size_t misses() const { return misses_; }
    size_t evictions() const { return evictions_; }
    void clear() { blocks_.clear(); order_.clear(); resident_=0; }
    // Reference invalidated by subsequent get(), read(), or clear().
    const std::vector<uint8_t>& get(size_t index) {
        auto it=blocks_.find(index);
        if (it!=blocks_.end()) {
            ++hits_;
            order_.splice(order_.begin(),order_,it->second.lru);
            return it->second.bytes;
        }
        ++misses_;
        auto decoded=source_.read_block(index); // CRC checked before caching
        if (decoded.empty() || decoded.size()>budget_)
            throw std::length_error("decoded block exceeds budget");
        while (resident_>budget_-decoded.size()) {
            if (order_.empty()) throw std::logic_error("invalid LRU accounting");
            const auto victim=order_.back();
            auto found=blocks_.find(victim);
            if (found==blocks_.end()) throw std::logic_error("missing LRU entry");
            resident_-=found->second.bytes.size();
            blocks_.erase(found);
            order_.pop_back();
            ++evictions_;
        }
        order_.push_front(index);
        try {
            auto result=blocks_.emplace(index,Entry{std::move(decoded),order_.begin()});
            if (!result.second) throw std::logic_error("duplicate cache entry");
            resident_+=result.first->second.bytes.size();
            peak_=std::max(peak_,resident_);
            return result.first->second.bytes;
        } catch (...) {
            order_.pop_front();
            throw;
        }
    }
    // Caller-owned bounded destination: avoids allocating a tensor-sized result.
    // Copy to independently owned staging memory before submitting GPU work.
    void read_into(uint64_t offset, uint8_t* dest, size_t length) {
        if ((!dest && length) || offset>source_.plain_size() ||
            uint64_t(length)>source_.plain_size()-offset)
            throw std::out_of_range("compressed tensor destination/range");
        size_t copied=0;
        while (copied<length) {
            const uint64_t position=offset+copied;
            const size_t index=static_cast<size_t>(position/source_.block_size());
            const size_t within=static_cast<size_t>(position%source_.block_size());
            const auto& block=get(index);
            if (within>=block.size()) throw std::runtime_error("invalid block extent");
            const size_t n=std::min(length-copied,block.size()-within);
            std::memcpy(dest+copied,block.data()+within,n);
            copied+=n;
        }
    }
    // Range reads allocate only the requested output plus the bounded cache.
    // Prefer get() for zero-copy access inside hot inference kernels.
    std::vector<uint8_t> read(uint64_t offset,size_t length) {
        if (offset>source_.plain_size() ||
            uint64_t(length)>source_.plain_size()-offset)
            throw std::out_of_range("compressed tensor range");
        std::vector<uint8_t> out(length);
        size_t copied=0;
        while (copied<length) {
            const uint64_t position=offset+copied;
            const size_t index=static_cast<size_t>(position/source_.block_size());
            const size_t within=static_cast<size_t>(position%source_.block_size());
            const auto& block=get(index);
            if (within>=block.size()) throw std::runtime_error("invalid block extent");
            const size_t n=std::min(length-copied,block.size()-within);
            std::memcpy(out.data()+copied,block.data()+within,n);
            copied+=n;
        }
        return out;
    }
};
} // namespace rawrxd::weights
