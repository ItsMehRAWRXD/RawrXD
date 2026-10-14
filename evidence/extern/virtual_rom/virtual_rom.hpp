#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <list>
#include <functional>
#include <stdexcept>
#include <algorithm>
#include <limits>
#include <cstring>

namespace rawrxd {
// Sparse logical byte-address space. Backing callback must reconstruct EXACT bytes.
// Not thread-safe: callers serialize access or wrap in a mutex.
class VirtualROM {
public:
    using Reader = std::function<bool(uint64_t, uint8_t*, size_t)>;
    struct Stats { uint64_t hits=0, misses=0, evictions=0, backing_bytes=0; };
    VirtualROM(uint64_t logical_bytes, size_t page_bytes, size_t resident_budget_bytes, Reader backing)
      : length_(logical_bytes), page_(page_bytes), capacity_(resident_budget_bytes/page_bytes), reader_(std::move(backing)) {
        if (!page_bytes || !capacity_ || !reader_) throw std::invalid_argument("invalid page/budget/backing");
    }
    uint64_t size() const noexcept { return length_; }
    size_t resident_bytes() const noexcept { return pages_.size()*page_; }
    Stats stats() const noexcept { return stats_; }
    void read(uint64_t offset, void* out, size_t bytes) {
        if (offset > length_ || uint64_t(bytes) > length_-offset) throw std::out_of_range("virtual read bounds");
        if (bytes && !out) throw std::invalid_argument("null destination");
        auto* dst = static_cast<uint8_t*>(out);
        while (bytes) {
            uint64_t index=offset/page_;
            size_t within=static_cast<size_t>(offset%page_);
            size_t n=std::min(bytes,page_-within);
            const auto& data=fetch(index);
            std::memcpy(dst,data.data()+within,n);
            dst+=n; offset+=n; bytes-=n;
        }
    }
    void invalidate(uint64_t index) {
        auto it=pages_.find(index);
        if(it!=pages_.end()) { lru_.erase(it->second.lru); pages_.erase(it); }
    }
    void invalidate_all() { pages_.clear(); lru_.clear(); }
private:
    struct Page { std::vector<uint8_t> data; std::list<uint64_t>::iterator lru; };
    const std::vector<uint8_t>& fetch(uint64_t index) {
        auto it=pages_.find(index);
        if(it!=pages_.end()) {
            ++stats_.hits;
            lru_.splice(lru_.begin(),lru_,it->second.lru);
            return it->second.data;
        }
        // Load before evicting: a failed backing read must not corrupt cache state.
        const uint64_t start=index*uint64_t(page_);
        size_t valid=static_cast<size_t>(std::min<uint64_t>(page_,length_-start));
        std::vector<uint8_t> data(page_,0);
        if (!reader_(start,data.data(),valid)) throw std::runtime_error("backing reconstruction failed");
        if(pages_.size()>=capacity_) {
            auto victim=lru_.back(); lru_.pop_back(); pages_.erase(victim); ++stats_.evictions;
        }
        lru_.push_front(index);
        auto inserted=pages_.emplace(index,Page{std::move(data),lru_.begin()});
        ++stats_.misses; stats_.backing_bytes+=valid;
        return inserted.first->second.data;
    }
    uint64_t length_;
    size_t page_,capacity_;
    Reader reader_;
    Stats stats_;
    std::list<uint64_t> lru_;
    std::unordered_map<uint64_t,Page> pages_;
};
}
