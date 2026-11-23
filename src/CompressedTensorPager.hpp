#pragma once
// Lazy compressed residency for a single logical tensor/range.
// Source bytes are fetched only on cache misses; resident pages are stored
// compressed (or raw when compression expands them). Reads inflate one page
// at a time into the caller's destination. Reader must provide exact ranges.
#include <zlib.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace deep2 {
class CompressedTensorPager {
public:
    using Reader = std::function<bool(uint64_t offset, uint64_t size, uint8_t* out)>;
    struct Stats { uint64_t logicalBytes=0, residentBytes=0, compressedPages=0, rawPages=0, cacheMisses=0; };

    CompressedTensorPager(uint64_t logicalSize, Reader reader,
                          std::size_t pageSize=256*1024,
                          std::size_t residentBudget=64*1024*1024)
        : logicalSize_(logicalSize), reader_(std::move(reader)),
          pageSize_(pageSize), budget_(residentBudget) {}

    bool read(uint64_t offset, uint64_t size, uint8_t* out) {
        if ((!out && size) || offset > logicalSize_ || size > logicalSize_ - offset ||
            pageSize_ == 0 || pageSize_ > std::numeric_limits<uInt>::max()) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t copied=0;
        std::vector<uint8_t> scratch;
        while(copied<size) {
            const uint64_t absolute=offset+copied, pageNo=absolute/pageSize_;
            const std::size_t inPage=static_cast<std::size_t>(absolute%pageSize_);
            const std::size_t rawSize=static_cast<std::size_t>(
                std::min<uint64_t>(pageSize_, logicalSize_-pageNo*pageSize_));
            Page* page=getPage(pageNo,rawSize);
            if(!page) return false;
            const std::size_t n=std::min<std::size_t>(
                static_cast<std::size_t>(size-copied), rawSize-inPage);
            if (!page->compressed) {
                if (page->bytes.size()!=rawSize) return false;
                std::memcpy(out+copied,page->bytes.data()+inPage,n);
                copied+=n;
                continue;
            }

            // Inflate through a fixed-size window. Bytes outside the requested
            // subrange are discarded instead of materializing a full raw page.
            if (page->bytes.size() > std::numeric_limits<uInt>::max()) return false;
            z_stream stream{};
            stream.next_in = const_cast<Bytef*>(
                reinterpret_cast<const Bytef*>(page->bytes.data()));
            stream.avail_in = static_cast<uInt>(page->bytes.size());
            if (inflateInit(&stream) != Z_OK) return false;
            std::array<uint8_t, 32 * 1024> window{};
            uint64_t producedTotal = 0;
            bool streamEnd = false;
            bool inflateOk = true;
            while (!streamEnd) {
                stream.next_out = reinterpret_cast<Bytef*>(window.data());
                stream.avail_out = static_cast<uInt>(window.size());
                const uInt inputBefore = stream.avail_in;
                const int status = inflate(&stream, Z_NO_FLUSH);
                const std::size_t produced = window.size() - stream.avail_out;
                if (producedTotal > rawSize || produced > rawSize - producedTotal) {
                    inflateOk = false;
                    break;
                }

                const uint64_t chunkBegin = producedTotal;
                const uint64_t chunkEnd = producedTotal + produced;
                const uint64_t wantedBegin = inPage;
                const uint64_t wantedEnd = static_cast<uint64_t>(inPage) + n;
                const uint64_t copyBegin = std::max(chunkBegin, wantedBegin);
                const uint64_t copyEnd = std::min(chunkEnd, wantedEnd);
                if (copyBegin < copyEnd) {
                    const std::size_t dstOffset = static_cast<std::size_t>(copyBegin - wantedBegin);
                    const std::size_t srcOffset = static_cast<std::size_t>(copyBegin - chunkBegin);
                    const std::size_t copyBytes = static_cast<std::size_t>(copyEnd - copyBegin);
                    std::memcpy(out + copied + dstOffset, window.data() + srcOffset, copyBytes);
                }
                producedTotal = chunkEnd;

                if (status == Z_STREAM_END) {
                    streamEnd = true;
                } else if (status != Z_OK ||
                           (produced == 0 && inputBefore == stream.avail_in)) {
                    inflateOk = false;
                    break;
                }
            }
            const bool exactPage = inflateOk && streamEnd &&
                                   producedTotal == rawSize && stream.avail_in == 0;
            inflateEnd(&stream);
            if (!exactPage) return false;
            copied+=n;
        }
        return true;
    }
    Stats stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats s; s.logicalBytes=logicalSize_; s.residentBytes=residentBytes_; s.cacheMisses=misses_;
        for(const auto& kv:pages_) (kv.second.compressed?s.compressedPages:s.rawPages)++;
        return s;
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        pages_.clear(); lru_.clear(); residentBytes_=0;
    }
private:
    struct Page { std::vector<uint8_t> bytes; bool compressed=false; std::list<uint64_t>::iterator lru; };
    Page* getPage(uint64_t number,std::size_t rawSize) {
        auto it=pages_.find(number);
        if(it!=pages_.end()) { lru_.erase(it->second.lru); lru_.push_front(number); it->second.lru=lru_.begin(); return &it->second; }
        ++misses_;
        if(!reader_) return nullptr;
        std::vector<uint8_t> raw(rawSize);
        if(!reader_(number*pageSize_,rawSize,raw.data())) return nullptr;
        Page page; page.bytes.resize(static_cast<std::size_t>(compressBound(static_cast<uLong>(rawSize))));
        uLongf packed=static_cast<uLongf>(page.bytes.size());
        if(compress2(page.bytes.data(),&packed,raw.data(),static_cast<uLong>(rawSize),Z_BEST_SPEED)!=Z_OK) return nullptr;
        if(packed<rawSize) { page.bytes.resize(static_cast<std::size_t>(packed)); page.compressed=true; }
        else { page.bytes.swap(raw); page.compressed=false; }
        const std::size_t cost=page.bytes.size();
        if(cost>budget_) return nullptr;
        while(residentBytes_>budget_-cost && !lru_.empty()) {
            const auto victim=lru_.back(); lru_.pop_back();
            auto vi=pages_.find(victim); if(vi!=pages_.end()) { residentBytes_-=vi->second.bytes.size(); pages_.erase(vi); }
        }
        lru_.push_front(number); page.lru=lru_.begin();
        auto inserted=pages_.emplace(number,std::move(page));
        residentBytes_+=inserted.first->second.bytes.size();
        return &inserted.first->second;
    }
    const uint64_t logicalSize_;
    Reader reader_;
    const std::size_t pageSize_,budget_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t,Page> pages_;
    std::list<uint64_t> lru_;
    std::size_t residentBytes_=0;
    uint64_t misses_=0;
};
} // namespace deep2
