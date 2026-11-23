#pragma once
// Optional compressed host-resident page store. No Qt dependency.
// Pages remain compressed between reads; only the requested page is inflated.
// The caller owns the staging buffer and its lifetime (e.g. until GPU fence).
#include <zlib.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <vector>
#include <utility>

namespace deep2 {
class CompressedPageStore {
public:
    explicit CompressedPageStore(std::size_t pageSize = 256 * 1024)
        : pageSize_(pageSize) {}
    bool assign(const std::uint8_t* src, std::size_t size) {
        if ((!src && size) || pageSize_ == 0 || pageSize_ > std::numeric_limits<uInt>::max())
            return false;
        std::vector<Page> next;
        if (size / pageSize_ > next.max_size() - 1) return false;
        std::size_t pos = 0;
        while (pos < size) {
            const auto count = std::min(pageSize_, size - pos);
            Page page;
            page.rawSize = count;
            const uLongf bound = compressBound(static_cast<uLong>(count));
            if (bound > page.bytes.max_size()) return false;
            page.bytes.resize(static_cast<std::size_t>(bound));
            uLongf written = bound;
            const int rc = compress2(page.bytes.data(), &written, src + pos,
                                     static_cast<uLong>(count), Z_BEST_SPEED);
            if (rc != Z_OK) return false;
            page.bytes.resize(static_cast<std::size_t>(written));
            // Incompressible pages are stored raw, avoiding expansion.
            if (page.bytes.size() >= count) {
                page.compressed = false;
                page.bytes.assign(src + pos, src + pos + count);
            }
            next.push_back(std::move(page));
            pos += count;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        pages_.swap(next);
        originalSize_ = size;
        return true;
    }
    bool read(std::size_t offset, std::size_t count, std::uint8_t* dst) const {
        if (!dst && count) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (offset > originalSize_ || count > originalSize_ - offset) return false;
        std::vector<std::uint8_t> scratch;
        std::size_t copied = 0;
        while (copied < count) {
            const auto index = (offset + copied) / pageSize_;
            const auto within = (offset + copied) % pageSize_;
            const Page& page = pages_[index];
            const auto take = std::min(count - copied, page.rawSize - within);
            if (page.compressed) {
                scratch.resize(page.rawSize);
                uLongf actual = static_cast<uLongf>(scratch.size());
                if (uncompress(scratch.data(), &actual, page.bytes.data(),
                               static_cast<uLong>(page.bytes.size())) != Z_OK ||
                    actual != page.rawSize) return false;
                std::memcpy(dst + copied, scratch.data() + within, take);
            } else {
                if (page.bytes.size() != page.rawSize) return false;
                std::memcpy(dst + copied, page.bytes.data() + within, take);
            }
            copied += take;
        }
        return true;
    }
    std::size_t originalBytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return originalSize_;
    }
    std::size_t residentBytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t total = 0;
        for (const auto& page : pages_) total += page.bytes.size();
        return total;
    }
    std::size_t pageCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pages_.size();
    }
private:
    struct Page {
        std::vector<std::uint8_t> bytes;
        std::size_t rawSize = 0;
        bool compressed = true;
    };
    const std::size_t pageSize_;
    mutable std::mutex mutex_;
    std::vector<Page> pages_;
    std::size_t originalSize_ = 0;
};
} // namespace deep2
