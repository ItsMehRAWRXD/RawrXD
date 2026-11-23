#pragma once
// Native, dependency-free, page-granular compressed weight backing store.
// C++17. This is a storage primitive: inference kernels acquire only the
// pages they need and keep the returned shared_ptr alive until GPU completion.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::memory {

class CompressedWeightStore final {
public:
    using Bytes = std::vector<std::uint8_t>;
    using Page = std::shared_ptr<const Bytes>;

    struct Stats {
        std::size_t logical_bytes = 0;
        std::size_t compressed_bytes = 0;
        std::size_t resident_expanded_bytes = 0;
        std::size_t cached_pages = 0;
        std::size_t page_size = 0;
    };

    // Build takes a transient source view. After return, only encoded pages
    // are retained by the store; the caller owns and may release source.
    static std::shared_ptr<CompressedWeightStore> Build(
        const void* source, std::size_t bytes,
        std::size_t page_size = 64u * 1024u,
        std::size_t expanded_cache_budget = 256u * 1024u * 1024u) {
        if ((!source && bytes) || page_size == 0)
            throw std::invalid_argument("invalid compressed weight source");
        auto store = std::shared_ptr<CompressedWeightStore>(
            new CompressedWeightStore(page_size, expanded_cache_budget, bytes));
        const auto* input = static_cast<const std::uint8_t*>(source);
        for (std::size_t offset = 0; offset < bytes;) {
            const std::size_t count = (std::min)(page_size, bytes - offset);
            Bytes raw(input + offset, input + offset + count);
            Bytes encoded = Encode(raw);
            PageRecord record;
            if (encoded.size() < raw.size()) {
                record.encoded = std::move(encoded);
                record.raw = false;
            } else {
                record.encoded = std::move(raw);
                record.raw = true;
            }
            record.logical_size = count;
            store->compressed_bytes_ += record.encoded.size();
            store->pages_.push_back(std::move(record));
            offset += count;
        }
        return store;
    }

    CompressedWeightStore(const CompressedWeightStore&) = delete;
    CompressedWeightStore& operator=(const CompressedWeightStore&) = delete;

    std::size_t SizeBytes() const noexcept { return logical_bytes_; }
    std::size_t PageSize() const noexcept { return page_size_; }
    std::size_t PageCount() const noexcept { return pages_.size(); }

    // A returned page is a pin. Keep it alive until every CPU/GPU consumer
    // has completed; eviction only removes cache entries with no external pin.
    Page AcquirePage(std::size_t page_index) const {
        if (page_index >= pages_.size()) return {};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = cache_.find(page_index);
            if (found != cache_.end()) {
                found->second.last_use = ++clock_;
                return found->second.bytes;
            }
        }

        const PageRecord& record = pages_[page_index];
        auto expanded = std::make_shared<Bytes>(
            record.raw ? record.encoded : Decode(record.encoded, record.logical_size));
        if (expanded->size() != record.logical_size) return {};

        std::lock_guard<std::mutex> lock(mutex_);
        auto existing = cache_.find(page_index);
        if (existing != cache_.end()) {
            existing->second.last_use = ++clock_;
            return existing->second.bytes;
        }
        EvictUntilFits(expanded->size());
        if (expanded_cache_budget_ == 0 || expanded->size() > expanded_cache_budget_ ||
            resident_expanded_bytes_ > expanded_cache_budget_ - expanded->size()) {
            return expanded; // valid transient pin; deliberately not cached
        }
        resident_expanded_bytes_ += expanded->size();
        cache_.emplace(page_index, CacheEntry{expanded, ++clock_});
        return expanded;
    }

    // Copy an arbitrary byte range, expanding only the pages intersecting it.
    bool ReadRange(std::size_t offset, void* destination, std::size_t length) const {
        if ((!destination && length) || offset > logical_bytes_ ||
            length > logical_bytes_ - offset) return false;
        auto* out = static_cast<std::uint8_t*>(destination);
        while (length) {
            const std::size_t page_index = offset / page_size_;
            const std::size_t in_page = offset % page_size_;
            Page page = AcquirePage(page_index);
            if (!page || in_page >= page->size()) return false;
            const std::size_t count = (std::min)(length, page->size() - in_page);
            std::memcpy(out, page->data() + in_page, count);
            out += count;
            offset += count;
            length -= count;
        }
        return true;
    }

    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return Stats{logical_bytes_, compressed_bytes_, resident_expanded_bytes_,
                     cache_.size(), page_size_};
    }

private:
    struct PageRecord {
        Bytes encoded;
        std::size_t logical_size = 0;
        bool raw = false;
    };
    struct CacheEntry {
        Page bytes;
        std::uint64_t last_use = 0;
    };

    CompressedWeightStore(std::size_t page_size, std::size_t budget, std::size_t logical)
        : page_size_(page_size), expanded_cache_budget_(budget), logical_bytes_(logical) {}

    // PackBits-like byte RLE. Token high bit: repeated byte; low 7 bits encode
    // run length minus one. Otherwise token encodes literal length minus one.
    // Worst case is bounded by n + ceil(n/128); caller retains raw if not smaller.
    static Bytes Encode(const Bytes& input) {
        Bytes out;
        out.reserve(input.size());
        std::size_t i = 0;
        while (i < input.size()) {
            std::size_t run = 1;
            while (i + run < input.size() && input[i + run] == input[i] && run < 128) ++run;
            if (run >= 3) {
                out.push_back(static_cast<std::uint8_t>(0x80u | (run - 1)));
                out.push_back(input[i]);
                i += run;
                continue;
            }
            const std::size_t begin = i;
            i += run;
            while (i < input.size() && i - begin < 128) {
                std::size_t next_run = 1;
                while (i + next_run < input.size() &&
                       input[i + next_run] == input[i] && next_run < 128) ++next_run;
                if (next_run >= 3) break;
                const std::size_t take = (std::min)(next_run, 128 - (i - begin));
                i += take;
            }
            const std::size_t count = i - begin;
            out.push_back(static_cast<std::uint8_t>(count - 1));
            out.insert(out.end(), input.begin() + begin, input.begin() + i);
        }
        return out;
    }

    static Bytes Decode(const Bytes& input, std::size_t expected_size) {
        Bytes out;
        out.reserve(expected_size);
        std::size_t i = 0;
        while (i < input.size()) {
            const std::uint8_t token = input[i++];
            const std::size_t count = static_cast<std::size_t>(token & 0x7fu) + 1;
            if (token & 0x80u) {
                if (i >= input.size() || count > expected_size - out.size())
                    return {};
                out.insert(out.end(), count, input[i++]);
            } else {
                if (count > input.size() - i || count > expected_size - out.size())
                    return {};
                out.insert(out.end(), input.begin() + i, input.begin() + i + count);
                i += count;
            }
        }
        if (out.size() != expected_size) return {};
        return out;
    }

    void EvictUntilFits(std::size_t incoming) const {
        while (!cache_.empty() &&
               (incoming > expanded_cache_budget_ ||
                resident_expanded_bytes_ > expanded_cache_budget_ - incoming)) {
            auto victim = cache_.end();
            for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                if (it->second.bytes.use_count() != 1) continue; // pinned by a consumer
                if (victim == cache_.end() ||
                    it->second.last_use < victim->second.last_use) victim = it;
            }
            if (victim == cache_.end()) break; // all pages are in-flight
            resident_expanded_bytes_ -= victim->second.bytes->size();
            cache_.erase(victim);
        }
    }

    const std::size_t page_size_;
    const std::size_t expanded_cache_budget_;
    const std::size_t logical_bytes_;
    std::vector<PageRecord> pages_;
    std::size_t compressed_bytes_ = 0;
    mutable std::mutex mutex_;
    mutable std::unordered_map<std::size_t, CacheEntry> cache_;
    mutable std::size_t resident_expanded_bytes_ = 0;
    mutable std::uint64_t clock_ = 0;
};

} // namespace rawrxd::memory
