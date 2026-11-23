#pragma once
// Bounded, lossless compressed residency for arbitrary encoded tensor payloads.
// GGUF quantization bytes are preserved exactly; only RLE-profitable chunks
// enter this cache. Non-profitable tensors remain on the ROM pager path.
#include "NativeTensorCompression.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Deep2 {
class TensorByteResidencyCache {
public:
    struct Stats {
        size_t budgetBytes = 0;
        size_t compressedBytes = 0;
        size_t logicalBytes = 0;
        size_t tensorCount = 0;
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t evictions = 0;
        uint64_t bytesDecoded = 0;
    };

    explicit TensorByteResidencyCache(size_t budget = 512ull * 1024ull * 1024ull)
        : budgetBytes_(budget) {}
    TensorByteResidencyCache(const TensorByteResidencyCache&) = delete;
    TensorByteResidencyCache& operator=(const TensorByteResidencyCache&) = delete;

    template<class Reader>
    bool RegisterFromReader(const std::string& key, size_t byteCount, Reader&& reader,
                            size_t chunkBytes = 64 * 1024) {
        if (key.empty()) return false;
        size_t buildBudget;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (entries_.find(key) != entries_.end()) return true;
            if (rawFallback_.find(key) != rawFallback_.end()) return false;
            buildBudget = budgetBytes_;
        }
        std::shared_ptr<RawrXD::TensorCompression::ChunkedByteStorage> built;
        try {
            built = std::make_shared<RawrXD::TensorCompression::ChunkedByteStorage>(
                RawrXD::TensorCompression::ChunkedByteStorage::BuildFromReader(
                    byteCount, std::forward<Reader>(reader), chunkBytes, true, buildBudget));
        } catch (...) {
            return false;
        }
        const size_t stored = built->storedBytes();
        if (byteCount && stored >= byteCount) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (stored > budgetBytes_) return false;
        auto existing = entries_.find(key);
        if (existing != entries_.end()) { existing->second.lastUse = ++tick_; return true; }
        EvictToFitLocked(stored, key);
        if (stored > budgetBytes_ - compressedBytes_) return false;
        Entry e;
        e.storage = std::move(built);
        e.compressedBytes = stored;
        e.logicalBytes = byteCount;
        e.lastUse = ++tick_;
        compressedBytes_ += stored;
        logicalBytes_ += byteCount;
        entries_.emplace(key, std::move(e));
        return true;
    }

    bool Contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.find(key) != entries_.end();
    }
    void MarkRawFallback(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        rawFallback_.insert(key);
    }
    bool IsRawFallback(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return rawFallback_.find(key) != rawFallback_.end();
    }
    bool ReadRange(const std::string& key, size_t first, size_t count,
                   uint8_t* destination, std::vector<uint8_t>& scratch) {
        std::shared_ptr<const RawrXD::TensorCompression::ChunkedByteStorage> storage;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it == entries_.end()) { ++misses_; return false; }
            it->second.lastUse = ++tick_;
            ++hits_;
            storage = it->second.storage;
        }
        try { storage->ReadRange(first, count, destination, scratch); }
        catch (...) { return false; }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const uint64_t n = static_cast<uint64_t>(count);
            bytesDecoded_ = n > UINT64_MAX - bytesDecoded_ ? UINT64_MAX : bytesDecoded_ + n;
        }
        return true;
    }
    bool Evict(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        compressedBytes_ -= it->second.compressedBytes;
        logicalBytes_ -= it->second.logicalBytes;
        entries_.erase(it);
        ++evictions_;
        return true;
    }
    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        evictions_ += entries_.size();
        entries_.clear();
        rawFallback_.clear();
        compressedBytes_ = logicalBytes_ = 0;
    }
    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {budgetBytes_, compressedBytes_, logicalBytes_, entries_.size(),
                hits_, misses_, evictions_, bytesDecoded_};
    }
private:
    struct Entry {
        std::shared_ptr<RawrXD::TensorCompression::ChunkedByteStorage> storage;
        size_t compressedBytes = 0;
        size_t logicalBytes = 0;
        uint64_t lastUse = 0;
    };
    void EvictToFitLocked(size_t needed, const std::string& protectedKey) {
        while (needed <= budgetBytes_ && compressedBytes_ > budgetBytes_ - needed) {
            auto victim = entries_.end();
            for (auto it = entries_.begin(); it != entries_.end(); ++it)
                if (it->first != protectedKey &&
                    (victim == entries_.end() || it->second.lastUse < victim->second.lastUse))
                    victim = it;
            if (victim == entries_.end()) break;
            compressedBytes_ -= victim->second.compressedBytes;
            logicalBytes_ -= victim->second.logicalBytes;
            entries_.erase(victim);
            ++evictions_;
        }
    }
    mutable std::mutex mutex_;
    size_t budgetBytes_ = 0, compressedBytes_ = 0, logicalBytes_ = 0;
    uint64_t tick_ = 0, hits_ = 0, misses_ = 0, evictions_ = 0, bytesDecoded_ = 0;
    std::unordered_map<std::string, Entry> entries_;
    std::unordered_set<std::string> rawFallback_;
};
} // namespace Deep2
