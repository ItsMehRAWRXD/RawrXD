#pragma once
// Native, dependency-free, chunked byte residency cache.
// Lossless RLE is selected per chunk only when it is smaller than raw bytes.
// Callers request byte ranges; only intersecting chunks are materialized.
// This cache does not own the source mapping: owners may release it only after
// successful admission and after all readers have stopped using that mapping.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2 {

class TensorResidencyCache {
public:
    enum class Encoding : uint8_t { Raw = 0, RLE = 1 };

    struct Stats {
        size_t budgetBytes = 0;
        size_t storedBytes = 0;
        size_t logicalBytes = 0;
        size_t tensorCount = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t bytesDecoded = 0;
        uint64_t evictions = 0;
        size_t chunkCount = 0;
    };

    explicit TensorResidencyCache(size_t budgetBytes = 512ull * 1024ull * 1024ull,
                                  size_t chunkBytes = 64ull * 1024ull)
        : budgetBytes_(budgetBytes), chunkBytes_(chunkBytes) {
        if (!chunkBytes_) throw std::invalid_argument("zero residency chunk size");
    }

    TensorResidencyCache(const TensorResidencyCache&) = delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&) = delete;

    // Register an immutable byte span. No source pointer is retained.
    // Returns false if encoding does not save space or the entry cannot fit.
    bool Register(const std::string& key, const void* source, size_t bytes) {
        if (key.empty() || (bytes && !source)) return false;
        if (!bytes) return false;

        auto candidate = std::make_shared<Entry>();
        candidate->logicalBytes = bytes;
        const auto* src = static_cast<const uint8_t*>(source);
        size_t total = 0;
        for (size_t offset = 0; offset < bytes;) {
            const size_t n = std::min(chunkBytes_, bytes - offset);
            Chunk chunk;
            chunk.logicalBytes = n;
            EncodeChunk(src + offset, n, chunk);
            if (chunk.payload.size() > std::numeric_limits<size_t>::max() - total)
                return false;
            total += chunk.payload.size();
            candidate->chunks.emplace_back(std::move(chunk));
            offset += n;
        }
        if (total >= bytes) return false;
        candidate->storedBytes = total;

        std::lock_guard<std::mutex> lock(mutex_);
        auto existing = entries_.find(key);
        if (existing != entries_.end()) {
            TouchLocked(*existing->second);
            return true;
        }
        if (total > budgetBytes_) return false;
        EvictLocked(total);
        if (total > budgetBytes_ - storedBytes_) return false;
        candidate->lastUse = ++tick_;
        storedBytes_ += total;
        logicalBytes_ += bytes;
        chunkCount_ += candidate->chunks.size();
        entries_.emplace(key, std::move(candidate));
        return true;
    }

    // Read a bounded range into caller-owned memory. On invalid arguments the
    // destination is not touched. Chunks are independently decoded.
    bool ReadRange(const std::string& key, size_t offset, size_t bytes,
                   void* destination) {
        std::shared_ptr<const Entry> entry;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it == entries_.end()) { ++cacheMisses_; return false; }
            if (offset > it->second->logicalBytes ||
                bytes > it->second->logicalBytes - offset ||
                (bytes && !destination)) return false;
            TouchLocked(*it->second);
            ++cacheHits_;
            entry = it->second;
        }
        if (!bytes) return true;

        auto* out = static_cast<uint8_t*>(destination);
        const size_t firstChunk = offset / chunkBytes_;
        const size_t lastChunk = (offset + bytes - 1) / chunkBytes_;
        size_t written = 0;
        try {
            for (size_t index = firstChunk; index <= lastChunk; ++index) {
                const Chunk& chunk = entry->chunks.at(index);
                std::vector<uint8_t> decoded;
                DecodeChunk(chunk, decoded);
                const size_t chunkStart = index * chunkBytes_;
                const size_t begin = std::max(offset, chunkStart) - chunkStart;
                const size_t end = std::min(offset + bytes,
                    chunkStart + chunk.logicalBytes) - chunkStart;
                const size_t count = end - begin;
                std::memcpy(out + written, decoded.data() + begin, count);
                written += count;
            }
        } catch (...) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            bytesDecoded_ = bytes > std::numeric_limits<uint64_t>::max() - bytesDecoded_
                ? std::numeric_limits<uint64_t>::max()
                : bytesDecoded_ + static_cast<uint64_t>(bytes);
        }
        return written == bytes;
    }

    bool Contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.find(key) != entries_.end();
    }

    bool Erase(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        storedBytes_ -= it->second->storedBytes;
        logicalBytes_ -= it->second->logicalBytes;
        chunkCount_ -= it->second->chunks.size();
        entries_.erase(it);
        return true;
    }

    void SetBudget(size_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        budgetBytes_ = bytes;
        EvictLocked(0);
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        storedBytes_ = logicalBytes_ = chunkCount_ = 0;
    }

    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats s;
        s.budgetBytes = budgetBytes_;
        s.storedBytes = storedBytes_;
        s.logicalBytes = logicalBytes_;
        s.tensorCount = entries_.size();
        s.cacheHits = cacheHits_;
        s.cacheMisses = cacheMisses_;
        s.bytesDecoded = bytesDecoded_;
        s.evictions = evictions_;
        s.chunkCount = chunkCount_;
        return s;
    }

private:
    struct Chunk {
        Encoding encoding = Encoding::Raw;
        size_t logicalBytes = 0;
        std::vector<uint8_t> payload;
    };
    struct Entry {
        std::vector<Chunk> chunks;
        size_t logicalBytes = 0;
        size_t storedBytes = 0;
        uint64_t lastUse = 0;
    };

    static void EncodeChunk(const uint8_t* src, size_t bytes, Chunk& out) {
        std::vector<uint8_t> rle;
        rle.reserve(bytes);
        for (size_t i = 0; i < bytes;) {
            size_t run = 1;
            while (run < 255 && run < bytes - i && src[i + run] == src[i]) ++run;
            rle.push_back(static_cast<uint8_t>(run));
            rle.push_back(src[i]);
            i += run;
            if (rle.size() >= bytes) break;
        }
        if (rle.size() < bytes) {
            out.encoding = Encoding::RLE;
            out.payload = std::move(rle);
        } else {
            out.encoding = Encoding::Raw;
            out.payload.assign(src, src + bytes);
        }
    }

    static void DecodeChunk(const Chunk& chunk, std::vector<uint8_t>& out) {
        out.resize(chunk.logicalBytes);
        if (chunk.encoding == Encoding::Raw) {
            if (chunk.payload.size() != chunk.logicalBytes)
                throw std::runtime_error("raw residency chunk size mismatch");
            if (!out.empty()) std::memcpy(out.data(), chunk.payload.data(), out.size());
            return;
        }
        if (chunk.encoding != Encoding::RLE || (chunk.payload.size() & 1u))
            throw std::runtime_error("invalid residency chunk encoding");
        size_t total = 0;
        for (size_t i = 0; i < chunk.payload.size(); i += 2) {
            const size_t run = chunk.payload[i];
            if (!run || run > chunk.logicalBytes - total)
                throw std::runtime_error("invalid residency RLE run");
            total += run;
        }
        if (total != chunk.logicalBytes)
            throw std::runtime_error("residency RLE length mismatch");
        size_t at = 0;
        for (size_t i = 0; i < chunk.payload.size(); i += 2) {
            const size_t run = chunk.payload[i];
            std::memset(out.data() + at, chunk.payload[i + 1], run);
            at += run;
        }
    }

    void TouchLocked(Entry& entry) const { entry.lastUse = ++tick_; }

    void EvictLocked(size_t incoming) {
        while (incoming > budgetBytes_ - std::min(budgetBytes_, storedBytes_)) {
            auto victim = entries_.end();
            for (auto it = entries_.begin(); it != entries_.end(); ++it)
                if (victim == entries_.end() ||
                    it->second->lastUse < victim->second->lastUse) victim = it;
            if (victim == entries_.end()) break;
            storedBytes_ -= victim->second->storedBytes;
            logicalBytes_ -= victim->second->logicalBytes;
            chunkCount_ -= victim->second->chunks.size();
            entries_.erase(victim);
            ++evictions_;
        }
    }

    mutable std::mutex mutex_;
    mutable uint64_t tick_ = 0;
    size_t budgetBytes_ = 0;
    size_t chunkBytes_ = 0;
    size_t storedBytes_ = 0;
    size_t logicalBytes_ = 0;
    size_t chunkCount_ = 0;
    uint64_t cacheHits_ = 0;
    uint64_t cacheMisses_ = 0;
    uint64_t bytesDecoded_ = 0;
    uint64_t evictions_ = 0;
    std::unordered_map<std::string, std::shared_ptr<Entry>> entries_;
};

} // namespace Deep2

namespace gguf_shard_cache {
using TensorResidencyCache = Deep2::TensorResidencyCache;
} // namespace gguf_shard_cache
