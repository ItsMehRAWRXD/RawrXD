#pragma once
// Bounded, thread-safe compressed F32 weight residency for Deep2.
// Stores chunked private representations, not modified GGUF wire data.
// Readers decode only the requested chunks into caller-owned scratch/output.
#include "NativeTensorCompression.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace Deep2 {
class TensorResidencyCache {
public:
    struct Stats {
        size_t budgetBytes = 0;
        size_t compressedBytes = 0;
        size_t logicalBytes = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t bytesDecoded = 0;
        uint64_t evictions = 0;
        size_t tensorCount = 0;
    };

    explicit TensorResidencyCache(size_t budgetBytes = 512ull * 1024ull * 1024ull)
        : budgetBytes_(budgetBytes) {}

    TensorResidencyCache(const TensorResidencyCache&) = delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&) = delete;

    void SetBudget(size_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        budgetBytes_ = bytes;
        EvictToFitLocked(0, std::string());
    }

    template<class Reader>
    bool RegisterF32FromReader(const std::string& key,size_t elementCount,
                               float maxAbsError,Reader&& reader,
                               size_t chunkElements = 4096) {
        if(key.empty()) return false;
        std::shared_ptr<RawrXD::TensorCompression::ChunkedF32Storage> built;
        try {
            built = std::make_shared<RawrXD::TensorCompression::ChunkedF32Storage>(
                RawrXD::TensorCompression::ChunkedF32Storage::BuildFromReader(
                    elementCount,maxAbsError,std::forward<Reader>(reader),chunkElements,true));
        } catch (...) {
            return false;
        }
        if (elementCount > std::numeric_limits<size_t>::max()/sizeof(float))
            return false;
        const size_t stored = built->storedBytes();
        const size_t logical = elementCount * sizeof(float);
        // A raw fallback is not a compression win. Do not duplicate an F32
        // tensor in the cache when no lossless/tolerance-approved encoding
        // actually reduces its resident footprint.
        if (elementCount && stored >= logical) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if(stored > budgetBytes_) return false;
        if(entries_.find(key)!=entries_.end()) {
            entries_[key].lastUse=++tick_;
            return true;
        }
        EvictToFitLocked(stored,key);
        if(stored > budgetBytes_ - compressedBytes_) return false;
        Entry e;
        e.storage=std::move(built);
        e.compressedBytes=stored;
        e.logicalBytes=elementCount*sizeof(float);
        e.lastUse=++tick_;
        compressedBytes_+=e.compressedBytes;
        logicalBytes_+=e.logicalBytes;
        entries_.emplace(key,std::move(e));
        return true;
    }

    bool Contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.find(key)!=entries_.end();
    }

    bool ReadRange(const std::string& key,size_t first,size_t count,float* destination) {
        std::vector<uint8_t> decodeScratch;
        return ReadRange(key,first,count,destination,decodeScratch);
    }

    bool ReadRange(const std::string& key,size_t first,size_t count,float* destination,
                   std::vector<uint8_t>& decodeScratch) {
        std::shared_ptr<const RawrXD::TensorCompression::ChunkedF32Storage> storage;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it=entries_.find(key);
            if(it==entries_.end()) { ++cacheMisses_; return false; }
            it->second.lastUse=++tick_;
            ++cacheHits_;
            storage=it->second.storage;
        }
        try {
            storage->ReadRange(first,count,destination,decodeScratch);
        } catch (...) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const uint64_t bytes=static_cast<uint64_t>(count)*sizeof(float);
            bytesDecoded_ = bytes > std::numeric_limits<uint64_t>::max()-bytesDecoded_
                ? std::numeric_limits<uint64_t>::max() : bytesDecoded_+bytes;
        }
        return true;
    }

    bool Evict(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=entries_.find(key);
        if(it==entries_.end()) return false;
        compressedBytes_-=it->second.compressedBytes;
        logicalBytes_-=it->second.logicalBytes;
        entries_.erase(it);
        ++evictions_;
        return true;
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!entries_.empty()) evictions_+=entries_.size();
        entries_.clear();
        compressedBytes_=0;
        logicalBytes_=0;
    }

    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats s;
        s.budgetBytes=budgetBytes_;
        s.compressedBytes=compressedBytes_;
        s.logicalBytes=logicalBytes_;
        s.cacheHits=cacheHits_;
        s.cacheMisses=cacheMisses_;
        s.bytesDecoded=bytesDecoded_;
        s.evictions=evictions_;
        s.tensorCount=entries_.size();
        return s;
    }

private:
    struct Entry {
        std::shared_ptr<RawrXD::TensorCompression::ChunkedF32Storage> storage;
        size_t compressedBytes=0;
        size_t logicalBytes=0;
        uint64_t lastUse=0;
    };

    void EvictToFitLocked(size_t needed,const std::string& protectedKey) {
        while(needed<=budgetBytes_ && compressedBytes_>budgetBytes_-needed) {
            auto victim=entries_.end();
            for(auto it=entries_.begin();it!=entries_.end();++it) {
                if(it->first==protectedKey) continue;
                if(victim==entries_.end() || it->second.lastUse<victim->second.lastUse)
                    victim=it;
            }
            if(victim==entries_.end()) break;
            compressedBytes_-=victim->second.compressedBytes;
            logicalBytes_-=victim->second.logicalBytes;
            entries_.erase(victim);
            ++evictions_;
        }
    }

    mutable std::mutex mutex_;
    size_t budgetBytes_=0;
    size_t compressedBytes_=0;
    size_t logicalBytes_=0;
    uint64_t tick_=0;
    uint64_t cacheHits_=0;
    uint64_t cacheMisses_=0;
    uint64_t bytesDecoded_=0;
    uint64_t evictions_=0;
    std::unordered_map<std::string,Entry> entries_;
};
} // namespace Deep2
