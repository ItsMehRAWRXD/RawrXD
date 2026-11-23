#pragma once
// Bounded, thread-safe compressed F32 weight residency for Deep2.
// Stores chunked private representations, not modified GGUF wire data.
// Readers decode only the requested chunks into caller-owned scratch/output.
#include "NativeTensorCompression.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
        size_t activeReaders = 0;
    };

    explicit TensorResidencyCache(size_t budgetBytes = 512ull * 1024ull * 1024ull)
        : budgetBytes_(budgetBytes) {}

    TensorResidencyCache(const TensorResidencyCache&) = delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&) = delete;

    // Explicit model boundary: equal-sized keys are not proof of identical
    // weights. A new identity invalidates both encoded entries and fallback
    // decisions, after all in-flight readers release their leases.
    // The caller must stop starting reads for the old model before switching.
    void SetModelIdentity(const std::string& identity) {
        std::lock_guard<std::mutex> buildLock(buildMutex_);
        std::unique_lock<std::mutex> lock(mutex_);
        if (modelIdentity_ == identity) return;
        readersDrained_.wait(lock, [this] {
            for (const auto& item : entries_)
                if (item.second.activeReaders != 0) return false;
            return true;
        });
        evictions_ += entries_.size();
        entries_.clear();
        rawFallback_.clear();
        compressedBytes_ = logicalBytes_ = 0;
        modelIdentity_ = identity;
    }

    std::string ModelIdentity() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return modelIdentity_;
    }

    void SetBudget(size_t bytes) {
        // Serialize budget changes with first-touch builds. Otherwise a build
        // can hold a candidate sized for the old budget while the new smaller
        // budget is already advertised to concurrent inference callers.
        std::lock_guard<std::mutex> buildLock(buildMutex_);
        std::lock_guard<std::mutex> lock(mutex_);
        if (budgetBytes_ != bytes) rawFallback_.clear();
        budgetBytes_ = bytes;
        EvictToFitLocked(0, std::string());
    }

    template<class Reader>
    bool RegisterF32FromReader(const std::string& key,size_t elementCount,
                               float maxAbsError,Reader&& reader,
                               size_t chunkElements = 4096) {
        if(key.empty()) return false;
        // Serialize first-touch construction. Concurrent inference agents must
        // not create duplicate temporary compressed copies of one tensor.
        std::lock_guard<std::mutex> buildLock(buildMutex_);
        auto rejectAndMemoize = [this, &key]() {
            std::lock_guard<std::mutex> lock(mutex_);
            rawFallback_.insert(key);
            return false;
        };
        size_t buildBudget = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto existing = entries_.find(key);
            if (existing != entries_.end()) {
                // Reject a key reused for a differently sized model tensor.
                // Callers must also namespace keys by model identity, since
                // equal-sized tensors can contain different values.
                if (elementCount > std::numeric_limits<size_t>::max() / sizeof(float) ||
                    existing->second.logicalBytes != elementCount * sizeof(float) ||
                    existing->second.maxAbsError > maxAbsError)
                    return false;
                existing->second.lastUse = ++tick_;
                return true;
            }
            // Deterministic no-win/budget rejection is memoized; transient source
            // and runtime failures remain retryable.
            if (rawFallback_.find(key) != rawFallback_.end()) return false;
            // Bound the candidate itself to the configured budget. Once its
            // exact encoded size is known, insertion evicts least-recently-used
            // entries atomically under mutex_.
            buildBudget = budgetBytes_;
        }
        if (!buildBudget) return rejectAndMemoize();
        std::shared_ptr<RawrXD::TensorCompression::ChunkedF32Storage> built;
        try {
            built = std::make_shared<RawrXD::TensorCompression::ChunkedF32Storage>(
                RawrXD::TensorCompression::ChunkedF32Storage::BuildFromReader(
                    elementCount,maxAbsError,std::forward<Reader>(reader),chunkElements,false,
                    buildBudget));
        } catch (const RawrXD::TensorCompression::SourceReadFailure&) {
            return false; // retryable: do not memoize transient source I/O failures
        } catch (const RawrXD::TensorCompression::StorageAdmissionRejected&) {
            return rejectAndMemoize(); // deterministic no-win/budget rejection
        } catch (...) {
            // Allocation and unexpected failures do not establish that the
            // tensor is intrinsically incompressible; permit a later retry.
            return false;
        }
        if (elementCount > std::numeric_limits<size_t>::max()/sizeof(float))
            return rejectAndMemoize();
        const size_t stored = built->storedBytes();
        const size_t logical = elementCount * sizeof(float);
        // A raw fallback is not a compression win. Do not duplicate an F32
        // tensor in the cache when no lossless/tolerance-approved encoding
        // actually reduces its resident footprint.
        if (elementCount && stored >= logical) return rejectAndMemoize();
        std::lock_guard<std::mutex> lock(mutex_);
        if(stored > budgetBytes_) { rawFallback_.insert(key); return false; }
        if(entries_.find(key)!=entries_.end()) {
            entries_[key].lastUse=++tick_;
            return true;
        }
        EvictToFitLocked(stored,key);
        // A concurrent reader may temporarily pin enough old entries that
        // the cache remains above a newly lowered budget. Do not subtract in
        // that state (size_t would underflow), and do not memoize this as a
        // deterministic raw fallback: once leases drain, admission can retry.
        if(compressedBytes_ > budgetBytes_ ||
           stored > budgetBytes_ - compressedBytes_) {
            return false;
        }
        Entry e;
        e.storage=std::move(built);
        e.compressedBytes=stored;
        e.logicalBytes=elementCount*sizeof(float);
        e.maxAbsError=maxAbsError;
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

    // Remember tensors that cannot be compressed safely or do not fit the
    // current budget, so every later tile does not repeat the initial probe.
    void MarkRawFallback(const std::string& key) {
        // Match the builder lock order (buildMutex_ -> mutex_) so a fallback
        // cannot be published midway through a concurrent first-touch build.
        std::lock_guard<std::mutex> buildLock(buildMutex_);
        std::lock_guard<std::mutex> lock(mutex_);
        rawFallback_.insert(key);
    }

    bool IsRawFallback(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return rawFallback_.find(key)!=rawFallback_.end();
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
            ++it->second.activeReaders;
            ++cacheHits_;
            storage=it->second.storage;
        }
        bool decoded = false;
        try {
            storage->ReadRange(first,count,destination,decodeScratch);
            decoded = true;
        } catch (...) {
            decoded = false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it != entries_.end() && it->second.activeReaders) --it->second.activeReaders;
            if (decoded) {
                const uint64_t bytes=static_cast<uint64_t>(count)*sizeof(float);
                bytesDecoded_ = bytes > std::numeric_limits<uint64_t>::max()-bytesDecoded_
                    ? std::numeric_limits<uint64_t>::max() : bytesDecoded_+bytes;
            }
            EvictToFitLocked(0, std::string());
            readersDrained_.notify_all();
        }
        return decoded;
    }

    // Export compact F16/BF16 bytes for a chunk-aligned range. A successful
    // call pins the entry against eviction for the duration of the copy. The
    // returned bytes remain in the cache's native 16-bit representation.
    bool ExportUniform16BitRange(const std::string& key, size_t first, size_t count,
                                 RawrXD::TensorCompression::Encoding& encoding,
                                 std::vector<uint8_t>& packed) {
        std::shared_ptr<const RawrXD::TensorCompression::ChunkedF32Storage> storage;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it == entries_.end()) { ++cacheMisses_; packed.clear(); return false; }
            it->second.lastUse = ++tick_;
            ++it->second.activeReaders;
            ++cacheHits_;
            storage = it->second.storage;
        }
        bool exported = false;
        try {
            exported = storage->ExportUniform16BitRange(first, count, encoding, packed);
        } catch (...) {
            packed.clear();
            exported = false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it != entries_.end() && it->second.activeReaders) --it->second.activeReaders;
            EvictToFitLocked(0, std::string());
            readersDrained_.notify_all();
        }
        if (!exported) packed.clear();
        return exported;
    }

    // Fill caller-owned GPU upload staging directly. The shared storage
    // reference keeps chunks alive while the copy is in progress.
    bool CopyUniform16BitRange(const std::string& key, size_t first, size_t count,
                               RawrXD::TensorCompression::Encoding& encoding,
                               void* destination, size_t destinationBytes) {
        std::shared_ptr<const RawrXD::TensorCompression::ChunkedF32Storage> storage;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it == entries_.end()) { ++cacheMisses_; return false; }
            it->second.lastUse = ++tick_;
            ++it->second.activeReaders;
            ++cacheHits_;
            storage = it->second.storage;
        }
        bool copied = false;
        try {
            copied = storage->CopyUniform16BitRange(
                first, count, encoding, destination, destinationBytes);
        } catch (...) {
            copied = false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it != entries_.end() && it->second.activeReaders)
                --it->second.activeReaders;
            EvictToFitLocked(0, std::string());
            readersDrained_.notify_all();
        }
        return copied;
    }

    bool Evict(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=entries_.find(key);
        if(it==entries_.end() || it->second.activeReaders != 0) return false;
        compressedBytes_-=it->second.compressedBytes;
        logicalBytes_-=it->second.logicalBytes;
        entries_.erase(it);
        ++evictions_;
        return true;
    }

    void Clear() {
        std::lock_guard<std::mutex> buildLock(buildMutex_);
        std::unique_lock<std::mutex> lock(mutex_);
        readersDrained_.wait(lock, [this] {
            for (const auto& item : entries_)
                if (item.second.activeReaders != 0) return false;
            return true;
        });
        if(!entries_.empty()) evictions_+=entries_.size();
        entries_.clear();
        rawFallback_.clear();
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
        for (const auto& item : entries_) s.activeReaders += item.second.activeReaders;
        return s;
    }

private:
    std::string modelIdentity_;

    struct Entry {
        std::shared_ptr<RawrXD::TensorCompression::ChunkedF32Storage> storage;
        size_t compressedBytes=0;
        size_t logicalBytes=0;
        float maxAbsError=0.0f;
        uint64_t lastUse=0;
        size_t activeReaders=0;
    };

    void EvictToFitLocked(size_t needed,const std::string& protectedKey) {
        while(needed<=budgetBytes_ && compressedBytes_>budgetBytes_-needed) {
            auto victim=entries_.end();
            for(auto it=entries_.begin();it!=entries_.end();++it) {
                if(it->first==protectedKey || it->second.activeReaders != 0) continue;
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
    std::mutex buildMutex_;
    std::condition_variable readersDrained_;
    size_t budgetBytes_=0;
    size_t compressedBytes_=0;
    size_t logicalBytes_=0;
    uint64_t tick_=0;
    uint64_t cacheHits_=0;
    uint64_t cacheMisses_=0;
    uint64_t bytesDecoded_=0;
    uint64_t evictions_=0;
    std::unordered_map<std::string,Entry> entries_;
    std::unordered_set<std::string> rawFallback_;
};
} // namespace Deep2
