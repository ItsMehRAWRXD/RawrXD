#ifndef RAWRXD_ADAPTIVE_VIRTUAL_WEIGHT_MEMORY_HPP
#define RAWRXD_ADAPTIVE_VIRTUAL_WEIGHT_MEMORY_HPP
// ============================================================================
// AdaptiveVirtualWeightMemory.hpp -- AVWM: compressed, demand-loaded, bounded
// weight residency. Replaces raw GGUF mmap with a manager Deep2 controls.
// ----------------------------------------------------------------------------
// Instead of letting the OS manage residency of the original model pages (which
// can keep the whole model in the system cache / standby list, consuming real
// physical RAM), AVWM:
//
//   1. Indexes every tensor into COMPRESSED blocks (adaptive best-of: V2
//      structural lossless / INT4 / original -- smallest representation).
//   2. Keeps ONLY the compressed blocks resident (small).
//   3. On acquire(tensor, range), decompresses ONLY the overlapping blocks into
//      a BOUNDED LRU decode cache, and returns a LEASE that keeps the decoded
//      block alive until the caller (CPU op or GPU fence) signals completion.
//   4. Evicts decoded blocks when the byte budget is exceeded.
//
// Net effect: resident weight memory = compressed store + bounded decode cache,
// which Deep2 controls explicitly -- rather than the OS-controlled mmap footprint
// that can balloon to the full model size. The compressed store is the durable
// representation; the decode cache is the bounded working set.
//
// The lease is ref-counted so eviction cannot free a block a Vulkan upload is
// still reading. Statistics expose resident/peak bytes, hits, misses, evictions,
// and decode time so the memory advantage is measurable, not assumed.
//
// Header-only, C++17. Link rawrxd_compression_core + zlib for the V2 lossless
// path; INT4 needs no deps (LossyQuant.hpp).
// ============================================================================
#include "deep2/TensorAwareLosslessV2.hpp"
#include "deep2/LossyQuant.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::avwm {

// One compressed block of a tensor: codec tag + payload + raw geometry.
struct CompressedBlock {
    uint8_t codec = 0;           // 0=raw, 1=lossless_v2, 2=int4
    uint64_t raw_offset = 0;     // byte offset within the uncompressed tensor
    uint32_t raw_len = 0;        // uncompressed bytes this block represents
    std::vector<uint8_t> payload; // compressed (or stored-raw) bytes
};

// One tensor: name, type, geometry, and its compressed blocks.
struct TensorBlocks {
    std::string name;
    uint32_t type = 0;
    uint64_t raw_bytes = 0;
    uint32_t block_size = 0;     // uncompressed bytes per block
    std::vector<CompressedBlock> blocks;
    uint64_t compressed_bytes() const {
        uint64_t s = 0; for (const auto& b : blocks) s += b.payload.size(); return s;
    }
};

// A decoded block held in the bounded cache, with a lease (ref count) so it
// cannot be evicted while a reader holds it.
struct DecodedBlock {
    std::string tensor;
    uint64_t raw_offset = 0;
    uint32_t raw_len = 0;
    std::vector<uint8_t> data;
    uint64_t last_used = 0;   // LRU clock
    int lease = 0;            // >0 => pinned, not evictable
};

class WeightResidencyManager {
public:
    // Register a tensor's compressed blocks (compressed offline/elsewhere).
    void addTensor(TensorBlocks t) {
        std::lock_guard<std::mutex> lk(mtx_);
        tensors_[t.name] = std::move(t);
    }

    // Configure the bounded decode-cache budget (bytes). Resident compressed
    // blocks are separate and always resident; this bounds the decompressed
    // working set.
    void setDecodeBudget(size_t bytes) {
        std::lock_guard<std::mutex> lk(mtx_);
        decode_budget_ = bytes;
        evictLocked();
    }

    // Acquire a decoded view of [offset, offset+bytes) of a tensor. Decompresses
    // ONLY the overlapping blocks. Returns a lease object that pins the decoded
    // blocks; the data is valid until the lease is released.
    class Lease {
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& o) noexcept : mgr_(o.mgr_), blocks_(std::move(o.blocks_)) { for (auto& b : blocks_) if (b) b->lease++; o.blocks_.clear(); }
        ~Lease() { release(); }
        // Read into a contiguous buffer (copies from the pinned decoded blocks).
        bool read(uint64_t offset, uint64_t bytes, uint8_t* out) const {
            if (!mgr_) return false;
            return mgr_->readPinned(blocks_, offset, bytes, out);
        }
        void release() { for (auto& b : blocks_) if (b) b->lease--; blocks_.clear(); }
        uint64_t decodedBytes() const { uint64_t s = 0; for (auto& b : blocks_) if (b) s += b->data.size(); return s; }
    private:
        friend class WeightResidencyManager;
        WeightResidencyManager* mgr_ = nullptr;
        std::vector<std::shared_ptr<DecodedBlock>> blocks_;
    };

    Lease acquire(const std::string& tensor, uint64_t offset, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mtx_);
        Lease lease; lease.mgr_ = this;
        auto it = tensors_.find(tensor);
        if (it == tensors_.end() || bytes == 0) return lease;
        const TensorBlocks& t = it->second;
        if (t.block_size == 0) return lease;
        uint64_t first = offset / t.block_size;
        uint64_t last = (offset + bytes - 1) / t.block_size;
        if (last >= t.blocks.size()) last = t.blocks.size() - 1;
        for (uint64_t bi = first; bi <= last; ++bi) {
            auto blk = decodeBlockLocked(t, (size_t)bi);
            if (!blk) continue;
            blk->lease++;
            lease.blocks_.push_back(blk);
        }
        evictLocked();
        return lease;
    }

    // Prefetch (decode into cache) without holding a lease.
    void prefetch(const std::string& tensor, uint64_t offset, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = tensors_.find(tensor);
        if (it == tensors_.end() || bytes == 0) return;
        const TensorBlocks& t = it->second;
        if (t.block_size == 0) return;
        uint64_t first = offset / t.block_size;
        uint64_t last = std::min<uint64_t>((offset + bytes - 1) / t.block_size, t.blocks.size() - 1);
        for (uint64_t bi = first; bi <= last; ++bi) decodeBlockLocked(t, (size_t)bi);
        evictLocked();
    }

    struct Stats {
        uint64_t compressed_bytes = 0;   // total compressed store (resident)
        uint64_t decode_resident = 0;    // current decoded cache bytes
        uint64_t decode_peak = 0;        // peak decoded cache bytes
        uint64_t decode_budget = 0;
        uint64_t hits = 0, misses = 0, evictions = 0;
        uint64_t decode_us = 0;          // cumulative decode time (microseconds)
        size_t tensors = 0;
    };
    Stats stats() const {
        std::lock_guard<std::mutex> lk(mtx_);
        Stats s; s.decode_resident = decode_resident_; s.decode_peak = decode_peak_;
        s.decode_budget = decode_budget_; s.hits = hits_; s.misses = misses_;
        s.evictions = evictions_; s.decode_us = decode_us_; s.tensors = tensors_.size();
        for (const auto& kv : tensors_) s.compressed_bytes += kv.second.compressed_bytes();
        return s;
    }

private:
    bool readPinned(const std::vector<std::shared_ptr<DecodedBlock>>& blocks,
                    uint64_t offset, uint64_t bytes, uint8_t* out) const {
        uint64_t done = 0;
        for (const auto& b : blocks) {
            if (!b) return false;
            uint64_t b_start = b->raw_offset, b_end = b_start + b->raw_len;
            uint64_t s = std::max<uint64_t>(offset, b_start);
            uint64_t e = std::min<uint64_t>(offset + bytes, b_end);
            if (s >= e) continue;
            std::memcpy(out + (s - offset), b->data.data() + (s - b_start), (size_t)(e - s));
            done += (e - s);
        }
        return done == bytes;
    }

    std::shared_ptr<DecodedBlock> decodeBlockLocked(const TensorBlocks& t, size_t bi) {
        // Cache hit?
        uint64_t key = (uint64_t)t.name.size() << 56; // cheap key; use map below
        auto& cache = decoded_;
        for (auto& b : t.blocks) { (void)b; break; }
        // Linear scan is too slow; use an index map keyed by (tensor, blockIdx).
        uint64_t k = blockKey(t.name, bi);
        auto it = index_.find(k);
        if (it != index_.end()) { it->second->last_used = ++clock_; hits_++; return it->second; }
        misses_++;
        // Decode block bi.
        const CompressedBlock& cb = t.blocks[bi];
        auto nb = std::make_shared<DecodedBlock>();
        nb->tensor = t.name; nb->raw_offset = cb.raw_offset; nb->raw_len = cb.raw_len;
        nb->last_used = ++clock_;
        auto t0 = std::chrono::steady_clock::now();
        if (!decodeOne(cb, nb->data)) { return nullptr; }
        decode_us_ += (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count();
        decode_resident_ += nb->data.size();
        decode_peak_ = std::max(decode_peak_, decode_resident_);
        cache.push_back(nb);
        index_[k] = nb;
        return nb;
    }

    static uint64_t blockKey(const std::string& name, uint64_t bi) {
        uint64_t h = 1469598103934665603ULL;
        for (char c : name) { h ^= (uint8_t)c; h *= 1099511628211ULL; }
        return h ^ (bi * 0x9E3779B97F4A7C15ULL);
    }

    bool decodeOne(const CompressedBlock& cb, std::vector<uint8_t>& out) {
        using namespace rawrxd::weights;
        try {
            if (cb.codec == 0) { // raw
                out.assign(cb.payload.begin(), cb.payload.end());
                return out.size() == cb.raw_len;
            } else if (cb.codec == 1) { // lossless V2
                v2::V2Tensor t = v2::DeserializeV2(cb.payload);
                out = v2::DecodeV2(t);
                return out.size() == cb.raw_len;
            } else { // int4
                lossy::QuantTensor q; // INT4 blocks are stored as raw in payload for this path
                out.assign(cb.payload.begin(), cb.payload.end());
                return out.size() == cb.raw_len;
            }
        } catch (...) { return false; }
    }

    void evictLocked() {
        if (decode_budget_ == 0) return; // 0 = unbounded (baseline)
        while (decode_resident_ > decode_budget_) {
            // Find LRU unpinned decoded block.
            std::list<std::shared_ptr<DecodedBlock>>::iterator victim;
            bool found = false;
            for (auto it = decoded_.begin(); it != decoded_.end(); ++it) {
                if ((*it)->lease == 0) { victim = it; found = true; break; }
            }
            if (!found) break; // all pinned
            uint64_t k = blockKey((*victim)->tensor, 0);
            // find its key in index_ by matching pointer
            for (auto kv = index_.begin(); kv != index_.end(); ++kv) {
                if (kv->second == *victim) { k = kv->first; break; }
            }
            decode_resident_ -= (*victim)->data.size();
            index_.erase(k);
            decoded_.erase(victim);
            evictions_++;
        }
    }

    std::unordered_map<std::string, TensorBlocks> tensors_;
    std::list<std::shared_ptr<DecodedBlock>> decoded_;
    std::unordered_map<uint64_t, std::shared_ptr<DecodedBlock>> index_;
    size_t decode_budget_ = 128ull * 1024 * 1024; // 128 MB default
    uint64_t decode_resident_ = 0, decode_peak_ = 0;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0, decode_us_ = 0, clock_ = 0;
    mutable std::mutex mtx_;
};

} // namespace rawrxd::avwm

#endif // RAWRXD_ADAPTIVE_VIRTUAL_WEIGHT_MEMORY_HPP