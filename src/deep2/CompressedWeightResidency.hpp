#ifndef RAWRXD_COMPRESSED_WEIGHT_RESIDENCY_HPP
#define RAWRXD_COMPRESSED_WEIGHT_RESIDENCY_HPP
// ============================================================================
// CompressedWeightResidency.hpp  --  Native Universal Compression Expansion
// ----------------------------------------------------------------------------
// Keeps model weights compressed WHILE RESIDENT IN MEMORY and decompresses only
// the byte ranges an inference kernel actually reads. This is the step past
// "compress the GGUF file on disk": the resident footprint of a loaded model is
// the compressed size, and a kernel that touches one row materialises only the
// block(s) covering that row -- never the whole tensor.
//
// Design (block-indexed, codec-agnostic):
//   * A tensor is split into fixed-size uncompressed blocks (default 64 KiB).
//   * Each block is compressed independently through rawrxd::compression
//     (zlib when RAWRXD_HAVE_ZLIB=1, otherwise the dependency-free RXDN codec).
//     Every block is therefore a self-contained, byte-exact, corruption-checked
//     unit that can be inflated on its own.
//   * "Universal / fp16-style" policy: a block is stored compressed only when
//     that shrinks it; otherwise it is stored verbatim (stored_raw=1). This is
//     the same rule as "fp16 only shrinks f32 tensors" -- compressible data
//     shrinks, already-dense/incompressible data is left untouched rather than
//     expanded. Incompressible tensors therefore cost ~raw + tiny index.
//   * Only the compressed blob and a small per-block index are kept resident.
//     The caller's uncompressed buffer is NOT retained.
//
// read(offset, bytes) inflates exactly the blocks that overlap the request and
// copies the requested sub-slice, so a single-row read of a 200-block tensor
// touches one block, not all of them. Diagnostic counters make that provable.
//
// Header-only, C++17, no Qt, no zlib types leak. Link rawrxd_compression_core.
// ============================================================================
#include "codec/compression_core.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::residency {

// One compressed (or verbatim-stored) block inside CompressedTensor::blob_.
struct CompressedBlock {
    std::uint64_t raw_offset = 0;  // byte offset of this block in the tensor
    std::uint32_t raw_len = 0;     // uncompressed bytes in this block
    std::uint64_t comp_offset = 0; // byte offset of the block inside blob_
    std::uint32_t comp_len = 0;    // bytes occupied in blob_
    std::uint32_t stored_raw = 0;  // 1 => stored verbatim (compression did not shrink)
};

// ---------------------------------------------------------------------------
// CompressedTensor -- one tensor kept compressed in memory.
// ---------------------------------------------------------------------------
class CompressedTensor {
public:
    CompressedTensor() = default;
    CompressedTensor(const CompressedTensor&) = delete;
    CompressedTensor& operator=(const CompressedTensor&) = delete;
    // Holds a std::mutex, so it is neither copyable nor movable. The store keeps
    // tensors behind std::unique_ptr for exactly this reason.
    CompressedTensor(CompressedTensor&&) = delete;
    CompressedTensor& operator=(CompressedTensor&&) = delete;

    // Compress `size` bytes at `data` into this tensor's resident store.
    // `block_size` is the uncompressed bytes per independent block. The input
    // buffer is consumed immediately and never referenced again, so the store
    // truly holds only the compressed form. Returns false on any codec failure.
    bool build(const std::uint8_t* data, std::size_t size,
               std::size_t block_size = 64u * 1024u) {
        if (data == nullptr && size != 0) return false;
        if (block_size == 0) block_size = 1;
        std::lock_guard<std::mutex> lk(mtx_);
        blocks_.clear();
        blob_.clear();
        raw_bytes_ = size;
        block_size_ = block_size;
        try {
            blob_.reserve(size / 2 + 16);
        } catch (...) {
            return false;
        }
        for (std::uint64_t off = 0; off < size;) {
            const std::uint64_t remain = static_cast<std::uint64_t>(size) - off;
            const std::uint32_t raw_len =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(remain, block_size_));
            const std::uint8_t* src = data + off;

            const auto comp = rawrxd::compression::compress(src, raw_len);
            CompressedBlock blk;
            blk.raw_offset = off;
            blk.raw_len = raw_len;
            blk.comp_offset = blob_.size();

            if (comp.status == rawrxd::compression::Status::Ok &&
                comp.bytes.size() < raw_len) {
                // Compression shrank this block -> keep it compressed.
                blk.comp_len = static_cast<std::uint32_t>(comp.bytes.size());
                blk.stored_raw = 0;
                blob_.insert(blob_.end(), comp.bytes.begin(), comp.bytes.end());
            } else {
                // Incompressible (or codec unavailable) -> store verbatim so we
                // never expand data. Mirrors "only shrink what is shrinkable".
                blk.comp_len = raw_len;
                blk.stored_raw = 1;
                blob_.insert(blob_.end(), src, src + raw_len);
            }
            blocks_.push_back(blk);
            off += raw_len;
        }
        built_ = blocks_.empty() ? (size == 0) : true;
        // build() already holds mtx_; reset the diagnostic counters inline
        // (calling reset_counters() here would re-lock the non-recursive mutex).
        blocks_touched_ = 0;
        blocks_decompressed_ = 0;
        decompressed_bytes_ = 0;
        return built_;
    }

    // Read [offset, offset+bytes) into `out` (must have room for `bytes`).
    // Only overlapping blocks are inflated. Returns false on a range error or a
    // block that fails its integrity check (corruption).
    bool read(std::uint64_t offset, std::uint64_t bytes, std::uint8_t* out) const {
        if (bytes == 0) return true;
        if (offset > raw_bytes_) return false;
        const std::uint64_t end = std::min<std::uint64_t>(offset + bytes, raw_bytes_);
        const std::uint64_t n = end - offset;
        if (n == 0) return true;

        std::lock_guard<std::mutex> lk(mtx_);
        if (blocks_.empty()) return false;
        const std::uint64_t bs = block_size_ ? block_size_ : 1;
        std::size_t first = static_cast<std::size_t>(offset / bs);
        std::size_t last = static_cast<std::size_t>((end - 1) / bs);
        if (last >= blocks_.size()) return false;

        std::vector<std::uint8_t> scratch;
        for (std::size_t i = first; i <= last; ++i) {
            const CompressedBlock& b = blocks_[i];
            const std::uint64_t b_end = b.raw_offset + b.raw_len;
            const std::uint64_t s = std::max<std::uint64_t>(offset, b.raw_offset);
            const std::uint64_t e = std::min<std::uint64_t>(end, b_end);
            if (s >= e) continue;

            const std::uint8_t* block_raw = nullptr;
            if (b.stored_raw) {
                block_raw = blob_.data() + b.comp_offset;  // verbatim slice
                ++blocks_touched_;
            } else {
                const auto d = rawrxd::compression::decompress(
                    blob_.data() + b.comp_offset, b.comp_len, b.raw_len);
                if (d.status != rawrxd::compression::Status::Ok ||
                    d.bytes.size() != b.raw_len) {
                    return false;  // corruption / truncation / ceiling
                }
                scratch.assign(d.bytes.begin(), d.bytes.end());
                block_raw = scratch.data();
                ++blocks_decompressed_;
                decompressed_bytes_ += b.raw_len;
                ++blocks_touched_;
            }
            std::memcpy(out + (s - offset), block_raw + (s - b.raw_offset),
                        static_cast<std::size_t>(e - s));
        }
        return true;
    }

    bool read(std::uint64_t offset, std::uint64_t bytes,
              std::vector<std::uint8_t>& out) const {
        out.resize(static_cast<std::size_t>(bytes));
        if (bytes == 0) return true;
        return read(offset, bytes, out.data());
    }

    // Inflate the whole tensor (reference / verification use).
    bool read_all(std::vector<std::uint8_t>& out) const {
        return read(0, raw_bytes_, out);
    }

    // ---- stats -------------------------------------------------------------
    std::uint64_t raw_bytes() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return raw_bytes_;
    }
    // Bytes actually held in memory: compressed blob + block index.
    std::uint64_t resident_bytes() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return static_cast<std::uint64_t>(blob_.size()) +
               static_cast<std::uint64_t>(blocks_.size() * sizeof(CompressedBlock));
    }
    std::size_t block_count() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return blocks_.size();
    }
    bool valid() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return built_;
    }
    // Diagnostics proving partial decompression: how many blocks were inflated /
    // touched by reads since the last reset, and how many uncompressed bytes were
    // materialised. A single-row read leaves these far below block_count().
    std::uint64_t blocks_touched() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return blocks_touched_;
    }
    std::uint64_t blocks_decompressed() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return blocks_decompressed_;
    }
    std::uint64_t decompressed_bytes() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return decompressed_bytes_;
    }
    void reset_counters() const {
        std::lock_guard<std::mutex> lk(mtx_);
        blocks_touched_ = 0;
        blocks_decompressed_ = 0;
        decompressed_bytes_ = 0;
    }
    // Fraction of the uncompressed size that stays resident (lower is better).
    double resident_ratio() const {
        const std::uint64_t raw = raw_bytes();
        if (raw == 0) return 0.0;
        return static_cast<double>(resident_bytes()) / static_cast<double>(raw);
    }

    // Test hook: flip one byte of one stored block so corruption handling can be
    // exercised. Clearly named; never called by production code.
    bool corrupt_block_byte_for_testing(std::size_t idx) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (idx >= blocks_.size()) return false;
        CompressedBlock& b = blocks_[idx];
        if (b.comp_len == 0) return false;
        blob_[b.comp_offset + (b.comp_len >> 1)] ^= 0xFFu;
        return true;
    }

private:
    std::vector<CompressedBlock> blocks_;
    std::vector<std::uint8_t> blob_;
    std::uint64_t raw_bytes_ = 0;
    std::size_t block_size_ = 64u * 1024u;
    bool built_ = false;
    mutable std::mutex mtx_;
    mutable std::uint64_t blocks_touched_ = 0;
    mutable std::uint64_t blocks_decompressed_ = 0;
    mutable std::uint64_t decompressed_bytes_ = 0;
};

// ---------------------------------------------------------------------------
// CompressedWeightStore -- a whole model's worth of compressed tensors.
// ---------------------------------------------------------------------------
class CompressedWeightStore {
public:
    // Compress and retain `size` bytes at `data` under `name`. The store keeps
    // only the compressed form; the caller may free its buffer immediately.
    bool add(const std::string& name, const std::uint8_t* data, std::size_t size,
             std::size_t block_size = 64u * 1024u) {
        auto t = std::make_unique<CompressedTensor>();
        if (!t->build(data, size, block_size)) return false;
        std::lock_guard<std::mutex> lk(mtx_);
        emplace_locked(name, std::move(t));
        return true;
    }

    CompressedTensor* get(const std::string& name) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = tensors_.find(name);
        return it == tensors_.end() ? nullptr : it->second.get();
    }
    const CompressedTensor* get(const std::string& name) const {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = tensors_.find(name);
        return it == tensors_.end() ? nullptr : it->second.get();
    }

    std::size_t tensor_count() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return tensors_.size();
    }

    std::uint64_t total_raw_bytes() const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::uint64_t sum = 0;
        for (const auto& kv : tensors_) sum += kv.second->raw_bytes();
        return sum;
    }

    std::uint64_t total_resident_bytes() const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::uint64_t sum = 0;
        for (const auto& kv : tensors_) sum += kv.second->resident_bytes();
        return sum;
    }

    double overall_resident_ratio() const {
        const std::uint64_t raw = total_raw_bytes();
        if (raw == 0) return 0.0;
        return static_cast<double>(total_resident_bytes()) / static_cast<double>(raw);
    }

private:
    void emplace_locked(const std::string& name,
                        std::unique_ptr<CompressedTensor> t) {
        tensors_[name] = std::move(t);  // node-based: stable, no element moves
    }
    std::unordered_map<std::string, std::unique_ptr<CompressedTensor>> tensors_;
    mutable std::mutex mtx_;
};

} // namespace rawrxd::residency

#endif // RAWRXD_COMPRESSED_WEIGHT_RESIDENCY_HPP