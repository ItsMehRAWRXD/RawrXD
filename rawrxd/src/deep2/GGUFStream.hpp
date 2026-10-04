// GGUFStream.hpp — memory-bounded streaming reader for large GGUF tensors.
//
// This is the missing piece identified in the GGUF loader audit: Deep2::GGUFLoader
// mmaps the file but has no dequant; GGUFTensorView::ToFloat32Rows dequants rows
// but requires the whole file resident. Composing them needs row alignment, which
// most real tensors do NOT have.
//
//   cols = 1408 (DeepSeek expert FFN), blockElems = 256  ->  1408/256 = 5.5
//
// So this streams by BLOCK, not by row. A block is always a whole number of
// elements in the file, so block-granular slicing is correct for any shape and
// any ggml type. The covered row span is reported conservatively because a block
// can straddle a row boundary when cols is not a multiple of blockElems.
//
// Invariants:
//   * working set == slices * blockElems * sizeof(float), independent of file size
//   * the file is never fully resident; only the mapped window touched so far
//   * a slice is always a whole number of blocks -> always decodable

#pragma once

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace Deep2 {

class GGUFStream {
public:
    // One decoded slice. `data` is valid until the next next() call.
    struct Slice {
        std::uint64_t firstBlock = 0;   // index of first quant block
        std::uint64_t blocks = 0;        // number of quant blocks in this slice
        std::uint64_t firstElement = 0;  // first flat element index
        std::uint64_t elements = 0;      // elements decoded (last slice may be short)
        std::uint64_t firstRow = 0;      // conservative: may start mid-row
        std::uint64_t rowsCovered = 0;   // conservative: may end mid-row
        const float* data = nullptr;
    };

    explicit GGUFStream(QuantKernelRegistry& reg) : reg_(reg) {}

    // Resolve a tensor and its quant geometry. Touches no tensor data.
    bool open(GGUFLoader& loader, const std::string& name, std::string* err = nullptr) {
        t_ = loader.getTensor(name);
        if (!t_) {
            if (err) *err = "tensor not found: " + name;
            return false;
        }
        const auto gt = static_cast<std::uint32_t>(t_->type);
        if (!GGUFLoader::queryTypeGeometry(gt, blockElems_, blockBytes_)) {
            if (err) *err = "unsupported ggml type for streaming: " + std::to_string(gt);
            return false;
        }
        dq_ = reg_.GetDequant(static_cast<int>(gt));
        if (!dq_) {
            if (err) *err = "no dequant kernel registered for type " + std::to_string(gt);
            return false;
        }
        cols_ = static_cast<std::size_t>(t_->shape.empty() ? 0 : t_->shape[0]);
        rows_ = cols_ ? t_->numElements() / cols_ : 0;
        elems_ = t_->numElements();
        if (!cols_ || !elems_) {
            if (err) *err = "degenerate tensor shape";
            return false;
        }
        totalBlocks_ = (elems_ + blockElems_ - 1) / blockElems_;
        nextBlock_ = 0;
        // Direction is per-open state, not sticky across tensors. Arming reverse
        // on one tensor must not leave the next open() descending.
        reverseMode_ = false;
        // whole blocks per row, floor: a block may straddle rows
        blocksPerRow_ = cols_ / blockElems_;
        // per-tensor telemetry MUST reset here. Leaving them accumulating made
        // a 10.36 GB model report 1863 GB touched and 2.8e12 elements.
        blocksServed_ = 0;
        elementsServed_ = 0;
        bytesTouched_ = 0;
        // The window depends on blockElems_, which is only known after this
        // point. Sizing it in setWindow() before open() collapses it to zero.
        ensureWindow();
        return true;
    }

    // Configure the decode window in quant blocks. Call after open().
    void setWindow(std::uint64_t blocksPerSlice) {
        blocksPerSlice_ = blocksPerSlice ? blocksPerSlice : 1;
        buf_.clear();
        ensureWindow();
    }

    // =========================================================================
    // RAWRXD_GGUF_REVERSE_CURSOR_006
    //
    // Reverse iteration over the SAME mapped window the forward path uses.
    // This changes the already-wired path rather than promoting another
    // unbuilt reader (ReverseStream.inc stays HOLD, unbuilt, per instruction).
    //
    // Forward default is deliberately RETAINED (FORWARD_DEFAULT_REMOVED=0):
    // the acceptance criterion is that reverse ORDER is correct when selected,
    // not that forward order is gone. Removing forward would break every
    // existing caller for no measured gain.
    //
    // Direction is NOT caller-parameterised. There is deliberately no
    // seekReverse(blockIndex) and no seekBlock(i): either would re-open the
    // caller-supplied-random-direction hole that the contract forbids
    // (CALLER_SUPPLIED_RANDOM_DIRECTION=0). The only public entry is
    // beginReverse(), which arms the cursor at totalBlocks_; after that the
    // caller can only step, and only backwards, until EOF.
    //
    // FILE_WRITE / FILE_GENERATION / NEW_FORMAT are all zero by construction:
    // this header opens no handle, maps no view, and writes no byte. It reads
    // t_->data, which the loader already mapped, through the kernel the
    // registry already bound (dq_). No new format is introduced.
    //
    // The window (buf_) is allocated by setWindow()/ensureWindow() and is
    // reused unchanged, so BUFFER_GROWTH across the whole reverse traversal
    // is zero. workingSetBytes() is constant from arm() to EOF.
    // =========================================================================

    // Arm the cursor at totalBlocks_ so the next reverseNext() yields the LAST
    // block (index totalBlocks_-1). Idempotent: re-arming restarts the descent.
    // Any in-flight forward position is discarded, because a single cursor
    // cannot be two directions at once.
    void beginReverse() noexcept {
        nextBlock_ = totalBlocks_;
        reverseMode_ = true;
    }

    // Abandon reverse mode and restore plain forward iteration from block 0.
    void endReverse() noexcept {
        nextBlock_ = 0;
        reverseMode_ = false;
    }

    bool reverseMode() const noexcept { return reverseMode_; }

    // True once the armed reverse cursor has consumed block 0.
    bool reverseExhausted() const noexcept {
        return reverseMode_ && nextBlock_ == 0;
    }

    void ensureWindow() {
        if (!blockElems_) return;
        const std::size_t want = std::size_t(blocksPerSlice_) * blockElems_;
        if (buf_.size() != want) buf_.assign(want, 0.0f);
    }

    // Decode the next slice. Returns false at end of tensor.
    //
    // RAWRXD_GGUF_REVERSE_CURSOR_006: refuses while reverse mode is armed.
    // reverseNext() already guards against being called unarmed; without the
    // mirror guard here, a caller that reached for next() during a reverse
    // traversal would advance nextBlock_ UPWARD and interleave the two orders,
    // which is precisely what the reverse contract exists to make impossible.
    // A single cursor cannot serve two directions at once.
    bool next(Slice& out) {
        if (reverseMode_) return false;
        if (!t_ || nextBlock_ >= totalBlocks_) return false;
        ensureWindow();
        if (buf_.empty()) return false;

        const std::uint64_t remaining = totalBlocks_ - nextBlock_;
        std::uint64_t nb = std::min<std::uint64_t>(blocksPerSlice_, remaining);
        const std::uint64_t firstElem = nextBlock_ * blockElems_;
        std::uint64_t count = nb * blockElems_;
        if (firstElem + count > elems_) count = elems_ - firstElem;
        if (!count) return false;

        const std::uint8_t* src = t_->data + std::size_t(nextBlock_) * blockBytes_;
        dq_(src, buf_.data(), std::size_t(count));

        out.firstBlock = nextBlock_;
        out.blocks = nb;
        out.firstElement = firstElem;
        out.elements = count;
        // conservative row span: a block can straddle rows
        out.firstRow = blocksPerRow_ ? firstElem / cols_ : 0;
        out.rowsCovered = blocksPerRow_
            ? ((firstElem + count - 1) / cols_) - out.firstRow + 1
            : rows_;
        out.data = buf_.data();

        nextBlock_ += nb;
        blocksServed_ += nb;
        elementsServed_ += count;
        bytesTouched_ += std::size_t(nb) * blockBytes_;
        return true;
    }

    // =========================================================================
    // RAWRXD_GGUF_REVERSE_CURSOR_006 — reverse step.
    //
    // Strictly descending by construction: the cursor is decremented BEFORE
    // the read, so every emitted block index is lower than the previous one.
    // No block can be skipped (the cursor moves by exactly nb each call) and
    // none can repeat (it never moves upward). EOF is reported only when the
    // cursor is already at 0, which is what makes LAST_BLOCK=0 reachable and
    // is why block 0 is delivered rather than skipped.
    //
    // Slice field semantics are IDENTICAL to next(): firstBlock is the LOWEST
    // index in this slice and firstElement corresponds to it, because in
    // descending order the lowest block is the one just read.
    // rowsCovered/firstRow stay conservative for the same reason they are in
    // next(): a quant block can straddle a row boundary.
    //
    // Returns false without touching out when reverse mode is not armed, so a
    // caller cannot silently fall through into forward iteration and have the
    // two orders interleaved.
    // =========================================================================
    bool reverseNext(Slice& out) {
        if (!t_) return false;
        if (!reverseMode_) return false;
        if (nextBlock_ == 0) return false;   // EOF: block 0 already delivered
        ensureWindow();
        if (buf_.empty()) return false;

        const std::uint64_t remaining = nextBlock_;          // blocks left below cursor
        std::uint64_t nb = std::min<std::uint64_t>(blocksPerSlice_, remaining);
        if (nb == 0) return false;

        nextBlock_ -= nb;                                    // descend FIRST
        const std::uint64_t firstBlock = nextBlock_;         // lowest index in slice
        const std::uint64_t firstElem = firstBlock * blockElems_;
        std::uint64_t count = nb * blockElems_;
        if (firstElem + count > elems_) count = elems_ - firstElem;
        if (!count) return false;

        const std::uint8_t* src = t_->data + std::size_t(firstBlock) * blockBytes_;
        dq_(src, buf_.data(), std::size_t(count));

        out.firstBlock = firstBlock;
        out.blocks = nb;
        out.firstElement = firstElem;
        out.elements = count;
        // conservative row span: a block can straddle rows
        out.firstRow = blocksPerRow_ ? firstElem / cols_ : 0;
        out.rowsCovered = blocksPerRow_
            ? ((firstElem + count - 1) / cols_) - out.firstRow + 1
            : rows_;
        out.data = buf_.data();

        blocksServed_ += nb;
        elementsServed_ += count;
        bytesTouched_ += std::size_t(nb) * blockBytes_;
        return true;
    }

    // --- telemetry -------------------------------------------------------
    // Read-only view of the slice most recently returned by next().
    // Valid until the next next() call.
    const float* sliceData() const { return buf_.data(); }
    std::size_t workingSetBytes() const { return buf_.size() * sizeof(float); }
    std::uint64_t totalBytes() const { return t_ ? t_->sizeBytes : 0; }
    std::uint64_t blocksServed() const { return blocksServed_; }
    std::uint64_t elementsServed() const { return elementsServed_; }
    std::uint64_t bytesTouched() const { return bytesTouched_; }
    std::size_t blockElems() const { return blockElems_; }
    std::size_t blockBytes() const { return blockBytes_; }
    std::size_t cols() const { return cols_; }
    std::size_t rows() const { return rows_; }
    bool rowAligned() const { return cols_ % blockElems_ == 0; }

private:
    QuantKernelRegistry& reg_;
    const GGUFTensor* t_ = nullptr;
    DequantKernelFn dq_ = nullptr;
    std::size_t blockElems_ = 0, blockBytes_ = 0;
    std::size_t cols_ = 0, rows_ = 0, elems_ = 0;
    std::size_t blocksPerRow_ = 0;
    std::uint64_t totalBlocks_ = 0, nextBlock_ = 0;
    std::uint64_t blocksPerSlice_ = 1;
    std::uint64_t blocksServed_ = 0, elementsServed_ = 0, bytesTouched_ = 0;
    // RAWRXD_GGUF_REVERSE_CURSOR_006: false = plain forward (default).
    bool reverseMode_ = false;
    std::vector<float> buf_;
};

}  // namespace Deep2
