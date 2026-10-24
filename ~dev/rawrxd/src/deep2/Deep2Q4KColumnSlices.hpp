// Deep2Q4KColumnSlices.hpp -- immutable quantized dual-GPU column splits.
// No Qt, Vulkan, external libraries, or run-time dependencies beyond C++20.
// Snapshots keep weight buffers alive across concurrent cache rebuilds.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace Deep2 {
struct Q4KColumnSlices {
    uint32_t cols0 = 0, cols1 = 0;
    std::vector<uint8_t> w0, w1;
};

class Q4KColumnSliceCache {
public:
    using Snapshot = std::shared_ptr<const Q4KColumnSlices>;

    Snapshot get(const void* source, size_t availableBytes, size_t rows,
                 size_t cols, uint32_t requestedBlocks0) {
        constexpr size_t blockColumns = 256, blockBytes = 144;
        if (!source || !rows || !cols || cols % blockColumns != 0 ||
            cols > std::numeric_limits<uint32_t>::max()) return {};
        const size_t blocks = cols / blockColumns;
        if (blocks < 2 || requestedBlocks0 == 0 ||
            requestedBlocks0 >= blocks ||
            blocks > std::numeric_limits<size_t>::max() / blockBytes) return {};
        const size_t rowBytes = blocks * blockBytes;
        if (rows > std::numeric_limits<size_t>::max() / rowBytes ||
            rows * rowBytes > availableBytes) return {};
        const size_t bytes0 = (size_t)requestedBlocks0 * blockBytes;
        const size_t bytes1 = rowBytes - bytes0;

        std::lock_guard<std::mutex> guard(mu_);
        auto it = cache_.find(source);
        if (it != cache_.end() && it->second.rows == rows &&
            it->second.cols == cols && it->second.bytes == availableBytes &&
            it->second.snapshot) {
            const uint32_t old = it->second.blocks0;
            // For large tensors one 256-column quantum of timing jitter is
            // cheaper to tolerate than repacking the entire matrix.
            const bool near = blocks >= 64 &&
                (old == requestedBlocks0 + 1 || old + 1 == requestedBlocks0);
            if (old == requestedBlocks0 || near) return it->second.snapshot;
        }

        auto fresh = std::make_shared<Q4KColumnSlices>();
        fresh->cols0 = requestedBlocks0 * static_cast<uint32_t>(blockColumns);
        fresh->cols1 = static_cast<uint32_t>(cols) - fresh->cols0;
        fresh->w0.resize(rows * bytes0);
        fresh->w1.resize(rows * bytes1);
        const auto* raw = static_cast<const uint8_t*>(source);
        for (size_t row = 0; row < rows; ++row) {
            std::memcpy(fresh->w0.data() + row * bytes0,
                        raw + row * rowBytes, bytes0);
            std::memcpy(fresh->w1.data() + row * bytes1,
                        raw + row * rowBytes + bytes0, bytes1);
        }
        cache_[source] = Entry{rows, cols, availableBytes, requestedBlocks0, fresh};
        ++rebuilds_;
        return fresh;
    }

    void clear() noexcept {
        std::lock_guard<std::mutex> guard(mu_);
        cache_.clear(); // Active callers retain their own immutable snapshots.
    }
    size_t rebuilds() const noexcept {
        std::lock_guard<std::mutex> guard(mu_);
        return rebuilds_;
    }

private:
    struct Entry {
        size_t rows, cols, bytes;
        uint32_t blocks0;
        Snapshot snapshot;
    };
    mutable std::mutex mu_;
    std::unordered_map<const void*, Entry> cache_;
    size_t rebuilds_ = 0;
};
} // namespace Deep2
