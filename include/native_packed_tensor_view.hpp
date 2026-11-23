#pragma once
// Zero-copy GGUF packed block access: never expands a whole tensor.
// Caller owns mapped GGUF bytes and must keep mapping alive during visits.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
namespace RawrXD::Compression {
struct PackedTensorView {
    const uint8_t* bytes = nullptr;
    size_t encoded_bytes = 0;
    uint64_t elements = 0;
    uint32_t elements_per_block = 0;
    uint32_t bytes_per_block = 0;

    uint64_t block_count() const {
        if (!elements_per_block || !bytes_per_block || !bytes)
            throw std::invalid_argument("invalid packed tensor descriptor");
        if (elements % elements_per_block)
            throw std::invalid_argument("partial quantization block");
        const uint64_t count = elements / elements_per_block;
        if (count > std::numeric_limits<size_t>::max() / bytes_per_block ||
            count * bytes_per_block > encoded_bytes)
            throw std::out_of_range("packed tensor exceeds mapped data");
        return count;
    }
    const uint8_t* block(uint64_t index) const {
        const uint64_t count = block_count();
        if (index >= count) throw std::out_of_range("packed block index");
        return bytes + static_cast<size_t>(index * bytes_per_block);
    }
    template <typename Kernel>
    void visit(uint64_t first, uint64_t count, Kernel&& kernel) const {
        const uint64_t total = block_count();
        if (first > total || count > total - first)
            throw std::out_of_range("packed block range");
        for (uint64_t i = 0; i < count; ++i)
            kernel(first + i, block(first + i), bytes_per_block);
    }
};
} // namespace RawrXD::Compression
