#pragma once
// Adapter for TensorROM: cache a GGUF tensor's original encoded bytes in
// bounded blocks, preserving the GGUF type. No implicit lossy conversion.
#include "CompressedResidencyCache.hpp"
#include "../TensorROM.hpp"
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace RawrXD {
class TensorROMCompressedBlocks {
public:
    explicit TensorROMCompressedBlocks(deep2::TensorROM& rom,
                                       CompressedResidencyCache& cache)
        : rom_(rom), cache_(cache) {}

    // Caller supplies the exact format-specific decoder. The returned lease
    // must remain alive until CPU use / GPU staging copy has completed.
    // encodedOffset and encodedSize are measured in GGUF storage bytes;
    // never split a quantization block across calls.
    CompressedResidencyCache::Lease acquire(
        const deep2::TensorEntry& tensor, std::uint64_t encodedOffset,
        std::size_t encodedSize, std::size_t decodedSize,
        CompressedResidencyCache::Decoder decoder) {
        if (!decoder || !encodedSize || !decodedSize)
            throw std::invalid_argument("invalid tensor block request");
        const auto total = deep2::TensorROM::tensorStorageBytes(tensor);
        if (encodedOffset > total || encodedSize > total - encodedOffset)
            throw std::out_of_range("encoded block exceeds tensor storage");
        if (tensor.shardIndex > std::numeric_limits<std::uint32_t>::max())
            throw std::overflow_error("shard identifier overflow");
        const auto key = CompressedResidencyCache::Key{
            tensor.offset, encodedOffset, static_cast<std::uint64_t>(tensor.shardIndex)};
        return cache_.acquireOrLoad(
            key, decodedSize,
            [&]() {
                std::vector<std::uint8_t> bytes(encodedSize);
                if (!rom_.readTensorRange(tensor, encodedOffset, encodedSize, bytes.data()))
                    throw std::runtime_error("GGUF tensor block read failed");
                return bytes;
            },
            std::move(decoder));
    }
private:
    deep2::TensorROM& rom_;
    CompressedResidencyCache& cache_;
};
} // namespace RawrXD
