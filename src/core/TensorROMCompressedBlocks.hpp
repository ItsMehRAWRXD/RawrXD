#pragma once
// TensorROM adapter for the bounded decoded-block cache.
// GGUF quantized bytes remain encoded in TensorROM and are fetched on demand.
// The caller supplies the exact GGUF-type decoder (or identity for kernels
// that natively consume quantized blocks). No implicit F32 expansion occurs.
#include "../TensorROM.hpp"
#include "../../include/native_compressed_residency.hpp"
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace deep2 {

class TensorROMCompressedBlocks {
public:
    explicit TensorROMCompressedBlocks(const TensorROM& rom, size_t decodedCacheBudget)
        : rom_(rom), cache_(decodedCacheBudget) {}

    // byteOffset/encodedBytes refer to GGUF's *encoded* tensor payload.
    // decodedBytes is the exact expected output of decode().
    // Stable tensorId must uniquely identify a tensor in this ROM instance.
    template <typename Decoder>
    std::shared_ptr<const std::vector<uint8_t>> acquire(
        const TensorEntry& entry, uint64_t tensorId, uint64_t blockId,
        uint64_t byteOffset, uint64_t encodedBytes, uint64_t decodedBytes,
        Decoder&& decoder) {
        const uint64_t storage = TensorROM::tensorStorageBytes(entry);
        if (!encodedBytes || !decodedBytes || byteOffset > storage ||
            encodedBytes > storage - byteOffset ||
            encodedBytes > std::numeric_limits<size_t>::max() ||
            decodedBytes > std::numeric_limits<size_t>::max())
            throw std::invalid_argument("invalid GGUF tensor block range");
        using namespace RawrXD::Compression;
        // Descriptor offset is tensor-relative. Key is stable across calls.
        return cache_.acquire(
            BlockKey{tensorId, blockId},
            BlockDescriptor{byteOffset, encodedBytes, decodedBytes},
            [&](uint64_t offset, size_t length, std::vector<uint8_t>& packed) {
                packed.resize(length);
                return rom_.readTensorRange(entry, offset, length, packed.data());
            },
            [&](const uint8_t* packed, size_t length, size_t expected,
                std::vector<uint8_t>& output) {
                return decoder(entry.type, packed, length, expected, output);
            });
    }

    // For quantization-aware kernels: no dequantization, exact GGUF bytes.
    std::shared_ptr<const std::vector<uint8_t>> acquireQuantized(
        const TensorEntry& entry, uint64_t tensorId, uint64_t blockId,
        uint64_t byteOffset, uint64_t encodedBytes) {
        return acquire(entry, tensorId, blockId, byteOffset, encodedBytes,
            encodedBytes,
            [](TensorType, const uint8_t* bytes, size_t length, size_t expected,
               std::vector<uint8_t>& output) {
                if (length != expected) return false;
                output.assign(bytes, bytes + length);
                return true;
            });
    }

    RawrXD::Compression::BlockResidency::Stats stats() const {
        return cache_.stats();
    }
    void clear() { cache_.clear(); }

private:
    const TensorROM& rom_;
    RawrXD::Compression::BlockResidency cache_;
};

} // namespace deep2
