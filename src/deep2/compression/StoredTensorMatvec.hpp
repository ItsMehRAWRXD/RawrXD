#pragma once
// Adapter from the actual compressed in-memory block store to the bounded
// matrix/vector kernel. Only requested block spans are decoded by readRange.
#include "CompressedWeightStore.hpp"
#include "../../../include/native_resident_matvec.hpp"
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace rawrxd::compression {

inline std::uint32_t ResidentGGMLTypeForKernel(ResidentWeightType type) {
    switch (type) {
        case ResidentWeightType::F32: return GGML_TYPE_F32;
        case ResidentWeightType::F16: return GGML_TYPE_F16;
        case ResidentWeightType::Q4_0: return 2u;
        case ResidentWeightType::Q4_1: return 3u;
        case ResidentWeightType::Q5_0: return 6u;
        case ResidentWeightType::Q5_1: return 7u;
        case ResidentWeightType::Q8_0: return 8u;
    }
    throw std::invalid_argument("unsupported resident weight kernel type");
}
class StoredTensorReader {
public:
    StoredTensorReader(CompressedWeightStore& store, std::string name)
        : store_(store), name_(std::move(name)) {
        if (!store_.contains(name_))
            throw std::invalid_argument("resident tensor missing from compressed store");
        bytes_ = store_.tensorBytes(name_);
        block_bytes_ = store_.blockBytes();
    }
    std::size_t size() const noexcept { return bytes_; }
    void read(std::size_t offset, std::uint8_t* dst, std::size_t count) const {
        if (offset > bytes_ || count > bytes_ - offset || (count && !dst))
            throw std::out_of_range("resident tensor read outside bounds");
        // Retain only the current decoded block across tiny kernel reads.
        // This avoids decoding the same block for every FP16/Q8 scalar when
        // the shared decoded cache budget is zero.
        while (count) {
            const std::size_t block = offset / block_bytes_;
            const std::size_t within = offset % block_bytes_;
            if (!lease_ || lease_index_ != block) {
                std::string error;
                auto next = store_.acquireBlock(name_, block, &error);
                if (!next)
                    throw std::runtime_error("compressed resident read failed: " + error);
                lease_ = std::move(next);
                lease_index_ = block;
            }
            if (within >= lease_->size())
                throw std::runtime_error("compressed resident block geometry invalid");
            const std::size_t take = std::min(count, lease_->size() - within);
            std::memcpy(dst, lease_->data() + within, take);
            offset += take;
            dst += take;
            count -= take;
        }
    }
private:
    CompressedWeightStore& store_;
    std::string name_;
    std::size_t bytes_ = 0;
    std::size_t block_bytes_ = 0;
    mutable std::size_t lease_index_ = (std::numeric_limits<std::size_t>::max)();
    mutable CompressedWeightStore::BlockLease lease_;
    // A reader is request-local and must not be shared concurrently.
};

inline void StoredTensorMatvec(CompressedWeightStore& store,
                               const std::string& tensorName,
                               ResidentWeightType type,
                               const float* x, float* y,
                               std::size_t rows, std::size_t cols,
                               std::size_t stagingBytes = 64 * 1024) {
    // Never reinterpret compressed GGML bytes using a different kernel type.
    // F32 and F16 are GGML scalar IDs 0 and 1; Q8_0 is GGML ID 8.
    const std::uint32_t expected = ResidentGGMLTypeForKernel(type);
    if (store.tensorType(tensorName) != expected)
        throw std::invalid_argument("resident tensor GGML type does not match kernel");
    StoredTensorReader reader(store, tensorName);
    ResidentMatvec(reader, type, x, y, rows, cols, stagingBytes);
}

inline void StoredTensorReadRow(CompressedWeightStore& store,
                                const std::string& tensorName,
                                ResidentWeightType type,
                                std::size_t row,
                                float* output,
                                std::size_t cols) {
    if (!output || cols == 0)
        throw std::invalid_argument("invalid resident row arguments");
    const std::uint32_t expected = ResidentGGMLTypeForKernel(type);
    if (store.tensorType(tensorName) != expected)
        throw std::invalid_argument("resident row GGML type does not match decoder");
    const std::size_t rowBytes = ResidentRowBytes(type, cols);
    const std::size_t totalBytes = store.tensorBytes(tensorName);
    if (totalBytes % rowBytes != 0 || row >= totalBytes / rowBytes)
        throw std::out_of_range("resident row outside tensor geometry");
    if (row > (std::numeric_limits<std::size_t>::max)() / rowBytes)
        throw std::overflow_error("resident row offset overflow");

    std::vector<std::uint8_t> packed(rowBytes);
    std::string error;
    if (!store.readRange(tensorName, row * rowBytes,
                         packed.data(), packed.size(), &error))
        throw std::runtime_error("compressed resident row read failed: " + error);

    if (type == ResidentWeightType::F32) {
        for (std::size_t i = 0; i < cols; ++i) {
            std::memcpy(&output[i], packed.data() + i * sizeof(float), sizeof(float));
            if (!std::isfinite(output[i]))
                throw std::domain_error("nonfinite F32 resident row value");
        }
        return;
    }
    if (type == ResidentWeightType::F16) {
        for (std::size_t i = 0; i < cols; ++i) {
            output[i] = DecodeHalfLE(packed.data() + i * 2);
            if (!std::isfinite(output[i]))
                throw std::domain_error("nonfinite F16 resident row value");
        }
        return;
    }

    const std::size_t blocks = cols / 32;
    const std::size_t blockBytes =
        type == ResidentWeightType::Q4_0 ? 18 :
        type == ResidentWeightType::Q4_1 ? 20 :
        type == ResidentWeightType::Q5_0 ? 22 :
        type == ResidentWeightType::Q5_1 ? 24 : 34;
    for (std::size_t block = 0; block < blocks; ++block) {
        const std::uint8_t* p = packed.data() + block * blockBytes;
        const float scale = DecodeHalfLE(p);
        const bool affine = type == ResidentWeightType::Q4_1 ||
                            type == ResidentWeightType::Q5_1;
        const float minimum = affine ? DecodeHalfLE(p + 2) : 0.0f;
        if (!std::isfinite(scale) || !std::isfinite(minimum))
            throw std::domain_error("nonfinite resident quantization scale/minimum");
        float* dst = output + block * 32;
        if (type == ResidentWeightType::Q8_0) {
            for (std::size_t i = 0; i < 32; ++i) {
                const int q = p[2 + i] < 128 ? int(p[2 + i]) : int(p[2 + i]) - 256;
                dst[i] = scale * static_cast<float>(q);
            }
        } else if (type == ResidentWeightType::Q4_0 ||
                   type == ResidentWeightType::Q4_1) {
            const std::size_t qOffset = type == ResidentWeightType::Q4_0 ? 2 : 4;
            for (std::size_t i = 0; i < 16; ++i) {
                const unsigned q = p[qOffset + i];
                const int q0 = int(q & 0x0fu);
                const int q1 = int(q >> 4);
                dst[i] = type == ResidentWeightType::Q4_0
                    ? scale * static_cast<float>(q0 - 8)
                    : scale * static_cast<float>(q0) + minimum;
                dst[16 + i] = type == ResidentWeightType::Q4_0
                    ? scale * static_cast<float>(q1 - 8)
                    : scale * static_cast<float>(q1) + minimum;
            }
        } else {
            const bool q5Affine = type == ResidentWeightType::Q5_1;
            const std::size_t highOffset = q5Affine ? 4 : 2;
            const std::size_t qOffset = q5Affine ? 8 : 6;
            for (std::size_t i = 0; i < 16; ++i) {
                const unsigned packedQ = p[qOffset + i];
                const unsigned loHigh = (p[highOffset + i / 8] >> (i % 8)) & 1u;
                const std::size_t upper = i + 16;
                const unsigned hiHigh = (p[highOffset + upper / 8] >> (upper % 8)) & 1u;
                const int q0 = int(packedQ & 0x0fu) | (int(loHigh) << 4);
                const int q1 = int(packedQ >> 4) | (int(hiHigh) << 4);
                dst[i] = q5Affine
                    ? scale * static_cast<float>(q0) + minimum
                    : scale * static_cast<float>(q0 - 16);
                dst[16 + i] = q5Affine
                    ? scale * static_cast<float>(q1) + minimum
                    : scale * static_cast<float>(q1 - 16);
            }
        }
        for (std::size_t i = 0; i < 32; ++i)
            if (!std::isfinite(dst[i]))
                throw std::domain_error("nonfinite decoded resident row value");
    }
}

} // namespace rawrxd::compression
