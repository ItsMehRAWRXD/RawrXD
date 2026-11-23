#pragma once
// Adapter from the actual compressed in-memory block store to the bounded
// matrix/vector kernel. Only requested block spans are decoded by readRange.
#include "CompressedWeightStore.hpp"
#include "../../../include/native_resident_matvec.hpp"
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace rawrxd::compression {
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
    const std::uint32_t expected =
        type == ResidentWeightType::F32 ? GGML_TYPE_F32 :
        type == ResidentWeightType::F16 ? GGML_TYPE_F16 :
        type == ResidentWeightType::Q4_0 ? 2u : 8u;
    if (store.tensorType(tensorName) != expected)
        throw std::invalid_argument("resident tensor GGML type does not match kernel");
    StoredTensorReader reader(store, tensorName);
    ResidentMatvec(reader, type, x, y, rows, cols, stagingBytes);
}
} // namespace rawrxd::compression
