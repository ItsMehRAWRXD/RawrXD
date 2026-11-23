#pragma once
// Adapter from the actual compressed in-memory block store to the bounded
// matrix/vector kernel. Only requested block spans are decoded by readRange.
#include "CompressedWeightStore.hpp"
#include "../../../include/native_resident_matvec.hpp"
#include <cstddef>
#include <cstdint>
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
    }
    std::size_t size() const noexcept { return bytes_; }
    void read(std::size_t offset, std::uint8_t* dst, std::size_t count) const {
        if (offset > bytes_ || count > bytes_ - offset || (count && !dst))
            throw std::out_of_range("resident tensor read outside bounds");
        std::string error;
        if (!store_.readRange(name_, offset, dst, count, &error))
            throw std::runtime_error("compressed resident read failed: " + error);
    }
private:
    CompressedWeightStore& store_;
    std::string name_;
    std::size_t bytes_ = 0;
};

inline void StoredTensorMatvec(CompressedWeightStore& store,
                               const std::string& tensorName,
                               ResidentWeightType type,
                               const float* x, float* y,
                               std::size_t rows, std::size_t cols,
                               std::size_t stagingBytes = 64 * 1024) {
    // Never reinterpret compressed GGML bytes using a different kernel type.
    // F32 and F16 are GGML scalar IDs 0 and 1; Q8_0 is GGML ID 8.
    const std::uint32_t expected = type == ResidentWeightType::F32 ? GGML_TYPE_F32 :
                                   type == ResidentWeightType::F16 ? GGML_TYPE_F16 : 8u;
    if (store.tensorType(tensorName) != expected)
        throw std::invalid_argument("resident tensor GGML type does not match kernel");
    StoredTensorReader reader(store, tensorName);
    ResidentMatvec(reader, type, x, y, rows, cols, stagingBytes);
}
} // namespace rawrxd::compression
