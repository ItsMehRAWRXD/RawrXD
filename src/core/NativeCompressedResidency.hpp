// NativeCompressedResidency.hpp
// Bounded, synchronous, callback-driven compressed tensor residency primitive.
// C++17, dependency-free. Integration into Deep2/GPU dispatch is a separate step.
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace Compression {

enum class Status : uint8_t {
    Ok, Missing, Invalid, BudgetExceeded, DecodeFailed, KernelFailed
};

struct Slice {
    uint64_t tensorId = 0;
    size_t offset = 0; // Byte offset in *decoded* tensor
    size_t length = 0;
};

using DecodeSlice = bool (*)(const uint8_t* encoded, size_t encodedBytes,
                            size_t decodedBytes, size_t offset, size_t length,
                            uint8_t* output, void* context);
using ConsumeSlice = bool (*)(const uint8_t* bytes, size_t length, void* context);

struct Record {
    std::vector<uint8_t> encoded;
    size_t decodedBytes = 0;
    DecodeSlice decode = nullptr;
    void* decoderContext = nullptr;
};

// No persistent decoded copies. The callback receives a temporary buffer
// valid only until it returns; callbacks must not retain the pointer.
// The mutex serializes operations so replace/erase cannot invalidate sources.
class NativeCompressedResidency {
public:
    explicit NativeCompressedResidency(size_t scratchBudgetBytes)
        : budget_(scratchBudgetBytes) {}

    Status insert(uint64_t id, Record record) {
        if (!record.decode || !record.decodedBytes || record.encoded.empty())
            return Status::Invalid;
        std::lock_guard<std::mutex> lock(mutex_);
        records_[id] = std::move(record);
        return Status::Ok;
    }

    Status erase(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_.erase(id) ? Status::Ok : Status::Missing;
    }

    Status consume(const Slice& slice, ConsumeSlice kernel, void* context) {
        if (!kernel || !slice.length) return Status::Invalid;
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = records_.find(slice.tensorId);
        if (it == records_.end()) return Status::Missing;
        const Record& record = it->second;
        if (slice.offset > record.decodedBytes ||
            slice.length > record.decodedBytes - slice.offset)
            return Status::Invalid;
        if (slice.length > budget_) return Status::BudgetExceeded;
        // Exact-sized scratch is allocated only for the requested decoded range.
        // Decode implementations must validate format-specific block alignment.
        std::vector<uint8_t> scratch(slice.length);
        if (!record.decode(record.encoded.data(), record.encoded.size(),
                           record.decodedBytes, slice.offset, slice.length,
                           scratch.data(), record.decoderContext))
            return Status::DecodeFailed;
        const bool ok = kernel(scratch.data(), scratch.size(), context);
        std::fill(scratch.begin(), scratch.end(), uint8_t{0});
        return ok ? Status::Ok : Status::KernelFailed;
    }

    size_t encodedResidentBytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& pair : records_) {
            if (pair.second.encoded.size() > std::numeric_limits<size_t>::max() - total)
                return std::numeric_limits<size_t>::max();
            total += pair.second.encoded.size();
        }
        return total;
    }

    size_t scratchBudgetBytes() const { return budget_; }

private:
    const size_t budget_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, Record> records_;
};

// Reference passthrough decoder: useful for exact-byte tests and already
// quantized blocks; not a GGUF quantization decoder.
inline bool copyDecodedSlice(const uint8_t* input, size_t encodedBytes,
                             size_t decodedBytes, size_t offset, size_t length,
                             uint8_t* output, void*) {
    if (!input || !output || encodedBytes != decodedBytes ||
        offset > decodedBytes || length > decodedBytes - offset)
        return false;
    std::memcpy(output, input + offset, length);
    return true;
}

} // namespace Compression
} // namespace RawrXD
