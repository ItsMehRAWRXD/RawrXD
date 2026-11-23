#pragma once
// Kernel-facing bounded staging: never expands an entire resident tensor.
// Callbacks consume ephemeral decoded bytes synchronously. For asynchronous
// Vulkan DMA, copy into an owned staging slot and retain it until fence signal.
#include "native_resident_compressed_tensor.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
class BoundedWeightStager {
public:
    explicit BoundedWeightStager(std::size_t budgetBytes)
        : budget_(budgetBytes) {
        if (!budget_) throw std::invalid_argument("zero staging budget");
    }
    std::size_t budget_bytes() const noexcept { return budget_; }

    template<class Consumer>
    void for_each_chunk(const ResidentCompressedTensor& tensor,
                        std::size_t offset, std::size_t bytes,
                        Consumer&& consumer) const {
        if (offset > tensor.size() || bytes > tensor.size() - offset)
            throw std::out_of_range("weight staging outside tensor");
        std::vector<std::uint8_t> staging(std::min(budget_, bytes));
        std::size_t completed = 0;
        while (completed < bytes) {
            const auto count = std::min(staging.size(), bytes - completed);
            tensor.read(offset + completed, staging.data(), count);
            consumer(offset + completed, staging.data(), count);
            completed += count;
        }
    }
private:
    std::size_t budget_;
};
} // namespace rawrxd::compression
