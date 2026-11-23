#pragma once
// CPU reference path: matrix weights stay compressed; decode one row-sized
// range at a time through a bounded cache. No full decoded matrix allocation.
// This is not a Vulkan kernel integration.
#include "DecodedBlockCache.hpp"
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>
namespace rawrxd::weights {
inline std::vector<float> compressed_matvec_f32(
    const Tensor& weights, const std::vector<float>& input,
    size_t rows, size_t cols, size_t cache_budget_bytes) {
    if (cols != input.size() || cols == 0 || rows == 0 ||
        cols > std::numeric_limits<size_t>::max()/sizeof(float) ||
        rows > std::numeric_limits<size_t>::max()/(cols*sizeof(float)) ||
        weights.plain_size != uint64_t(rows)*cols*sizeof(float) ||
        weights.element_bytes != sizeof(float))
        throw std::invalid_argument("invalid compressed matrix dimensions");
    DecodedBlockCache cache(weights,cache_budget_bytes);
    std::vector<float> output(rows,0.0f);
    const size_t chunk_floats=std::max<size_t>(1,weights.block_size/sizeof(float));
    for (size_t row=0;row<rows;++row) {
        double acc=0.0;
        for (size_t col=0;col<cols;) {
            const size_t count=std::min(chunk_floats,cols-col);
            const uint64_t offset=(uint64_t(row)*cols+col)*sizeof(float);
            const auto bytes=cache.read(offset,count*sizeof(float));
            for (size_t i=0;i<count;++i) {
                float w;
                std::memcpy(&w,bytes.data()+i*sizeof(float),sizeof(float));
                acc+=double(w)*input[col+i];
            }
            col+=count;
        }
        output[row]=static_cast<float>(acc);
    }
    return output;
}
} // namespace rawrxd::weights
