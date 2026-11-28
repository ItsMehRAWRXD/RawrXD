#pragma once
#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
struct CompressedGpuTile {
    std::size_t first_row=0;
    std::size_t row_count=0;
    std::size_t byte_offset=0;
    std::size_t byte_count=0;
};

// Plans bounded row-aligned slices for a Vulkan GEMV ABI that requires a
// contiguous weight pointer. At most max_staging_bytes are staged except when
// one complete packed row itself exceeds that budget.
inline std::vector<CompressedGpuTile> PlanCompressedGpuTiles(
    std::size_t total_rows,std::size_t requested_rows,
    std::size_t packed_row_bytes,std::size_t max_staging_bytes) {
    if(!total_rows||!requested_rows||requested_rows>total_rows||
       !packed_row_bytes||!max_staging_bytes)
        throw std::invalid_argument("invalid compressed GPU tile geometry");
    if(total_rows>std::numeric_limits<std::size_t>::max()/packed_row_bytes)
        throw std::overflow_error("compressed GPU tensor byte size overflow");
    const std::size_t max_rows=std::max<std::size_t>(1,max_staging_bytes/packed_row_bytes);
    std::vector<CompressedGpuTile> tiles;
    for(std::size_t first=0;first<requested_rows;) {
        const std::size_t count=std::min(max_rows,requested_rows-first);
        if(first>std::numeric_limits<std::size_t>::max()/packed_row_bytes||
           count>std::numeric_limits<std::size_t>::max()/packed_row_bytes)
            throw std::overflow_error("compressed GPU tile range overflow");
        tiles.push_back({first,count,first*packed_row_bytes,count*packed_row_bytes});
        first+=count;
    }
    return tiles;
}
} // namespace rawrxd::compression
