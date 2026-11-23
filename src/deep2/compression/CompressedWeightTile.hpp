#pragma once
// Bounded extraction of a contiguous output-row window from a compressed
// tensor. The reader is expected to decompress only the requested byte range.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rawrxd::compression {

struct CompressedWeightTile {
    std::size_t first_row = 0;
    std::size_t row_count = 0;
    std::size_t row_bytes = 0;
    std::vector<std::uint8_t> bytes;
};

template<class RangeReader>
CompressedWeightTile ReadCompressedWeightTile(
    std::size_t total_bytes,
    std::size_t total_rows,
    std::size_t row_bytes,
    std::size_t first_row,
    std::size_t row_count,
    RangeReader&& read_range) {
    if (row_bytes == 0 || row_count == 0)
        throw std::invalid_argument("compressed weight tile has zero geometry");
    if (first_row > total_rows || row_count > total_rows - first_row)
        throw std::out_of_range("compressed weight tile rows exceed tensor shape");
    if (total_rows > (std::numeric_limits<std::size_t>::max)() / row_bytes)
        throw std::overflow_error("compressed weight tensor extent overflow");

    const std::size_t expected_bytes = total_rows * row_bytes;
    if (expected_bytes > total_bytes)
        throw std::out_of_range("compressed weight tensor is shorter than its row geometry");
    if (first_row > (std::numeric_limits<std::size_t>::max)() / row_bytes ||
        row_count > (std::numeric_limits<std::size_t>::max)() / row_bytes)
        throw std::overflow_error("compressed weight tile range overflow");

    const std::size_t offset = first_row * row_bytes;
    const std::size_t length = row_count * row_bytes;
    if (offset > total_bytes || length > total_bytes - offset)
        throw std::out_of_range("compressed weight tile byte range exceeds tensor");

    CompressedWeightTile tile;
    tile.first_row = first_row;
    tile.row_count = row_count;
    tile.row_bytes = row_bytes;
    tile.bytes.resize(length);
    if (!read_range(offset, tile.bytes.data(), length))
        throw std::runtime_error("compressed weight tile range read failed");
    return tile;
}

} // namespace rawrxd::compression
