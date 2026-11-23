#include "../../src/deep2/compression/CompressedWeightTile.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <vector>

using rawrxd::compression::ReadCompressedWeightTile;

int main() {
    std::vector<std::uint8_t> source(10 * 16);
    for (std::size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<std::uint8_t>((i * 37u) & 0xffu);

    std::size_t calls = 0;
    auto tile = ReadCompressedWeightTile(
        source.size(), 10, 16, 4, 3,
        [&](std::size_t offset, std::uint8_t* destination, std::size_t length) {
            ++calls;
            assert(offset == 64 && length == 48);
            std::copy(source.begin() + offset, source.begin() + offset + length,
                      destination);
            return true;
        });
    assert(calls == 1);
    assert(tile.first_row == 4 && tile.row_count == 3 && tile.row_bytes == 16);
    assert(tile.bytes.size() == 48);
    assert(std::equal(tile.bytes.begin(), tile.bytes.end(), source.begin() + 64));

    bool rejected = false;
    try {
        (void)ReadCompressedWeightTile(source.size(), 10, 16, 9, 2,
            [](std::size_t, std::uint8_t*, std::size_t) { return true; });
    } catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);

    rejected = false;
    try {
        (void)ReadCompressedWeightTile(source.size(), 10, 16, 0, 1,
            [](std::size_t, std::uint8_t*, std::size_t) { return false; });
    } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);

    rejected = false;
    try {
        (void)ReadCompressedWeightTile(source.size(), 10, 0, 0, 1,
            [](std::size_t, std::uint8_t*, std::size_t) { return true; });
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    return 0;
}
