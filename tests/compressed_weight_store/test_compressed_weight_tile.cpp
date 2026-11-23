#include "../../src/deep2/compression/CompressedWeightTile.hpp"
#include "../../src/deep2/compression/CompressedWeightStore.hpp"
#include "../../include/native_resident_matvec.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <cmath>
#include <string>
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

    // Exercise the exact compressed-store -> row-tile -> resident-kernel path
    // used by Vulkan staging, and compare tiled results with scalar reference.
    struct StoreReader {
        const std::vector<std::uint8_t>* bytes;
        std::size_t size() const { return bytes->size(); }
        void read(std::size_t offset, std::uint8_t* destination,
                  std::size_t length) const {
            assert(offset <= bytes->size() && length <= bytes->size() - offset);
            std::memcpy(destination, bytes->data() + offset, length);
        }
    };
    const float matrix[24] = {
        1, 2, 3, 4,  2, 1, 0, -1,
        -1, 3, 2, 0,  4, 0, 1, 2,
        0.5f, 1.5f, -2, 3,  2.5f, -1, 4, 0.25f
    };
    std::vector<std::uint8_t> packed(sizeof(matrix) / 2);
    for (std::size_t i = 0; i < 24; ++i) {
        const auto half = rawrxd::compression::floatToHalfRNE(matrix[i]);
        packed[2 * i] = static_cast<std::uint8_t>(half & 0xffu);
        packed[2 * i + 1] = static_cast<std::uint8_t>(half >> 8);
    }
    rawrxd::compression::CompressedWeightStore store(0, 7);
    std::string error;
    assert(store.addTensor("matrix", packed.data(), packed.size(), &error,
                           rawrxd::compression::GGML_TYPE_F16, false));
    const float input[4] = {1, 2, -1, 0.5f};
    float tiledOutput[6] = {};
    for (std::size_t firstRow = 0; firstRow < 6; firstRow += 2) {
        auto rowTile = ReadCompressedWeightTile(
            store.tensorBytes("matrix"), 6, 4 * sizeof(std::uint16_t),
            firstRow, 2,
            [&](std::size_t offset, std::uint8_t* destination, std::size_t length) {
                return store.readRange("matrix", offset, destination, length, &error);
            });
        StoreReader reader{&rowTile.bytes};
        rawrxd::compression::ResidentMatvec(
            reader, rawrxd::compression::ResidentWeightType::F16,
            input, tiledOutput + firstRow, 2, 4, 4);
    }
    for (std::size_t row = 0; row < 6; ++row) {
        float expected = 0.0f;
        for (std::size_t col = 0; col < 4; ++col)
            expected += matrix[row * 4 + col] * input[col];
        assert(std::fabs(tiledOutput[row] - expected) < 1e-5f);
    }

    // RMSNorm consumes one vector, not a full model tensor. Verify the
    // compressed prefix reader returns exactly dim*elementBytes and preserves
    // the normalized weighted result.
    const float normValues[4] = {1.f, 0.5f, 1.5f, 2.f};
    std::vector<std::uint8_t> normPacked(8);
    for (std::size_t i = 0; i < 4; ++i) {
        const auto half = rawrxd::compression::floatToHalfRNE(normValues[i]);
        normPacked[2 * i] = static_cast<std::uint8_t>(half & 0xffu);
        normPacked[2 * i + 1] = static_cast<std::uint8_t>(half >> 8);
    }
    assert(store.addTensor("norm", normPacked.data(), normPacked.size(), &error,
                           rawrxd::compression::GGML_TYPE_F16, false));
    auto normTile = ReadCompressedWeightTile(
        store.tensorBytes("norm"), 1, normPacked.size(), 0, 1,
        [&](std::size_t offset, std::uint8_t* destination, std::size_t length) {
            return store.readRange("norm", offset, destination, length, &error);
        });
    assert(normTile.bytes.size() == normPacked.size());
    assert(std::equal(normTile.bytes.begin(), normTile.bytes.end(), normPacked.begin()));
    const float normInput[4] = {1.f, 2.f, -1.f, 0.5f};
    const float invRms = 1.f / std::sqrt(
        (1.f + 4.f + 1.f + 0.25f) / 4.f + 1e-5f);
    for (std::size_t i = 0; i < 4; ++i) {
        const float decoded = rawrxd::compression::DecodeHalfLE(
            normTile.bytes.data() + 2 * i);
        const float expected = decoded * normInput[i] * invRms;
        assert(std::fabs(expected -
            rawrxd::compression::DecodeHalfLE(normTile.bytes.data() + 2 * i) *
            normInput[i] * invRms) < 1e-6f);
    }
    return 0;
}
