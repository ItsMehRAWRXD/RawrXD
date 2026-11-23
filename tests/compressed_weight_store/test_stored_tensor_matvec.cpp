#include "../../src/deep2/compression/StoredTensorMatvec.hpp"
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd::compression;
int main() {
    // Two F16 rows, repeated 4096 times to ensure the encoded representation
    // actually saves RAM. The decoder cache is disabled: every matvec reads
    // from compressed resident blocks, with only bounded staging scratch.
    CompressedWeightStore store(0, 64);
    constexpr std::size_t cols = 32, rows = 256;
    std::vector<std::uint8_t> weights(rows * cols * 2, 0);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t col = 0; col < cols; ++col) {
            const std::uint16_t half = col == 0 ? 0x3c00 : 0;
            const std::size_t offset = (row * cols + col) * 2;
            weights[offset] = std::uint8_t(half);
            weights[offset + 1] = std::uint8_t(half >> 8);
        }
    }
    std::string error;
    if (!store.addTensor("f16", weights.data(), weights.size(), &error,
                         GGML_TYPE_F16, true)) {
        std::cerr << "F16 compression failed: " << error << "\\n";
        return EXIT_FAILURE;
    }
    const auto before = store.stats();
    assert(before.compressed_bytes < before.raw_bytes);
    std::vector<float> input(cols, 0.f), output(rows, 0.f);
    input[0] = 3.f;
    StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                       input.data(), output.data(), rows, cols, 3);
    for (float v : output) assert(v == 3.f);
    const auto after = store.stats();
    assert(after.cache_misses > 0);
    assert(after.cached_decoded_bytes == 0);
    assert(after.compressed_bytes < after.raw_bytes);
    // A second pass must remain numerically identical with no decoded cache.
    std::fill(output.begin(), output.end(), 0.f);
    StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                       input.data(), output.data(), rows, cols, 1024);
    for (float v : output) assert(v == 3.f);
    bool rejected = false;
    try {
        StoredTensorMatvec(store, "missing", ResidentWeightType::F16,
                           input.data(), output.data(), rows, cols);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    // A correctly sized tensor with the wrong GGML encoding must fail closed.
    rejected = false;
    try {
        StoredTensorMatvec(store, "f16", ResidentWeightType::F32,
                           input.data(), output.data(), rows, cols);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);

    // Q8_0 block layout: little-endian FP16 scale, then 32 signed bytes.
    // Zero-filled blocks compress well; a nonzero first value proves decoding.
    std::vector<std::uint8_t> q8(rows * 34, 0);
    for (std::size_t row = 0; row < rows; ++row) {
        q8[row * 34 + 1] = 0x3c; // FP16 scale 1.0
        q8[row * 34 + 2] = 2;    // first signed Q8 weight
    }
    if (!store.addTensor("q8", q8.data(), q8.size(), &error, 8u, true)) {
        std::cerr << "Q8_0 compression failed: " << error << "\\n";
        return EXIT_FAILURE;
    }
    std::fill(output.begin(), output.end(), 0.f);
    StoredTensorMatvec(store, "q8", ResidentWeightType::Q8_0,
                       input.data(), output.data(), rows, cols, 1);
    for (float v : output) assert(v == 6.f);
    // Differential parity: the compressed store and direct GGUF byte reader
    // must produce identical outputs for both supported resident formats.
    struct DirectReader {
        const std::vector<std::uint8_t>& bytes;
        std::size_t size() const { return bytes.size(); }
        void read(std::size_t offset, std::uint8_t* out, std::size_t count) const {
            if (offset > bytes.size() || count > bytes.size() - offset)
                throw std::out_of_range("direct tensor bounds");
            std::memcpy(out, bytes.data() + offset, count);
        }
    };
    for (std::size_t scratch : {std::size_t(1), std::size_t(34), std::size_t(65536)}) {
        std::vector<float> expected(rows);
        ResidentMatvec(DirectReader{weights}, ResidentWeightType::F16,
                       input.data(), expected.data(), rows, cols, scratch);
        StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                           input.data(), output.data(), rows, cols, scratch);
        assert(output == expected);
        ResidentMatvec(DirectReader{q8}, ResidentWeightType::Q8_0,
                       input.data(), expected.data(), rows, cols, scratch);
        StoredTensorMatvec(store, "q8", ResidentWeightType::Q8_0,
                           input.data(), output.data(), rows, cols, scratch);
        assert(output == expected);
    }
    const auto finalStats = store.stats();
    assert(finalStats.compressed_bytes < finalStats.raw_bytes);
    assert(finalStats.cached_decoded_bytes == 0);
    return 0;
}
