#include "../../src/deep2/compression/StoredTensorMatvec.hpp"
#include <algorithm>
#include <cassert>
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
    assert(store.addTensor("f16", weights.data(), weights.size(), &error,
                           GGML_TYPE_F16, true));
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
    return 0;
}
