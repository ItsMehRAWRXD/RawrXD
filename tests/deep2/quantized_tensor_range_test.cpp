#include "../../src/quant_kernels.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

static void putU16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

int main() {
    // F16: each element is independently addressable.
    std::vector<std::uint8_t> halfBytes(64 * 2);
    for (std::uint16_t i = 0; i < 64; ++i) {
        // A constant 2.0 value is exactly representable in binary16.
        putU16(halfBytes.data() + i * 2, static_cast<std::uint16_t>(0x4000));
    }
    float halfOut[9] = {};
    assert(deep2::dequantizeTensorRange(deep2::TensorType::F16, 64, 17, 9,
        halfBytes.data() + 17 * 2, 9 * 2, halfOut));
    for (int i = 0; i < 9; ++i) assert(std::fabs(halfOut[i] - 2.0f) < 0.0001f);

    // Q8_0: a request crossing a 32-value boundary reads and decodes only
    // the two intersecting blocks, not the remaining tensor blocks.
    std::vector<std::uint8_t> q8(2 * 34);
    for (int block = 0; block < 2; ++block) {
        putU16(q8.data() + block * 34, 0x3c00); // fp16 scale = 1
        for (int i = 0; i < 32; ++i)
            q8[block * 34 + 2 + i] = static_cast<std::uint8_t>(static_cast<std::int8_t>(i - 16));
    }
    float q8Out[40] = {};
    assert(deep2::dequantizeTensorRange(deep2::TensorType::Q8_0, 64, 10, 40,
        q8.data(), q8.size(), q8Out));
    for (int i = 0; i < 40; ++i) {
        const int within = (10 + i) % 32;
        assert(q8Out[i] == static_cast<float>(within - 16));
    }

    // Bounds and unsupported layouts fail closed without modifying output.
    float sentinel[2] = { 123.0f, 456.0f };
    assert(!deep2::dequantizeTensorRange(deep2::TensorType::Q8_0, 64, 63, 2,
        q8.data(), q8.size(), sentinel));
    assert(sentinel[0] == 123.0f && sentinel[1] == 456.0f);
    assert(!deep2::dequantizeTensorRange(deep2::TensorType::Q4_0, 64, 0, 1,
        q8.data(), q8.size(), sentinel));

    std::cout << "bounded GGUF tensor range dequantization PASS\\n";
    return 0;
}
