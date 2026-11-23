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

    // BF16 and F64 ranges use their native byte widths without full expansion.
    std::vector<std::uint8_t> bf16Bytes(64 * 2);
    for (int i = 0; i < 64; ++i) putU16(bf16Bytes.data() + i * 2, 0x4000);
    float bf16Out[4] = {};
    assert(deep2::dequantizeTensorRange(deep2::TensorType::BF16, 64, 31, 4,
        bf16Bytes.data() + 31 * 2, 4 * 2, bf16Out));
    for (float value : bf16Out) assert(value == 2.0f);

    std::vector<std::uint8_t> f64Bytes(16 * sizeof(double));
    for (int i = 0; i < 16; ++i) {
        const double value = 3.25 + i;
        std::memcpy(f64Bytes.data() + i * sizeof(double), &value, sizeof(value));
    }
    float f64Out[3] = {};
    assert(deep2::dequantizeTensorRange(deep2::TensorType::F64, 16, 7, 3,
        f64Bytes.data() + 7 * sizeof(double), 3 * sizeof(double), f64Out));
    assert(f64Out[0] == 10.25f && f64Out[1] == 11.25f && f64Out[2] == 12.25f);

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

    // Canonical GGML K-quant blocks are 256 values. Cross a block boundary
    // and prove the range helper reads the two exact Q2_K blocks.
    std::vector<std::uint8_t> q2k(2 * 84, 0);
    float q2kOut[20];
    for (float& value : q2kOut) value = 9.0f;
    assert(deep2::dequantizeTensorRange(deep2::TensorType::Q2_K, 512, 250, 20,
        q2k.data(), q2k.size(), q2kOut));
    for (float value : q2kOut) assert(value == 0.0f);

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
