#include "quant_kernels.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <cstdlib>
#include <vector>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "CHECK failed at %d: %s\n", __LINE__, #x); std::abort(); } } while (0)

int main() {
    using deep2::TensorType;
    using deep2::TensorView;
    using deep2::DequantizedTensor;

    // Standard GGML Q4_0: fp16 d=1, then 16 packed bytes with both nibbles=9.
    std::vector<std::uint8_t> q4(18, 0x99);
    q4[0] = 0x00; q4[1] = 0x3c;
    TensorView q4View;
    q4View.type = TensorType::Q4_0;
    q4View.data = q4.data();
    q4View.byteSize = q4.size();
    q4View.dims = {32};
    DequantizedTensor q4Out;
    CHECK(deep2::dequantizeTensor(q4View, q4Out));
    CHECK(q4Out.data.size() == 32);
    for (float value : q4Out.data) CHECK(std::fabs(value - 1.0f) < 1e-6f);

    // Standard GGML Q8_0: fp16 d=1 comes before 32 signed quantized bytes.
    std::vector<std::uint8_t> q8(34, 1);
    q8[0] = 0x00; q8[1] = 0x3c;
    TensorView q8View;
    q8View.type = TensorType::Q8_0;
    q8View.data = q8.data();
    q8View.byteSize = q8.size();
    q8View.dims = {32};
    DequantizedTensor q8Out;
    CHECK(deep2::dequantizeTensor(q8View, q8Out));
    CHECK(q8Out.data.size() == 32);
    for (float value : q8Out.data) CHECK(std::fabs(value - 1.0f) < 1e-6f);

    // Q4_1 affine block: d=1, m=2, q=1 => 3.
    {
        std::vector<std::uint8_t> bytes(20, 0x11);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        bytes[2] = 0x00; bytes[3] = 0x40;
        TensorView view{TensorType::Q4_1, bytes.data(), bytes.size(), {32}, true};
        DequantizedTensor out;
        CHECK(deep2::dequantizeTensor(view, out));
        for (float value : out.data) CHECK(std::fabs(value - 3.0f) < 1e-6f);
    }

    // Q5_0: qh=all ones, nibble=9 => 25-16=9.
    {
        std::vector<std::uint8_t> bytes(22, 0x99);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        for (std::size_t i = 2; i < 6; ++i) bytes[i] = 0xff;
        TensorView view{TensorType::Q5_0, bytes.data(), bytes.size(), {32}, true};
        DequantizedTensor out;
        CHECK(deep2::dequantizeTensor(view, out));
        for (float value : out.data) CHECK(std::fabs(value - 9.0f) < 1e-6f);
    }

    // Q5_1: d=1, m=2, q=1 => 3.
    {
        std::vector<std::uint8_t> bytes(24, 0x11);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        bytes[2] = 0x00; bytes[3] = 0x40;
        for (std::size_t i = 4; i < 8; ++i) bytes[i] = 0;
        TensorView view{TensorType::Q5_1, bytes.data(), bytes.size(), {32}, true};
        DequantizedTensor out;
        CHECK(deep2::dequantizeTensor(view, out));
        for (float value : out.data) CHECK(std::fabs(value - 3.0f) < 1e-6f);
    }

    // Q8_1: d=1, s=0, qs=1 => 1; standard block is 36 bytes.
    {
        std::vector<std::uint8_t> bytes(36, 1);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        bytes[2] = 0x00; bytes[3] = 0x00;
        TensorView view{TensorType::Q8_1, bytes.data(), bytes.size(), {32}, true};
        DequantizedTensor out;
        CHECK(deep2::dequantizeTensor(view, out));
        for (float value : out.data) CHECK(std::fabs(value - 1.0f) < 1e-6f);
    }

    // Smallest positive binary16 subnormal is 2^-24, not zero or a wrapped exponent.
    const std::uint8_t subnormal[] = {0x01, 0x00};
    TensorView f16View;
    f16View.type = TensorType::F16;
    f16View.data = subnormal;
    f16View.byteSize = sizeof(subnormal);
    f16View.dims = {1};
    DequantizedTensor f16Out;
    CHECK(deep2::dequantizeTensor(f16View, f16Out));
    CHECK(std::fabs(f16Out.data[0] - 5.960464477539063e-8f) < 1e-14f);

    // A truncated packed block must be rejected before any out-of-bounds read.
    q4View.byteSize = 17;
    CHECK(!deep2::dequantizeTensor(q4View, q4Out));

    TensorView overflowView;
    overflowView.type = TensorType::F32;
    overflowView.data = subnormal;
    overflowView.byteSize = sizeof(subnormal);
    overflowView.dims = {(std::numeric_limits<std::uint64_t>::max)(), 2};
    DequantizedTensor overflowOut;
    CHECK(!deep2::dequantizeTensor(overflowView, overflowOut));
    return 0;
}
