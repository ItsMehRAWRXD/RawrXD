#include "quant_kernels.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

using namespace deep2;

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; ++failures; } } while (0)

int main() {
    // F32: the callback must receive only the requested byte interval, not the full tensor.
    std::vector<float> f32 = {0, 1, 2, 3, 4, 5, 6, 7};
    int f32Reads = 0;
    TensorRangeReader f32Reader = [&](uint64_t offset, uint64_t count, uint8_t* out) {
        ++f32Reads;
        if (offset != 8 || count != 16) return false;
        std::memcpy(out, reinterpret_cast<const uint8_t*>(f32.data()) + offset,
                    static_cast<size_t>(count));
        return true;
    };
    std::vector<float> decoded;
    CHECK(dequantizeTensorRange(TensorType::F32, 8, f32Reader, 2, 4, decoded, 2));
    CHECK(decoded.size() == 4);
    CHECK(decoded == std::vector<float>({2, 3, 4, 5}));
    CHECK(f32Reads == 2); // bounded two-element chunks

    // Q8_0: request exactly the second 32-value quant block.
    std::vector<uint8_t> q8(68, 0);
    for (size_t block = 0; block < 2; ++block) {
        for (size_t i = 0; i < 32; ++i)
            q8[block * 34 + i] = static_cast<uint8_t>(static_cast<int8_t>(i + 1));
        q8[block * 34 + 32] = 0x00; // fp16 1.0 = 0x3c00
        q8[block * 34 + 33] = 0x3c;
    }
    bool q8Exact = false;
    TensorRangeReader q8Reader = [&](uint64_t offset, uint64_t count, uint8_t* out) {
        q8Exact = offset == 34 && count == 34;
        if (!q8Exact) return false;
        std::memcpy(out, q8.data() + offset, static_cast<size_t>(count));
        return true;
    };
    CHECK(dequantizeTensorRange(TensorType::Q8_0, 64, q8Reader, 32, 32, decoded));
    CHECK(q8Exact && decoded.size() == 32);
    CHECK(std::fabs(decoded.front() - 1.0f) < 1e-6f);
    CHECK(std::fabs(decoded.back() - 32.0f) < 1e-6f);

    // Quantized requests must begin on block boundaries.
    CHECK(!dequantizeTensorRange(TensorType::Q8_0, 64, q8Reader, 1, 16, decoded));
    // Range overflow and reader failure must fail closed.
    CHECK(!dequantizeTensorRange(TensorType::F32, 8, f32Reader, 7, 2, decoded));
    TensorRangeReader failing = [](uint64_t, uint64_t, uint8_t*) { return false; };
    CHECK(!dequantizeTensorRange(TensorType::F32, 8, failing, 0, 2, decoded));
    CHECK(decoded.empty());

    std::cout << "compressed_range_dequant failures=" << failures << "\n";
    return failures ? 1 : 0;
}
