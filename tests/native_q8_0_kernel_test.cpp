#include "native_q8_0_kernel.hpp"
#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " #x " line " << __LINE__ << '\n'; return 1; } } while (0)
int main() {
    using namespace rawrxd::compression;
    CHECK(q8_0_half_to_float(0x3c00) == 1.0f);
    CHECK(q8_0_half_to_float(0xbc00) == -1.0f);
    CHECK(q8_0_half_to_float(0x0001) == std::ldexp(1.0f, -24));
    CHECK(q8_0_half_to_float(0x7bff) == 65504.0f);
    CHECK(std::isinf(q8_0_half_to_float(0x7c00)));
    CHECK(std::isnan(q8_0_half_to_float(0x7e00)));
    std::array<std::uint8_t,34> block{};
    block[0] = 0x00; block[1] = 0x38; // FP16 0.5
    std::array<float,32> input{}, output{};
    double expected = 0;
    for (int i=0; i<32; ++i) {
        const int q = (i % 9) - 4;
        block[2+i] = static_cast<std::uint8_t>(static_cast<std::int8_t>(q));
        input[i] = float(i+1) / 4;
        expected += 0.5 * q * input[i];
    }
    q8_0_decode_block(block.data(), output.data());
    for (int i=0; i<32; ++i)
        CHECK(output[i] == 0.5f * static_cast<std::int8_t>(block[2+i]));
    CHECK(std::abs(q8_0_dot_block(block.data(), input.data()) - expected) < 1e-10);
    block[0] = 0x00; block[1] = 0x7c; // FP16 +infinity: fail closed
    bool rejected = false;
    try { (void)q8_0_dot_block(block.data(), input.data()); }
    catch (const std::domain_error&) { rejected = true; }
    CHECK(rejected);
    return 0;
}
