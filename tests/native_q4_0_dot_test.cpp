#include "../include/native_q4_0_dot.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <stdexcept>
using namespace RawrXD::Compression;
int main() {
    uint8_t packed[18] = {0x00, 0x3c}; // FP16 1.0
    float x[32];
    for (int i = 0; i < 32; ++i) x[i] = 1.0f;
    for (int j = 0; j < 16; ++j) packed[2+j] = 0x98; // low=8 -> 0; high=9 -> 1
    PackedTensorView view{packed, sizeof(packed), 32, 32, 18};
    assert(std::fabs(q4_0_dot(view, x, 32) - 16.0f) < 0.0001f);
    assert(ggml_half_to_float(0x3c00) == 1.0f);
    assert(ggml_half_to_float(0x0001) > 0.0f);
    assert(std::isinf(ggml_half_to_float(0x7c00)));
    bool rejected = false;
    try { q4_0_dot(view, x, 31); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
