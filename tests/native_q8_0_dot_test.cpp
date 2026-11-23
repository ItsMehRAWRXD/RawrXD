#include "../include/native_q8_0_dot.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <stdexcept>
using namespace RawrXD::Compression;
int main() {
    uint8_t packed[68] = {};
    float x[64];
    for (int i = 0; i < 64; ++i) x[i] = 1.0f;
    packed[0] = 0x00; packed[1] = 0x3c; // 1.0
    packed[34] = 0x00; packed[35] = 0x38; // 0.5
    for (int i = 0; i < 32; ++i) {
        packed[2+i] = 2;    // +2 * 1.0
        packed[36+i] = 0xfe; // -2 * 0.5
    }
    PackedTensorView view{packed, sizeof(packed), 64, 32, 34};
    assert(std::fabs(q8_0_dot(view, x, 64) - 32.0f) < 0.0001f);
    bool rejected = false;
    try { q8_0_dot(view, x, 63); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
