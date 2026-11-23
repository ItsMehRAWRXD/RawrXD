#include "../include/native_q4_1_dot.hpp"
#include <cassert>
#include <cmath>
#include <stdexcept>
using namespace RawrXD::Compression;
int main() {
    uint8_t packed[20] = {0x00, 0x3c, 0x00, 0x38}; // d=1, m=0.5
    float x[32];
    for (int i=0; i<32; ++i) x[i] = 1.0f;
    for (int i=0; i<16; ++i) packed[4+i] = 0x21; // low 1, high 2
    PackedTensorView v{packed, sizeof(packed), 32, 32, 20};
    assert(std::fabs(q4_1_dot(v,x,32) - 64.0f) < 0.0001f);
    bool rejected = false;
    try { q4_1_dot(v,x,31); } catch (const std::invalid_argument&) { rejected=true; }
    assert(rejected);
}
