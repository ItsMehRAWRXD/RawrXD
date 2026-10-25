// Q5_0 packed layout reference and 15 boundary/value checks.
// No external libraries. Compile with cl /std:c++20 /EHsc /W4.
#include <array>
#include <bit>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
static float fp16(uint16_t h) {
    const uint32_t sign = (uint32_t(h & 0x8000u) << 16);
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t mant = h & 1023u;
    uint32_t bits;
    if (exp == 31) bits = sign | 0x7f800000u | (mant << 13);
    else if (exp) bits = sign | ((exp + 112u) << 23) | (mant << 13);
    else if (!mant) bits = sign;
    else {
        uint32_t m = mant, e = 113u;
        while ((m & 1024u) == 0) { m <<= 1; --e; }
        bits = sign | (e << 23) | ((m & 1023u) << 13);
    }
    return std::bit_cast<float>(bits);
}
static float decode(const std::array<uint8_t,22>& b, unsigned i) {
    if (i >= 32) throw std::out_of_range("Q5_0 index");
    const uint16_t dh = uint16_t(b[0]) | (uint16_t(b[1]) << 8);
    const uint32_t hi = uint32_t(b[2]) | (uint32_t(b[3]) << 8) |
                        (uint32_t(b[4]) << 16) | (uint32_t(b[5]) << 24);
    const uint8_t packed = b[6 + (i & 15)];
    const unsigned q = ((i < 16) ? (packed & 15u) : (packed >> 4u)) |
                       (((hi >> i) & 1u) << 4);
    return fp16(dh) * float(int(q) - 16);
}
int main() {
    std::array<uint8_t,22> b{};
    b[0] = 0; b[1] = 0x3c; // FP16 1.0
    assert(fp16(0x3c00) == 1.f);                     // 01
    assert(fp16(0xbc00) == -1.f);                    // 02
    assert(fp16(0x0000) == 0.f);                     // 03
    assert(fp16(0x4000) == 2.f);                     // 04
    assert(decode(b,0) == -16.f);                    // 05
    assert(decode(b,15) == -16.f);                   // 06
    assert(decode(b,16) == -16.f);                   // 07
    assert(decode(b,31) == -16.f);                   // 08
    b[6] = 0x9a;
    assert(decode(b,0) == -6.f);                     // 09
    assert(decode(b,16) == -7.f);                    // 10
    b[2] = 1;
    assert(decode(b,0) == 10.f);                     // 11
    assert(decode(b,16) == -7.f);                    // 12
    b[4] = 1;
    assert(decode(b,16) == 9.f);                     // 13
    bool invalid = false;
    try { (void)decode(b,32); } catch (const std::out_of_range&) { invalid = true; }
    assert(invalid);                                 // 14
    b[0] = 0; b[1] = 0x40;
    assert(decode(b,0) == 20.f);                    // 15
    return 0;
}
