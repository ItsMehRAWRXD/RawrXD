#include "native_resident_matvec.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>
using namespace rawrxd::compression;
struct Resident {
    std::vector<std::uint8_t> bytes;
    std::size_t size() const { return bytes.size(); }
    void read(std::size_t off, std::uint8_t* dst, std::size_t count) const {
        if (off > bytes.size() || count > bytes.size() - off) throw std::out_of_range("read");
        std::memcpy(dst, bytes.data() + off, count);
    }
};
int main() {
    assert(DecodeHalfLE((const std::uint8_t*)"\\x00\\x3c") == 1.f);
    const std::uint8_t subnormal[2] = {1, 0};
    assert(std::fabs(DecodeHalfLE(subnormal) - std::ldexp(1.f,-24)) < 1e-12f);
    const std::uint8_t neg[2] = {0, 0xbc};
    assert(DecodeHalfLE(neg) == -1.f);
    const float x[32] = {1, 2, 3, 4};
    float y[2] = {};
    Resident f16{{0,0x3c, 0,0xc0, 0,0x38, 0,0x40}};
    ResidentMatvec(f16, ResidentWeightType::F16, x, y, 2, 2, 2);
    assert(y[0] == -3.f && y[1] == 4.5f);
    Resident f32;
    for (float f : {1.f, -2.f, 0.5f, 2.f}) {
        std::uint8_t b[4];
        std::memcpy(b, &f, 4);
        f32.bytes.insert(f32.bytes.end(), b, b + 4);
    }
    ResidentMatvec(f32, ResidentWeightType::F32, x, y, 2, 2, 4);
    assert(y[0] == -3.f && y[1] == 4.5f);
    Resident q8;
    q8.bytes.resize(68, 0);
    q8.bytes[1] = 0x3c; q8.bytes[35] = 0x3c;
    q8.bytes[2] = 2; q8.bytes[3] = 0xff;
    q8.bytes[36] = 3; q8.bytes[37] = 0xfe;
    ResidentMatvec(q8, ResidentWeightType::Q8_0, x, y, 2, 32, 1);
    assert(y[0] == 0.f && y[1] == -1.f);
    bool rejected = false;
    try { ResidentMatvec(q8, ResidentWeightType::Q8_0, x, y, 2, 31); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { ResidentMatvec(f16, ResidentWeightType::F16, x, y, 3, 2); }
    catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);
    q8.bytes[1] = 0x7c; // +infinity scale
    rejected = false;
    try { ResidentMatvec(q8, ResidentWeightType::Q8_0, x, y, 2, 32); }
    catch (const std::domain_error&) { rejected = true; }
    assert(rejected);
}
