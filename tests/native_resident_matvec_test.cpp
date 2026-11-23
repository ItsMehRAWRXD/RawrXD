#include "native_resident_matvec.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <limits>
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
    const std::uint8_t one[2] = {0, 0x3c};
    assert(DecodeHalfLE(one) == 1.f);
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
    // Shape must match exactly, including rejection of trailing bytes.
    Resident trailing = f16;
    trailing.bytes.push_back(0);
    rejected = false;
    try { ResidentMatvec(trailing, ResidentWeightType::F16, x, y, 2, 2); }
    catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);
    // NaN inputs must not silently poison output or parity comparisons.
    float badInput[32] = {};
    badInput[0] = std::numeric_limits<float>::quiet_NaN();
    rejected = false;
    try { ResidentMatvec(f16, ResidentWeightType::F16, badInput, y, 2, 2); }
    catch (const std::domain_error&) { rejected = true; }
    assert(rejected);
    // Tile invariance: same matrix must produce the same results regardless
    // of the scratch limit, including limits smaller than one Q8 block.
    const auto verifyTiles = [&](const Resident& w, ResidentWeightType type,
                                 std::size_t width, float a, float b) {
        for (std::size_t limit : {std::size_t(1), std::size_t(2),
                                  std::size_t(3), std::size_t(34),
                                  std::size_t(65536)}) {
            float actual[2] = {};
            ResidentMatvec(w, type, x, actual, 2, width, limit);
            assert(actual[0] == a && actual[1] == b);
        }
    };
    verifyTiles(f16, ResidentWeightType::F16, 2, -3.f, 4.5f);
    verifyTiles(f32, ResidentWeightType::F32, 2, -3.f, 4.5f);
    verifyTiles(q8, ResidentWeightType::Q8_0, 32, 0.f, -1.f);
    // A half-precision NaN weight must be rejected, not interpreted as zero.
    Resident nanWeights = f16;
    nanWeights.bytes[1] = 0x7e;
    rejected = false;
    try { ResidentMatvec(nanWeights, ResidentWeightType::F16, x, y, 2, 2); }
    catch (const std::domain_error&) { rejected = true; }
    assert(rejected);
    q8.bytes[1] = 0x7c; // +infinity scale
    rejected = false;
    try { ResidentMatvec(q8, ResidentWeightType::Q8_0, x, y, 2, 32); }
    catch (const std::domain_error&) { rejected = true; }
    assert(rejected);
}
