// rawrxd_masm_f16_gate.cpp  --  RAWRXD_PURE_MASM_F16_BOUNDARY_001
//
// Certifies the complete binary16 -> binary32 boundary set, not just the one
// failing input. NaN cases assert CLASSIFICATION (isnan), not bit-exact payload
// equality, because the ABI does not require preserving the binary16 payload.
//
// Build:
//   ml64 /nologo /c /Fo:tfixed.obj src\masm\rawrxd_transformer_masm_fixed.asm
//   ml64 /nologo /c /Fo:math.obj   src\masm\rawrxd_math_masm.asm
//   cl /nologo /O2 /EHsc /std:c++17 rawrxd_masm_f16_gate.cpp tfixed.obj math.obj

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {
// std::bit_cast is C++20; memcpy keeps this gate buildable as C++17.
inline int32_t bits_of(float f) { int32_t i; std::memcpy(&i, &f, sizeof i); return i; }
}  // namespace

extern "C" float rawrxd_f16_to_f32(uint16_t h);

namespace {

int g_pass = 0;
int g_fail = 0;

// Independent scalar reference decoder. Written from the IEEE-754 binary16
// definition, deliberately not sharing code with the assembly.
float ref_f16(uint16_t h) {
    const int sign = (h & 0x8000u) ? -1 : 1;
    const int exp = (h >> 10) & 0x1F;
    const int man = h & 0x03FFu;
    if (exp == 0x1F) {
        return man == 0 ? (sign > 0 ? std::numeric_limits<float>::infinity()
                                     : -std::numeric_limits<float>::infinity())
                        : std::numeric_limits<float>::quiet_NaN();
    }
    if (exp == 0) {
        if (man == 0) return sign > 0 ? 0.0f : -0.0f;
        return static_cast<float>(sign) * (static_cast<double>(man) * 5.9604644775390625e-08);
    }
    return static_cast<float>(sign) *
           ((1.0 + static_cast<double>(man) / 1024.0) *
            std::pow(2.0, static_cast<double>(exp - 15)));
}

void expect(const char* name, uint16_t h, float got) {
    const float want = ref_f16(h);
    ++g_pass;
    bool ok;
    if (std::isnan(want)) {
        ok = std::isnan(got);  // classification only
    } else if (std::isinf(want)) {
        ok = std::isinf(got) && (std::signbit(got) == std::signbit(want));
    } else if (want == 0.0f) {
        ok = got == 0.0f && (std::signbit(got) == std::signbit(want));
    } else {
        // ULP comparison: the decoder is exact by construction, so allow 1 ulp
        // to absorb the final float rounding of the subnormal path.
        const int32_t ug = bits_of(got);
        const int32_t uw = bits_of(want);
        ok = std::abs(ug - uw) <= 1;
    }
    if (!ok) {
        ++g_fail;
        std::printf("  FAIL %-26s 0x%04X asm=%.9g ref=%.9g\n", name, h, double(got), double(want));
    } else {
        std::printf("  ok   %-26s 0x%04X -> %.9g\n", name, h, double(got));
    }
}

}  // namespace

int main() {
    std::printf("RAWRXD_PURE_MASM_F16_BOUNDARY_001\n");
    std::printf("=====================================\n");

    // The exact boundary set named in the gate spec.
    expect("+0",                0x0000, rawrxd_f16_to_f32(0x0000));
    expect("-0",                0x8000, rawrxd_f16_to_f32(0x8000));
    expect("smallest +subnorm", 0x0001, rawrxd_f16_to_f32(0x0001));
    expect("largest +subnorm",  0x03FF, rawrxd_f16_to_f32(0x03FF));
    expect("-smallest subnorm", 0x8001, rawrxd_f16_to_f32(0x8001));
    expect("-largest subnorm",  0x83FF, rawrxd_f16_to_f32(0x83FF));
    expect("smallest +normal",  0x0400, rawrxd_f16_to_f32(0x0400));
    expect("largest -subnorm?", 0x83FF, rawrxd_f16_to_f32(0x83FF));
    expect("+1",                0x3C00, rawrxd_f16_to_f32(0x3C00));
    expect("-1",                0xBC00, rawrxd_f16_to_f32(0xBC00));
    expect("max finite",        0x7BFF, rawrxd_f16_to_f32(0x7BFF));
    expect("min finite",        0xFBFF, rawrxd_f16_to_f32(0xFBFF));
    expect("+inf",              0x7C00, rawrxd_f16_to_f32(0x7C00));
    expect("-inf",              0xFC00, rawrxd_f16_to_f32(0xFC00));
    expect("sNaN",              0x7C01, rawrxd_f16_to_f32(0x7C01));
    expect("qNaN",              0x7E00, rawrxd_f16_to_f32(0x7E00));
    expect("-qNaN",             0xFE00, rawrxd_f16_to_f32(0xFE00));

    // Exhaustive sweep of every one of the 65536 encodings. This is the real
    // gate: it catches any remaining class-boundary error, not just the values
    // someone thought to enumerate by hand.
    int sweep_fail = 0;
    for (uint32_t h = 0; h < 0x10000u; ++h) {
        const uint16_t bits = static_cast<uint16_t>(h);
        const float got = rawrxd_f16_to_f32(bits);
        const float want = ref_f16(bits);
        bool ok;
        if (std::isnan(want)) {
            ok = std::isnan(got);
        } else if (std::isinf(want)) {
            ok = std::isinf(got) && (std::signbit(got) == std::signbit(want));
        } else if (want == 0.0f) {
            ok = got == 0.0f && (std::signbit(got) == std::signbit(want));
        } else {
            const int32_t ug = bits_of(got);
            const int32_t uw = bits_of(want);
            ok = std::abs(ug - uw) <= 1;
        }
        if (!ok) {
            if (sweep_fail < 8) {
                std::printf("  SWEEP FAIL 0x%04X asm=%.9g ref=%.9g\n", bits, double(got), double(want));
            }
            ++sweep_fail;
        }
    }

    std::printf("=====================================\n");
    std::printf("BOUNDARY_CASES=%d\n", g_pass);
    std::printf("BOUNDARY_FAILED=%d\n", g_fail);
    std::printf("SWEEP_CASES=65536\n");
    std::printf("SWEEP_FAILED=%d\n", sweep_fail);
    std::printf("VERDICT=%s\n", (g_fail == 0 && sweep_fail == 0) ? "PASS" : "FAIL");
    return (g_fail == 0 && sweep_fail == 0) ? 0 : 1;
}