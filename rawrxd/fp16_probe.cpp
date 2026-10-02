// fp16_probe.cpp
// RAWRXD_Q6K_LIVE_BLOCK_TRACE_001 -- second stage.
//
// The element-level trace reported DIRECT and TOFLOAT32 agreeing on every field
// for element 0, including d_fp32. That agreement is NOT yet exoneration, because
// the harness transcribed ggml_loader's own FP16ToFP32 rather than converting
// independently. A defect in the conversion is invisible to a check that uses it.
//
// The block's d for element 0 is 0x00C6: exponent field 0, so it is an fp16
// SUBNORMAL. The loader renormalizes subnormals by shifting left and then emits
// an fp32 exponent of (127 - 15 - e). That is one too small for the normalization
// the shift already performed. The error is exactly a factor of two, which is
// precisely the "exact 2x" the previous test reported and could not explain.
//
// This probe settles it by exhaustion: every one of the 65536 fp16 bit patterns,
// converted by the loader's routine and by an independent ldexp formulation.
#include "gguf_loader.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

// The routine under test is CALLED, not transcribed.
//
// The first version of this probe carried a verbatim copy of
// ggml_loader's FP16ToFP32. When the loader was repaired the probe kept
// reporting the bug, because it was measuring its own copy. A probe that
// re-implements the thing it audits will always agree with history and never
// with reality.
using rawrxd::FP16ToFP32;

// Independent formulation, written as arithmetic rather than bit assembly:
//   normal    : 2^(exp-15) * (1 + mant/1024) = (mant + 1024) * 2^(exp-25)
//   subnormal : 2^-14 * mant/1024             = mant * 2^-24
static float IndependentFP16(uint16_t h) {
    const int sign = (h & 0x8000) ? -1 : 1;
    const int exp  = (h >> 10) & 0x1F;
    const int mant = h & 0x3FF;
    if (exp == 31) return mant ? NAN : (float)sign * INFINITY;
    if (exp == 0)  return (float)sign * std::ldexp((float)mant, -24);
    return (float)sign * std::ldexp((float)(mant + 1024), exp - 25);
}

int main() {
    int normalBad = 0, subnormalBad = 0, subnormalTotal = 0, normalTotal = 0;
    double worstNormal = 0.0, worstSubnormal = 0.0;

    std::printf("%-10s %-18s %-18s %-14s %s\n",
                "H", "LOADER", "INDEPENDENT", "RATIO", "CLASS");
    for (uint32_t h = 0; h <= 0xFFFFu; ++h) {
        const uint16_t bits = static_cast<uint16_t>(h);
        const float a = FP16ToFP32(bits);
        const float b = IndependentFP16(bits);
        if (std::isnan(b)) continue;
        const int exp = (bits >> 10) & 0x1F;
        const bool sub = (exp == 0) && ((bits & 0x3FF) != 0);
        if (exp != 31 && exp != 0) ++normalTotal;
        if (sub) ++subnormalTotal;
        double ratio = 0.0;
        if (b != 0.0f) {
            ratio = (double)a / (double)b;
            const double dr = std::fabs(ratio - 1.0);
            if (sub) {
                if (dr > worstSubnormal) worstSubnormal = dr;
                if (dr > 1e-6) ++subnormalBad;
            } else if (exp != 31) {
                if (dr > worstNormal) worstNormal = dr;
                if (dr > 1e-6) ++normalBad;
            }
        }
        if (bits == 0x00C6) {
            std::printf("0x%04X     %-18.9g %-18.9g %-14.9g %s\n",
                        (unsigned)bits, (double)a, (double)b, ratio,
                        sub ? "SUBNORMAL" : "NORMAL");
        }
    }

    std::printf("\nNORMALS_TESTED=%d\n", normalTotal);
    std::printf("NORMALS_WRONG=%d\n", normalBad);
    std::printf("NORMALS_WORST_REL=%.9g\n", worstNormal);
    std::printf("SUBNORMALS_TESTED=%d\n", subnormalTotal);
    std::printf("SUBNORMALS_WRONG=%d\n", subnormalBad);
    std::printf("SUBNORMALS_WORST_REL=%.9g\n", worstSubnormal);
    if (subnormalTotal) {
        std::printf("SUBNORMALS_WRONG_FRACTION=%.6g\n",
                    (double)subnormalBad / (double)subnormalTotal);
    }
    std::printf("SUB_NORMAL_BUG_PRESENT=%d\n", subnormalBad > 0 ? 1 : 0);
    std::printf("NORMAL_PATH_BUG_PRESENT=%d\n", normalBad > 0 ? 1 : 0);
    return 0;
}