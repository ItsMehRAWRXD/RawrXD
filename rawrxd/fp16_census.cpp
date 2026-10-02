// fp16_census.cpp
// RAWRXD_Q6K_LIVE_BLOCK_TRACE_001 -- stage 3.
//
// Six transcriptions of fp16 -> fp32 exist in this tree. They are NOT the same
// code: some count shifts as e and subtract, one counts from exp = 1 and
// subtracts, one counts from e = -1 and subtracts. Reading them side by side is
// not enough to say which are wrong, because three of the six look plausible and
// two of the three use a subtraction.
//
// So all of them are measured, over every one of the 65536 fp16 bit patterns,
// against an independent arithmetic reference:
//
//   subnormal : 2^-14 * mant/1024 = mant * 2^-24
//   normal    : 2^(exp-15) * (1 + mant/1024) = (mant + 1024) * 2^(exp-25)
//
// A variant that is wrong by a CONSTANT factor of two is a different defect
// from one whose error grows with the number of shifts, and the first is easy to
// misread as "the other path is wrong by 2x".
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

static float Reference(uint16_t h) {
    const int sign = (h & 0x8000) ? -1 : 1;
    const int exp  = (h >> 10) & 0x1F;
    const int mant = h & 0x3FF;
    if (exp == 31) return mant ? NAN : (float)sign * INFINITY;
    if (exp == 0)  return (mant == 0) ? (float)sign * 0.0f
                                       : (float)sign * std::ldexp((float)mant, -24);
    return (float)sign * std::ldexp((float)(mant + 1024), exp - 25);
}

// V1: gguf_loader.cpp -- e = number of shifts, exponent 127 - 15 - e
static float V1_gguf_loader(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 0x1Fu, mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            uint32_t e = 0, m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1F) bits = sign | 0x7F800000u | (mant << 13);
    else bits = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    float o; std::memcpy(&o, &bits, 4); return o;
}

// V1-FIXED: the repaired form, 127 - 14 - e
static float V1fixed(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 0x1Fu, mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            uint32_t e = 0, m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((127 - 14 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1F) bits = sign | 0x7F800000u | (mant << 13);
    else bits = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    float o; std::memcpy(&o, &bits, 4); return o;
}

// V2: src/deep2/k_quant_gemv_avx512.h -- identical text to V1
static float V2_kquant_gemv(uint16_t h) { return V1_gguf_loader(h); }

// V3: src/core/kquant_dequantize_q4k.cpp -- REPAIRED: 127 - 15 + exp
static float V3_kquant_dequant(uint16_t h) {
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exp  = (h & 0x7C00) >> 10;
    uint32_t mant = (h & 0x03FF);
    if (exp == 0) {
        if (mant == 0) return *reinterpret_cast<float*>(&sign);
        exp = 1;
        while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
        mant &= 0x03FF;
        exp = 127 - 15 + exp;
    } else if (exp == 0x1F) {
        exp = 0xFF;
    } else {
        exp = exp - 15 + 127;
    }
    uint32_t r = sign | (exp << 23) | (mant << 13);
    return *reinterpret_cast<float*>(&r);
}

// V3-OLD: as committed before the repair -- 127 - 15 - exp
static float V3old_kquant_dequant(uint16_t h) {
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exp  = (h & 0x7C00) >> 10;
    uint32_t mant = (h & 0x03FF);
    if (exp == 0) {
        if (mant == 0) return *reinterpret_cast<float*>(&sign);
        exp = 1;
        while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
        mant &= 0x03FF;
        exp = 127 - 15 - exp;
    } else if (exp == 0x1F) {
        exp = 0xFF;
    } else {
        exp = exp - 15 + 127;
    }
    uint32_t r = sign | (exp << 23) | (mant << 13);
    return *reinterpret_cast<float*>(&r);
}

// V4: src/core/runtime_symbol_bridge.cpp -- counter seeded to -1, do/while
static float V4_runtime_symbol_bridge(uint16_t h) {
    const uint32_t sign = (h & 0x8000u) ? 1u : 0u;
    const uint32_t exp = (h >> 10U) & 0x1FU;
    const uint32_t frac = h & 0x3FFU;
    uint32_t outExp = 0, outFrac = 0;
    if (exp == 0) {
        if (frac == 0) { outExp = 0; outFrac = 0; }
        else {
            int e = -1;
            uint32_t f = frac;
            do { ++e; f <<= 1U; } while ((f & 0x400U) == 0U);
            f &= 0x3FFU;
            outExp = (uint32_t)(127 - 15 - e);
            outFrac = f << 13U;
        }
    } else if (exp == 0x1FU) { outExp = 0xFFU; outFrac = frac << 13U; }
    else { outExp = exp + (127U - 15U); outFrac = frac << 13U; }
    const uint32_t bits = (sign << 31U) | (outExp << 23U) | outFrac;
    float o; std::memcpy(&o, &bits, 4); return o;
}

// V5: src/core/dml_asm_impl.cpp and dml_asm_fallback.cpp -- shift the mantissa
// to normalize, then RESET exp to 0 and fall through to the normal rebias.
// Found by widening the search beyond the literal expression `127 - 15 - e`:
// these two files never write that string, so a text search for the known-bad
// expression would have missed them entirely.
static float V5_dml_asm(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16u;
    uint32_t exp = (h & 0x7C00u) >> 10u;
    uint32_t mantissa = h & 0x03FFu;
    if (exp == 0u) {
        if (mantissa == 0u) { float r; std::memcpy(&r, &sign, 4); return r; }
        while ((mantissa & 0x0400u) == 0u) { mantissa <<= 1u; exp -= 1u; }
        mantissa &= 0x03FFu;
        exp = 0u;
    }
    if (exp == 0x1Fu) {
        const uint32_t b = sign | 0x7F800000u | (mantissa << 13u);
        float r; std::memcpy(&r, &b, 4); return r;
    }
    exp = exp + (127u - 15u);
    const uint32_t b = sign | (exp << 23u) | (mantissa << 13u);
    float r; std::memcpy(&r, &b, 4); return r;
}

// V6: src/core/aperture_q4_0_reference.cpp -- pure arithmetic
static float V6_aperture_reference(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exponent = (h >> 10) & 0x1F;
    const uint32_t mantissa = h & 0x3FF;
    if (exponent == 0) {
        if (mantissa == 0) return sign ? -0.0f : 0.0f;
        const float v = (float)mantissa / 1024.0f;
        return sign ? -v * 0.00006103515625f : v * 0.00006103515625f;
    } else if (exponent == 31) {
        return mantissa == 0 ? (sign ? -INFINITY : INFINITY) : NAN;
    }
    const uint32_t fs = sign << 31;
    const uint32_t fe = (exponent + 112) << 23;
    const uint32_t fm = mantissa << 13;
    const uint32_t bits = fs | fe | fm;
    float r; std::memcpy(&r, &bits, 4); return r;
}

// V7: src/core/aperture_q4_0_avx512_intrinsics.cpp and aperture_q8_0_*
static float V7_aperture_avx512(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exponent = (h >> 10) & 0x1F;
    const uint32_t mantissa = h & 0x3FF;
    float scale;
    if (exponent == 0) {
        scale = (sign ? -1.0f : 1.0f) * (mantissa / 1024.0f) * (1.0f / 16384.0f);
    } else if (exponent == 31) {
        scale = sign ? -INFINITY : INFINITY;
    } else {
        scale = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / 1024.0f) * (float)(1 << (exponent - 15));
    }
    return scale;
}

// V8: src/core/gguf_dml_bridge.cpp -- seeds exp = 1, decrements, then ADDS
static float V8_gguf_dml_bridge(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t man = h & 0x3FF;
    float f32v;
    if (exp == 0) {
        if (man == 0) { float r = sign ? -0.0f : 0.0f; return r; }
        return (float)std::ldexp((float)man, -24) * (sign ? -1.0f : 1.0f);
    }
    if (exp == 31) {
        if (man == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    {
        uint32_t s2 = sign;
        uint32_t e2 = exp;
        uint32_t m2 = man;
        if (e2 == 0) {
            e2 = 1;
            while (!(m2 & 0x400)) { m2 <<= 1; e2--; }
            m2 &= 0x3FF;
            const uint32_t bits = (s2 << 31) | ((e2 + 127 - 15) << 23) | (m2 << 13);
            std::memcpy(&f32v, &bits, 4);
            return f32v;
        }
        const uint32_t bits = (s2 << 31) | ((e2 + 127 - 15) << 23) | (m2 << 13);
        std::memcpy(&f32v, &bits, 4);
        return f32v;
    }
}

// V5-FIXED: dml_asm_impl.cpp after preserving the shift count
static float V5fixed_dml_asm(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16u;
    uint32_t exp = (h & 0x7C00u) >> 10u;
    uint32_t mantissa = h & 0x03FFu;
    if (exp == 0u) {
        if (mantissa == 0u) { float r; std::memcpy(&r, &sign, 4); return r; }
        uint32_t shifts = 0;
        while ((mantissa & 0x0400u) == 0u) { mantissa <<= 1u; ++shifts; }
        mantissa &= 0x03FFu;
        const uint32_t b = sign | ((113u - shifts) << 23u) | (mantissa << 13u);
        float r; std::memcpy(&r, &b, 4); return r;
    }
    if (exp == 0x1Fu) {
        const uint32_t b = sign | 0x7F800000u | (mantissa << 13u);
        float r; std::memcpy(&r, &b, 4); return r;
    }
    exp = exp + (127u - 15u);
    const uint32_t b = sign | (exp << 23u) | (mantissa << 13u);
    float r; std::memcpy(&r, &b, 4); return r;
}

// V7-FIXED: aperture q4_0/q8_0 avx512 intrinsics after replacing the integer
// shift (1 << (exponent - 15)) with ldexp. The integer form is undefined
// behaviour for every exponent below 15 and cannot express fractional powers
// of two at all.
static float V7fixed_aperture_avx512(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exponent = (h >> 10) & 0x1F;
    const uint32_t mantissa = h & 0x3FF;
    float scale;
    if (exponent == 0) {
        scale = (sign ? -1.0f : 1.0f) * (mantissa / 1024.0f) * (1.0f / 16384.0f);
    } else if (exponent == 31) {
        scale = sign ? -INFINITY : INFINITY;
    } else {
        scale = (sign ? -1.0f : 1.0f) *
                std::ldexp(1.0f + mantissa / 1024.0f, (int)exponent - 15);
    }
    return scale;
}

struct Row { const char* name; const char* file; float (*fn)(uint16_t); };

int main() {
    const Row rows[] = {
        {"V1_gguf_loader",             "src/gguf_loader.cpp",            V1_gguf_loader},
        {"V1FIXED_127_14",             "src/gguf_loader.cpp (repaired)", V1fixed},
        {"V2FIXED_127_14",             "src/deep2/k_quant_gemv_avx512.h (repaired)", V1fixed},
        {"V3_kquant_dequantize_q4k",   "src/core/kquant_dequantize_q4k.cpp (repaired)", V3_kquant_dequant},
        {"V3OLD_kquant_dequant",     "src/core/kquant_dequantize_q4k.cpp (as found)", V3old_kquant_dequant},
        {"V4_runtime_symbol_bridge",   "src/core/runtime_symbol_bridge.cpp", V4_runtime_symbol_bridge},
        {"V5_dml_asm",                "src/core/dml_asm_impl.cpp + dml_asm_fallback.cpp (as found)", V5_dml_asm},
        {"V5FIXED_dml_asm",          "src/core/dml_asm_impl.cpp + dml_asm_fallback.cpp (repaired)", V5fixed_dml_asm},
        {"V6_aperture_reference",    "src/core/aperture_q4_0_reference.cpp", V6_aperture_reference},
        {"V7_aperture_avx512",       "src/core/aperture_q{4,8}_0_avx512_intrinsics.cpp (as found)", V7_aperture_avx512},
        {"V7FIXED_aperture_avx512",  "src/core/aperture_q{4,8}_0_avx512_intrinsics.cpp (repaired)", V7fixed_aperture_avx512},
        {"V8_gguf_dml_bridge",       "src/core/gguf_dml_bridge.cpp", V8_gguf_dml_bridge},
    };

    std::printf("%-28s %-42s %-9s %-9s %-12s %s\n",
                "VARIANT", "FILE", "SUB_OK", "NORM_OK", "SUB_RATIO", "VERDICT");
    for (const Row& r : rows) {
        int subBad = 0, subTotal = 0, normBad = 0, normTotal = 0;
        double ratioLo = 1e300, ratioHi = -1e300;
        for (uint32_t h = 0; h <= 0xFFFFu; ++h) {
            const uint16_t bits = (uint16_t)h;
            const float got = r.fn(bits);
            const float ref = Reference(bits);
            if (std::isnan(ref)) continue;
            const int exp = (bits >> 10) & 0x1F;
            if (exp == 31) continue;
            const bool sub = (exp == 0) && ((bits & 0x3FF) != 0);
            if (sub) ++subTotal; else ++normTotal;
            if (ref == 0.0f) { if (got != 0.0f) ++normBad; continue; }
            const double rel = std::fabs((double)got / (double)ref - 1.0);
            if (sub) {
                if (rel > 1e-6) ++subBad;
                const double q = (double)got / (double)ref;
                if (q < ratioLo) ratioLo = q;
                if (q > ratioHi) ratioHi = q;
            } else if (rel > 1e-6) ++normBad;
        }
        char ratio[32];
        if (subTotal == 0) std::snprintf(ratio, sizeof(ratio), "-");
        else if (ratioLo == ratioHi) std::snprintf(ratio, sizeof(ratio), "%.6g", ratioLo);
        else std::snprintf(ratio, sizeof(ratio), "%.4g..%.4g", ratioLo, ratioHi);
        const bool ok = (subBad == 0 && normBad == 0);
        std::printf("%-28s %-42s %-9s %-9s %-12s %s\n",
                    r.name, r.file,
                    subBad == 0 ? "YES" : "NO",
                    normBad == 0 ? "YES" : "NO",
                    ratio, ok ? "CORRECT" : "WRONG");
        if (!ok) {
            std::printf("    subnormals_wrong=%d/%d  normals_wrong=%d/%d\n",
                        subBad, subTotal, normBad, normTotal);
        }
    }
    return 0;
}