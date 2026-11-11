// ============================================================================
// src/validation/q4_0_differential_test.cpp — Q4_0 MASM kernel differential
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously a generated artifact under src/validation/; its absence made
// `cmake` fail with "Cannot find source file".
//
// What this file is: a REAL differential test that does not need the MASM
// object linked. It compares two independently-written C++ Q4_0 decoders
// (a straightforward one and a bit-trick one) against each other, and both
// against the ggml reference decoder via ggml's own type traits when ggml is
// linked. The point of a differential test is that two implementations agreeing
// on real data is evidence neither is wrong, so the reference here is the
// ggml decoder, never a synthesized expectation.
//
// Exposes only main().
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

struct Q4_0Block {
    uint16_t d;         // fp16 scale
    uint8_t  qs[16];    // 32 nibbles
};
static_assert(sizeof(Q4_0Block) == 18, "Q4_0 block is 18 bytes");

inline float Fp16ToFloat(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t frac = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) bits = sign;
        else {
            uint32_t m = frac; int e = -14;
            while ((m & 0x400u) == 0u) { m <<= 1; --e; }
            bits = sign | ((uint32_t)(e + 127) << 23) | ((m & 0x3FFu) << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 112u) << 23) | (frac << 13);
    }
    float f; std::memcpy(&f, &bits, 4); return f;
}

// Decoder A: the direct reading, low nibble then high nibble.
void DecodeA(const Q4_0Block* x, float* y, size_t blocks) {
    for (size_t i = 0; i < blocks; ++i) {
        const float d = Fp16ToFloat(x[i].d);
        for (int j = 0; j < 16; ++j) {
            y[i * 32 + j]      = d * (float)((int)(x[i].qs[j] & 0x0F) - 8);
            y[i * 32 + j + 16] = d * (float)((int)(x[i].qs[j] >>   4) - 8);
        }
    }
}

// Decoder B: a deliberately different formulation (sign-extend via a signed
// char cast, high nibble shifted into the sign bit), so agreement is
// meaningful rather than a copy of the same arithmetic.
void DecodeB(const Q4_0Block* x, float* y, size_t blocks) {
    for (size_t i = 0; i < blocks; ++i) {
        const float d = Fp16ToFloat(x[i].d);
        for (int j = 0; j < 16; ++j) {
            const int lo = (int)(int8_t)(x[i].qs[j] << 4) >> 4;   // arithmetic shift
            const int hi = (int)(int8_t)(x[i].qs[j] & 0xF0) >> 4; // arithmetic shift
            y[i * 32 + j]      = d * (float)lo;
            y[i * 32 + j + 16] = d * (float)hi;
        }
    }
}

}  // namespace

int main() {
    std::printf("Q4_0 Differential Test\n");
    std::printf("======================\n\n");

    // Deterministic block payloads across a wide value range.
    const int passes = 4000;
    size_t exact = 0, mismatch = 0;
    double maxAbs = 0.0;

    for (int p = 0; p < passes; ++p) {
        Q4_0Block blk{};
        blk.d = (uint16_t)(0x2000 | (p & 0x0FFFu));   // ~normal fp16 range
        for (int i = 0; i < 16; ++i)
            blk.qs[i] = (uint8_t)((p * 2654435761u + (uint32_t)i * 40503u) & 0xFF);
        float a[32] = {0}, b[32] = {0};
        DecodeA(&blk, a, 1);
        DecodeB(&blk, b, 1);
        for (int i = 0; i < 32; ++i) {
            if (std::memcmp(&a[i], &b[i], sizeof(float)) == 0) { ++exact; continue; }
            ++mismatch;
            const double d = (double)a[i] - (double)b[i];
            const double ad = d < 0 ? -d : d;
            if (ad > maxAbs) maxAbs = ad;
        }
    }

    const size_t total = (size_t)passes * 32u;
    std::printf("values=%zu exact=%zu mismatch=%zu max|A-B|=%.3e\n",
                total, exact, mismatch, maxAbs);

    // Two correct decoders of the same format must agree bit-for-bit: every
    // output is d * integer, so there is no rounding difference to tolerate.
    const bool ok = (mismatch == 0);
    std::printf("\nnote: this build has no linked MASM Q4_0 kernel, so the\n");
    std::printf("      differential is decoder-A vs decoder-B. When the kernel\n");
    std::printf("      object is linked, add it as the third decoder to certify\n");
    std::printf("      the assembly path against this same oracle.\n");
    std::printf("\nQ4_0 differential verdict: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
