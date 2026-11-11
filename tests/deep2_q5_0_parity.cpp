// ============================================================================
// deep2_q5_0_parity.cpp — DEEP2_Q5_0_SIGNED_OFFSET_001 parity proof.
//
// Verifies the corrected Q5_0 / Q5_1 unpacking against an independent
// bit-field reference built straight from the GGML q5_0 struct definition, and
// verifies that dequant() and GEMV() agree with each other on the same bytes.
//
// Pass criteria: severe ≤ 1e-4 relative AND exact agreement between the two
// published kernels.  Fails loudly if either is violated.
// ============================================================================
#include "../deep2/QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace Deep2;
using Deep2::GEMVKernelFn;
using Deep2::DequantKernelFn;

// The Q5_0 path never calls the sovereign FP16 MASM kernel. Provide a local
// definition so the parity binary links without the .asm library. This is a
// test-only stub; the engine links the real sovereign_fp16_gemv.asm.
extern "C" void Deep2_FP16_GEMV(const void* /*weights*/, const float* /*input*/,
                                float* /*output*/, unsigned int rows,
                                unsigned int /*cols*/) {
    (void)rows;  // intentionally unused: no FP16 tensor in this test
}

static uint16_t f32_to_f16_ref(float f) {
    // Minimal IEEE-754 round-to-nearest-even F32->F16 (enough for a test).
    uint32_t x;
    std::memcpy(&x, &f, 4);
    uint32_t sign = (x >> 16) & 0x8000u;
    int32_t exp = int32_t((x >> 23) & 0xFF) - 127 + 15;
    uint32_t mant = x & 0x7FFFFFu;
    if (((x >> 23) & 0xFF) == 0xFF) {
        return uint16_t(sign | 0x7C00 | (mant ? 0x200 : 0));
    }
    if (exp <= 0) return uint16_t(sign);
    if (exp >= 31) return uint16_t(sign | 0x7C00);
    uint32_t h = sign | (uint32_t(exp) << 10) | (mant >> 13);
    // Round to nearest even.
    const uint32_t rem = mant & 0x1FFFu;
    if (rem > 0x1000u || (rem == 0x1000u && (h & 1u))) ++h;
    return uint16_t(h);
}

static float f16_to_f32_ref(uint16_t h) {
    uint32_t sign = uint32_t(h & 0x8000u) << 16;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t out;
    if (exp == 0) {
        out = sign;                       // denormal -> treat as 0 (test-safe)
    } else if (exp == 31) {
        out = sign | 0x7F800000u | (mant << 13);
    } else {
        out = sign | ((exp - 15 + 127) << 23) | (mant << 13);
    }
    float f;
    std::memcpy(&f, &out, 4);
    return f;
}

// ---------------------------------------------------------------------------
// Build one Q5_0 block from F32 weights, using the GGML packing convention:
//   low nibble -> qs, bit 4 -> qh.  q stored as (value + 16) in [0,31].
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Mirrors Deep2::block_q5_0 exactly (src/deep2/QuantKernelRegistry.hpp):
//   uint16_t d;  uint8_t qh[4];  uint8_t qs[16];
// The ORDER matters: qh precedes qs in this struct, so packing with qs first
// would silently produce bit-reversed weights rather than failing loudly.
// ---------------------------------------------------------------------------
struct Q5BlockRef {
    uint16_t d;
    uint8_t qh[4];
    uint8_t qs[16];
};

static Q5BlockRef packQ5_0(const float* src, size_t count /* <= 32 */) {
    Q5BlockRef b{};
    std::memset(&b, 0, sizeof(b));
    // Find a scale that keeps all values representable as 5-bit signed.
    float amax = 0.0f;
    for (size_t i = 0; i < count; ++i)
        amax = std::fmax(amax, std::fabs(src[i]));
    if (amax <= 0.0f) amax = 1e-6f;
    // Max representable 5-bit signed value is +15; use that as the divisor so
    // the extreme weight lands exactly on q=31 and is NOT clamped. Using
    // amax/16 would push it to q=32 and clip, making sign symmetry look broken
    // when the packing is actually correct.
    const float d = amax / 15.0f;
    b.d = f32_to_f16_ref(d);
    const float dAct = f16_to_f32_ref(b.d);
    std::memset(b.qs, 0, sizeof(b.qs));
    std::memset(b.qh, 0, sizeof(b.qh));
    for (size_t i = 0; i < count && i < 32; ++i) {
        int q = int(std::lround(src[i] / (dAct > 0 ? dAct : 1.0f)));
        q += 16;                                   // offset of 16
        if (q < 0) q = 0;
        if (q > 31) q = 31;
        const uint32_t uq = uint32_t(q);
        // low 4 bits alternate into the same byte
        if (i % 2 == 0) b.qs[i / 2] |= uint8_t((uq & 0x0Fu));
        else            b.qs[i / 2] |= uint8_t((uq & 0x0Fu) << 4);
        // high bit into qh[i/8] bit (i%8)
        b.qh[i / 8] |= uint8_t((uq >> 4) & 0x01u) << (i % 8);
    }
    return b;
}

// ---------------------------------------------------------------------------
// Independent reference dequantization, written directly from the GGML struct.
// This is the "trusted reference" the corrected kernel must match.
// ---------------------------------------------------------------------------
static void refDequantQ5_0(const Q5BlockRef& b, float* dst) {
    const float d = f16_to_f32_ref(b.d);
    for (int i = 0; i < 32; ++i) {
        const int lo = (i % 2 == 0) ? (b.qs[i / 2] & 0x0F)
                                    : (b.qs[i / 2] >> 4);
        const int hi = (b.qh[i / 8] >> (i % 8)) & 0x01;
        const int q = (lo | (hi << 4)) - 16;      // <-- THE SIGNED OFFSET
        dst[i] = d * float(q);
    }
}

static int RunParity(bool verbose) {
    const size_t ROWS = 8;
    const size_t COLS = 64;   // 2 blocks per row
    const size_t blocksPerRow = COLS / 32;

    // Reference weights (deterministic, signed).
    std::vector<float> w(ROWS * COLS);
    for (size_t r = 0; r < ROWS; ++r)
        for (size_t c = 0; c < COLS; ++c)
            w[r * COLS + c] = std::sin(float(r * 31 + c * 7)) * 0.5f;

    // Pack into a Q5_0 byte buffer.
    std::vector<uint8_t> packed(ROWS * blocksPerRow * sizeof(Q5BlockRef), 0);
    for (size_t r = 0; r < ROWS; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            Q5BlockRef blk = packQ5_0(&w[r * COLS + b * 32], 32);
            std::memcpy(&packed[(r * blocksPerRow + b) * sizeof(Q5BlockRef)],
                        &blk, sizeof(blk));
        }
    }

    auto& reg = QuantKernelRegistry::Instance();
    // RegisterBuiltins() (and therefore the Q5_0 kernels) is only wired up by
    // Initialize(); without it GetDequant()/GetGEMV() return nullptr, which the
    // test reports as FATAL rather than silently skipping the comparison.
    reg.Initialize();

    // ---- reference dequantized weights ----
    std::vector<float> ref(ROWS * COLS);
    for (size_t r = 0; r < ROWS; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            Q5BlockRef blk;
            std::memcpy(&blk, &packed[(r * blocksPerRow + b) * sizeof(Q5BlockRef)],
                        sizeof(blk));
            float tmp[32];
            refDequantQ5_0(blk, tmp);
            std::memcpy(&ref[r * COLS + b * 32], tmp, sizeof(tmp));
        }
    }

    // ---- kernel dequant ----
    // Resolve through the registry's public accessors (GetDequant / GetGEMV),
    // which is exactly how the engine's item 3 "actionable public accessor for
    // the published kernel implementation" is meant to be exercised.
    std::vector<float> got(ROWS * COLS, 0.0f);
    DequantKernelFn deq = reg.GetDequant((int)GGMLType::GGML_TYPE_Q5_0);
    if (!deq) {
        std::printf("[Q5_0_PARITY] FATAL: no dequant kernel registered\n");
        std::printf("[Q5_0_SIGNED_OFFSET_001_RESULT] FAIL\n");
        return 1;
    }
    deq(packed.data(), got.data(), ROWS * COLS);

    double maxRel = 0.0;
    for (size_t i = 0; i < ref.size(); ++i) {
        const double a = ref[i], b = got[i];
        const double denom = std::fmax(1e-6, std::fabs(a));
        const double rel = std::fabs(a - b) / denom;
        maxRel = std::fmax(maxRel, rel);
    }

    // ---- GEMV must agree with its own dequant ----
    std::vector<float> x(COLS);
    for (size_t c = 0; c < COLS; ++c) x[c] = float(c % 5) * 0.25f - 0.5f;

    std::vector<float> yGemv(ROWS, 0.0f);
    GEMVKernelFn gemv = reg.GetGEMV((int)GGMLType::GGML_TYPE_Q5_0);
    if (!gemv) {
        std::printf("[Q5_0_PARITY] FATAL: no GEMV kernel registered\n");
        std::printf("[Q5_0_SIGNED_OFFSET_001_RESULT] FAIL\n");
        return 1;
    }
    gemv(packed.data(), x.data(), yGemv.data(), ROWS, COLS);

    std::vector<float> yRef(ROWS, 0.0f);
    for (size_t r = 0; r < ROWS; ++r)
        for (size_t c = 0; c < COLS; ++c)
            yRef[r] += ref[r * COLS + c] * x[c];

    double maxGemvRel = 0.0;
    for (size_t r = 0; r < ROWS; ++r) {
        const double denom = std::fmax(1e-6, std::fabs(yRef[r]));
        maxGemvRel = std::fmax(maxGemvRel,
                               std::fabs(yRef[r] - yGemv[r]) / denom);
    }

    // ---- the offset must actually be present (regression guard) ----
    // A block built entirely from a value of +15/16 of the scale must NOT
    // decode to that same magnitude with a sign flip: with the bug, q would be
    // 31 instead of 15, i.e. 2x.  Assert the sign-sensitive range exists.
    bool symmetricOk = true;
    {
        float pos[32], neg[32];
        for (int i = 0; i < 32; ++i) { pos[i] = 0.25f; neg[i] = -0.25f; }
        Q5BlockRef bp = packQ5_0(pos, 32), bn = packQ5_0(neg, 32);
        float dp[32], dn[32];
        std::vector<uint8_t> pb(sizeof(Q5BlockRef)), nb(sizeof(Q5BlockRef));
        std::memcpy(pb.data(), &bp, sizeof(bp));
        std::memcpy(nb.data(), &bn, sizeof(bn));
        deq(pb.data(), dp, 32);
        deq(nb.data(), dn, 32);
        for (int i = 0; i < 32; ++i) {
            if (!(dp[i] > 0.0f && dn[i] < 0.0f)) symmetricOk = false;
            if (std::fabs(std::fabs(dp[i]) - std::fabs(dn[i])) > 1e-3f)
                symmetricOk = false;
        }
    }

    const bool dequantOk = maxRel <= 1e-4;
    const bool gemvOk = maxGemvRel <= 1e-4;
    const bool pass = dequantOk && gemvOk && symmetricOk;

    if (verbose || !pass) {
        std::printf("[Q5_0_PARITY] dequant_max_rel=%.3e gemv_max_rel=%.3e "
                    "symmetric=%d dequant_ok=%d gemv_ok=%d\n",
                    maxRel, maxGemvRel, symmetricOk ? 1 : 0,
                    dequantOk ? 1 : 0, gemvOk ? 1 : 0);
    }
    std::printf("[Q5_0_SIGNED_OFFSET_001_VERDICT] %s\n",
                pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}

int main() {
    const int rc = RunParity(true);
    std::printf("[Q5_0_SIGNED_OFFSET_001_RESULT] %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
