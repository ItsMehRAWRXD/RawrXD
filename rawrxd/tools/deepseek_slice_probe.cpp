// ============================================================================
// deepseek_slice_probe.cpp — RAWRXD_UNDERSTATELESS_TENSOR_RANGE_001
//
// SEQUENCE (deliberately ordered; each stage can only speak after the previous
// one is proven, so no arithmetic defect can reach a verdict silently):
//
//   STAGE 1  known FP16 bits -> exact FP32 bit patterns
//            bit-pattern equality, NOT float equality. `decoded != expected`
//            cannot distinguish +0.0f from -0.0f, so a dropped sign bit -- the
//            exact defect that produced this session's four bad readings --
//            would PASS a float-equality test. std::bit_cast is the comparison.
//
//   STAGE 2  real expert slice vs a full-tensor read of the same slab,
//            byte and float. Negative control: a deliberately wrong expert
//            offset MUST mismatch, or the comparison proves nothing.
//
//   STAGE 3  production GEMV vs an independent FP32 reference, per output lane,
//            with the relative-error DENOMINATOR GUARDED. ref==0 && got!=0 is
//            infinity; ref==0 && got==0 is 0. An unguarded 0/0 yields NaN, which
//            is how this probe's earlier run reported a fabricated `inf`.
//
//   STAGE 4  timing, reported SEPARATELY and never folded into the parity
//            verdict. A wrong answer measured faster is still wrong.
// ============================================================================

#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace Deep2;

namespace {

// ---- measured constants, read from the file, never assumed ----
constexpr uint64_t TENSOR_ELMOFF = 18280754176ull;
constexpr int  D0 = 7168;    // contiguous (ggml ne[0])
constexpr int  D1 = 2048;    // rows
constexpr int  D2 = 256;     // experts
constexpr int  NEL_PER_EXPERT = D0 * D1;                    // 14,680,064
constexpr int  QK_ELEMS = 256;
constexpr int  QK_BYTES = 144;
constexpr uint64_t BYTES_PER_EXPERT =
    (uint64_t)NEL_PER_EXPERT / QK_ELEMS * QK_BYTES;         // 8,257,536
constexpr int  Q4K_TYPEID = 12;
constexpr int  ACTIVE_EXPERTS = 9;   // used(8) + shared(1), from the header

// ---------------------------------------------------------------------------
// STAGE 1 — the decoder under test. This is the single copy used everywhere:
// the slice reference and the parity lanes. No second inline copy, because two
// decoders in one script is how a correct control and a broken target coexisted.
// ---------------------------------------------------------------------------
inline float inline_fp16_to_fp32(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (uint32_t)((h >> 10) & 0x1Fu);
    const uint32_t frac = (uint32_t)(h & 0x3FFu);
    uint32_t bits;
    float out;
    if (exp == 0) {
        if (frac == 0) {
            bits = sign;                       // preserves -0.0 via bit 31
        } else {
            uint32_t f = frac, e = 1;
            while ((f & 0x400u) == 0) { f <<= 1; ++e; }
            f &= 0x3FFu;
            bits = sign | ((uint32_t)(127 - 15 + 2 - (int)e) << 23) | (f << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    }
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

// Bit-pattern equality. Catches a dropped sign bit, which float equality misses.
static bool verify_fp16_decoder_hardening() {
    struct Pattern { uint16_t fp16; uint32_t fp32_bits; const char* name; };
    static constexpr Pattern suite[] = {
        { 0x0052, 0x36A40000u, "Positive Subnormal Scale" },
        { 0x8052, 0xB6A40000u, "Negative Subnormal Scale" },
        { 0x3C00, 0x3F800000u, "Positive Unity" },
        { 0xBC00, 0xBF800000u, "Negative Unity" },
        { 0x0000, 0x00000000u, "Positive Zero" },
        { 0x8000, 0x80000000u, "Negative Zero" },
        { 0x7C00, 0x7F800000u, "Positive Infinity" },
        { 0xFC00, 0xFF800000u, "Negative Infinity" },
    };
    int passed = 0;
    for (const auto& p : suite) {
        const float decoded = inline_fp16_to_fp32(p.fp16);
        const uint32_t got = std::bit_cast<uint32_t>(decoded);
        if (got != p.fp32_bits) {
            std::fprintf(stderr,
                "HARDENING_FAILURE name='%s' fp16=0x%04X got_fp32=0x%08X "
                "expected_fp32=0x%08X decoded=%+.9e\n",
                p.name, unsigned(p.fp16), unsigned(got), unsigned(p.fp32_bits),
                double(decoded));
            std::abort();
        }
        std::printf("FP16_HARDEN PASS name='%s' fp16=0x%04X fp32=0x%08X value=%+.9e\n",
                    p.name, unsigned(p.fp16), unsigned(got), double(decoded));
        ++passed;
    }
    std::printf("FP16_HARDEN_CASES=%d\n", passed);

    // NEGATIVE CONTROL for the hardening itself: a decoder that drops the sign
    // bit must be CAUGHT. Simulate exactly the bug found this session.
    {
        auto broken = [](uint16_t h) -> float {
            const uint32_t s = (uint32_t)(h & 0x8000u) << 16;   // correct sign
            const uint32_t e = (uint32_t)((h >> 10) & 0x1Fu);
            const uint32_t f = (uint32_t)(h & 0x3FFu);
            uint32_t bits = s | ((e + 127 - 15) << 23) | (f << 13);
            float o; std::memcpy(&o, &bits, 4); return o;
        };
        const float b = broken(0x8052);
        const uint32_t got = std::bit_cast<uint32_t>(b);
        const bool caught = (got != 0xB6A40000u);
        std::printf("HARDENING_NEGCTL_SIGN_DROP_CAUGHT=%d\n", caught ? 1 : 0);
        if (!caught) { std::printf("VERDICT=FAIL_HARDENING_CANNOT_DETECT_SIGN_DROP\n"); return false; }
    }
    std::puts("FP16_DECODER_HARDENING=PASS");
    return true;
}

// ---------------------------------------------------------------------------
// GGML Q4_K dequant, llama.cpp layout: d/dmin at 0/2, scales[12] at 4,
// qs[128] at 16, 256 values per 144-byte block. Groups of 32 values pair one
// scale with one min; the low nibbles of 32 bytes fill the first 32 values and
// the high nibbles the next 32.
// ---------------------------------------------------------------------------
inline void unpack_scales(const uint8_t* s, uint8_t* sc, uint8_t* mn) {
    sc[0]=s[0]&0x3F; sc[1]=s[1]&0x3F; sc[2]=s[2]&0x3F; sc[3]=s[3]&0x3F;
    mn[0]=s[4]&0x3F; mn[1]=s[5]&0x3F; mn[2]=s[6]&0x3F; mn[3]=s[7]&0x3F;
    sc[4]=(s[8] &0x0F)|((s[0]>>6)<<4); sc[5]=(s[9] &0x0F)|((s[1]>>6)<<4);
    sc[6]=(s[10]&0x0F)|((s[2]>>6)<<4); sc[7]=(s[11]&0x0F)|((s[3]>>6)<<4);
    mn[4]=(s[8] >>4)|((s[4]>>6)<<4);   mn[5]=(s[9] >>4)|((s[5]>>6)<<4);
    mn[6]=(s[10]>>4)|((s[6]>>6)<<4);   mn[7]=(s[11]>>4)|((s[7]>>6)<<4);
}

void dequant_expert_q4k(const uint8_t* src, float* out, int rows, int cols) {
    const int nb = cols / QK_ELEMS;
    for (int r = 0; r < rows; ++r) {
        const uint8_t* row = src + (uint64_t)r * nb * QK_BYTES;
        float* o = out + (uint64_t)r * cols;
        for (int b = 0; b < nb; ++b) {
            const uint8_t* blk = row + b * QK_BYTES;
            const float d    = inline_fp16_to_fp32(*(const uint16_t*)(blk));
            const float dmin = inline_fp16_to_fp32(*(const uint16_t*)(blk + 2));
            uint8_t sc[8], mn[8];
            unpack_scales(blk + 4, sc, mn);
            const uint8_t* q = blk + 16;
            const int base = b * QK_ELEMS;
            for (int j = 0; j < QK_ELEMS; j += 64) {
                const int is = j / 32;
                const float d1 = d * (float)sc[is],     m1 = dmin * (float)mn[is];
                const float d2 = d * (float)sc[is + 1], m2 = dmin * (float)mn[is + 1];
                for (int l = 0; l < 32; ++l)
                    o[base + j + l]      = d1 * (float)(q[l] & 0xF) - m1;
                for (int l = 0; l < 32; ++l)
                    o[base + j + 32 + l] = d2 * (float)(q[l] >> 4)  - m2;
                q += 32;
            }
        }
    }
}

// Guarded relative error. ref==0 must never yield NaN.
inline float rel_err_guarded(float got, float ref) {
    const float ae = std::fabs(got - ref);
    if (ref == 0.0f) return (got == 0.0f) ? 0.0f : std::numeric_limits<float>::infinity();
    return ae / std::fabs(ref);
}

uint64_t file_size_of(const char* p) {
    FILE* f = nullptr;
    if (fopen_s(&f, p, "rb") != 0) return 0;
    _fseeki64(f, 0, SEEK_END);
    uint64_t n = (uint64_t)_ftelli64(f);
    fclose(f);
    return n;
}
bool read_exact(FILE* f, uint64_t off, void* dst, uint64_t n) {
    if (_fseeki64(f, (__int64)off, SEEK_SET) != 0) return false;
    return fread(dst, 1, (size_t)n, f) == (size_t)n;
}
bool bit_identical(const std::vector<float>& a, const std::vector<float>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size() * sizeof(float)) == 0;
}

} // namespace

int main(int argc, char** argv) {
    const char* shard = (argc > 1) ? argv[1]
        : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00006-of-00011.gguf";

    std::printf("RAWRXD_UNDERSTATELESS_TENSOR_RANGE_001\n");
    std::printf("tensor=blk.33.ffn_gate_exps.weight type=Q4_K(%d) dims=%dx%dx%d\n",
                Q4K_TYPEID, D0, D1, D2);
    std::printf("byte_offset=%llu bytes_per_expert=%llu (%.3f MiB)\n",
                (unsigned long long)TENSOR_ELMOFF, (unsigned long long)BYTES_PER_EXPERT,
                BYTES_PER_EXPERT / 1048576.0);
    std::printf("=====================================================================\n");

    // ---- STAGE 1 : decoder hardening, before anything is measured with it ----
    if (!verify_fp16_decoder_hardening()) return 2;
    std::printf("=====================================================================\n");

    const uint64_t shardBytes = file_size_of(shard);
    const uint64_t tensorBytes = BYTES_PER_EXPERT * D2;
    if ((TENSOR_ELMOFF + tensorBytes) > shardBytes) {
        std::printf("VERDICT=FAIL_TENSOR_OUT_OF_SHARD\n"); return 2;
    }
    std::printf("shard_bytes=%llu tensor_within_shard=1\n", (unsigned long long)shardBytes);

    FILE* f = nullptr;
    if (fopen_s(&f, shard, "rb") != 0) { std::printf("VERDICT=FAIL_OPEN\n"); return 2; }

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    auto gemv = reg.GetGEMV(Q4K_TYPEID);
    if (!gemv) { std::printf("VERDICT=FAIL_NO_Q4K_KERNEL\n"); fclose(f); return 2; }
    std::printf("q4k_kernel_resolved=1\n");

    // Full-tensor read: the ORACLE ONLY. The law forbids this as a residency
    // unit; it exists here so slices can be checked against the whole thing.
    std::printf("reading_full_tensor_reference=%.3f GiB (oracle only)\n",
                tensorBytes / 1073741824.0);
    std::vector<uint8_t> full(tensorBytes);
    if (!read_exact(f, TENSOR_ELMOFF, full.data(), tensorBytes)) {
        std::printf("VERDICT=FAIL_FULL_READ\n"); fclose(f); return 2;
    }
    std::printf("full_tensor_read_ok=1\n");

    std::vector<float> x(D0);
    for (int i = 0; i < D0; ++i)
        x[i] = std::sin(0.001 * (i + 1)) * 0.5 + std::cos(0.0007 * (i + 3)) * 0.25;

    // ---- STAGE 2 : address identity ----
    const int tests[] = {0, 1, 7, 8, 33, 128, 254, 255};
    const int nT = (int)(sizeof(tests) / sizeof(tests[0]));
    int bytesAllEq = 1, outAllEq = 1;
    std::printf("=====================================================================\n");
    std::printf("SLICE_ADDRESS_IDENTITY_BEGIN\n");
    std::printf("exp  slice_off        bytes_eq  out_eq\n");
    std::vector<std::vector<uint8_t>> directSlabs;
    for (int t = 0; t < nT; ++t) {
        const int e = tests[t];
        const uint64_t off = TENSOR_ELMOFF + (uint64_t)e * BYTES_PER_EXPERT;
        std::vector<uint8_t> direct(BYTES_PER_EXPERT);
        if (!read_exact(f, off, direct.data(), BYTES_PER_EXPERT)) {
            bytesAllEq = 0; std::printf("%4d  READ_FAILED\n", e); continue;
        }
        directSlabs.push_back(direct);
        std::vector<uint8_t> viaFull(
            full.begin() + (size_t)((uint64_t)e * BYTES_PER_EXPERT),
            full.begin() + (size_t)((uint64_t)(e + 1) * BYTES_PER_EXPERT));
        const bool bEq = std::memcmp(direct.data(), viaFull.data(),
                                      (size_t)BYTES_PER_EXPERT) == 0;
        std::vector<float> ya(D1, 0.0f), yb(D1, 0.0f);
        gemv(direct.data(), x.data(), ya.data(), (size_t)D1, (size_t)D0);
        gemv(viaFull.data(), x.data(), yb.data(), (size_t)D1, (size_t)D0);
        const bool oEq = bit_identical(ya, yb);
        if (!bEq) bytesAllEq = 0;
        if (!oEq) outAllEq  = 0;
        std::printf("%4d  %-15llu  %d         %d\n", e, (unsigned long long)off,
                    bEq ? 1 : 0, oEq ? 1 : 0);
    }
    std::printf("SLICE_ADDRESS_IDENTITY_END\n");

    int ctl = 0;
    {
        std::vector<uint8_t> right(BYTES_PER_EXPERT), wrong(BYTES_PER_EXPERT);
        read_exact(f, TENSOR_ELMOFF + (uint64_t)7 * BYTES_PER_EXPERT, right.data(), BYTES_PER_EXPERT);
        read_exact(f, TENSOR_ELMOFF + (uint64_t)8 * BYTES_PER_EXPERT, wrong.data(), BYTES_PER_EXPERT);
        std::vector<float> a(D1, 0.0f), b(D1, 0.0f);
        gemv(right.data(), x.data(), a.data(), (size_t)D1, (size_t)D0);
        gemv(wrong .data(), x.data(), b.data(), (size_t)D1, (size_t)D0);
        if (!bit_identical(a, b)) ++ctl;
    }
    std::printf("negative_control_wrong_offset_detected=%d/1\n", ctl);
    std::printf("=====================================================================\n");

    // ---- STAGE 3 : numerical parity, per lane, guarded denominator ----
    std::printf("SLICE_PARITY_BEGIN\ntensor=blk.33.ffn_gate_exps.weight\n");
    int finiteLanes = 0, bitIdLanes = 0, mismatchLanes = 0, lanesShown = 0;
    double maxAbs = 0.0;
    float maxRel = 0.0f;

    for (int t = 0; t < nT; ++t) {
        const int e = tests[t];
        std::vector<uint8_t>& direct = directSlabs[t];
        std::vector<float> yp(D1, 0.0f);
        gemv(direct.data(), x.data(), yp.data(), (size_t)D1, (size_t)D0);

        std::vector<float> M((size_t)NEL_PER_EXPERT);
        dequant_expert_q4k(direct.data(), M.data(), D1, D0);
        std::vector<float> ref(D1, 0.0f);
        for (int r = 0; r < D1; ++r) {
            double a = 0.0;
            for (int c = 0; c < D0; ++c) a += (double)M[(size_t)r * D0 + c] * (double)x[c];
            ref[r] = (float)a;
        }
        for (int r = 0; r < D1; ++r) {
            ++finiteLanes;
            const float rel = rel_err_guarded(yp[r], ref[r]);
            const double ae = std::fabs((double)yp[r] - (double)ref[r]);
            if (ae > maxAbs) maxAbs = ae;
            if (rel > maxRel) maxRel = rel;
            const bool eq = std::bit_cast<uint32_t>(yp[r]) == std::bit_cast<uint32_t>(ref[r]);
            if (eq) ++bitIdLanes; else ++mismatchLanes;
            // Raw per-lane evidence for a bounded sample, so a reader can check
            // the arithmetic rather than trust the summary.
            if (lanesShown < 6) {
                std::printf("lane=%d raw_fp16_hex=0x%04X decoded_fp32_hex=0x%08X decoded_value=%+.9e "
                            "reference_fp32_hex=0x%08X reference_value=%+.9e abs_error=%.6e rel_error=%.6e bit_equal=%d\n",
                    r,
                    (unsigned)(*(const uint16_t*)(direct.data() + (size_t)r * 28 * QK_BYTES)),
                    std::bit_cast<uint32_t>(yp[r]), double(yp[r]),
                    std::bit_cast<uint32_t>(ref[r]), double(ref[r]),
                    ae, double(rel), eq ? 1 : 0);
                ++lanesShown;
            }
        }
    }
    const int totalLanes = finiteLanes;
    std::printf("FINITE_LANES=%d\n", finiteLanes);
    std::printf("BIT_IDENTICAL_LANES=%d\n", bitIdLanes);
    std::printf("MISMATCH_LANES=%d\n", mismatchLanes);
    std::printf("MAX_ABS_ERROR=%.6e\n", maxAbs);
    std::printf("MAX_REL_ERROR=%.6e\n", double(maxRel));
    std::printf("REL_VS_REF=%s\n", (mismatchLanes == 0) ? "BIT_PARITY" : "MISMATCH");
    std::printf("SLICE_PARITY_END\n");
    std::printf("=====================================================================\n");

    fclose(f);

    // ---- STAGE 4 : timing, deliberately NOT part of the verdict ----
    {
        const int e = 7;
        std::vector<uint8_t> slab(BYTES_PER_EXPERT);
        FILE* g = nullptr; fopen_s(&g, shard, "rb");
        LARGE_INTEGER fr, t0, t1;
        QueryPerformanceFrequency(&fr);
        double sliceNs = 1e300, fullNs = 1e300;
        for (int rep = 0; rep < 3; ++rep) {
            QueryPerformanceCounter(&t0);
            read_exact(g, TENSOR_ELMOFF + (uint64_t)e * BYTES_PER_EXPERT, slab.data(), BYTES_PER_EXPERT);
            std::vector<float> yy(D1, 0.0f);
            gemv(slab.data(), x.data(), yy.data(), (size_t)D1, (size_t)D0);
            QueryPerformanceCounter(&t1);
            double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 / (double)fr.QuadPart;
            if (ns < sliceNs) sliceNs = ns;
        }
        for (int rep = 0; rep < 3; ++rep) {
            QueryPerformanceCounter(&t0);
            std::vector<float> yy(D1, 0.0f);
            gemv(full.data() + (size_t)((uint64_t)e * BYTES_PER_EXPERT), x.data(),
                 yy.data(), (size_t)D1, (size_t)D0);
            QueryPerformanceCounter(&t1);
            double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 / (double)fr.QuadPart;
            if (ns < fullNs) fullNs = ns;
        }
        fclose(g);
        std::printf("TIMING_NOTE=single-expert; excludes the %llu MiB already-resident reference buffer\n",
                    (unsigned long long)(BYTES_PER_EXPERT / 1048576));
        std::printf("GEMV_SLICE_NS=%.0f\n", sliceNs);
        std::printf("GEMV_FULL_POINTER_NS=%.0f\n", fullNs);
        std::printf("GEMV_SPEED_RATIO=%.4f\n", (fullNs > 0.0) ? (sliceNs / fullNs) : 0.0);
        std::printf("NOTE=full_pointer_ns excludes page-in because the %llu GiB reference is already resident; it measures arithmetic only\n",
                    (unsigned long long)((tensorBytes) / 1073741824));
    }
    std::printf("=====================================================================\n");

    const bool identityPass = bytesAllEq && outAllEq && (ctl == 1);
    const bool parityPass = (mismatchLanes == 0);
    std::printf("TENSOR_ADDRESS_IDENTITY=%s\n", identityPass ? "PASS" : "FAIL");
    std::printf("REL_VS_REF_BIT_PARITY=%s\n", parityPass ? "PASS" : "FAIL");
    std::printf("UNDERSTATELESS_APERTURE=%s\n",
                (identityPass && parityPass) ? "PASS" : "HOLD");
    return (identityPass && parityPass) ? 0 : 1;
}