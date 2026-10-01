// RAWRXD_B65_Q3K_BLOCK_DIFF_001
//
// Host-only differential gate for Q3_K dequantization. This is STEP_2..STEP_5
// of the B65 closure ladder, and it deliberately does NOT touch Vulkan.
//
// Why this exists: the first B65 attempt ported q3_K to GLSL from a structural
// analogy to the Q2_K path. It compiled, dispatched 5488 times with zero
// dispatch-level failures, reported 7.49 TPS, and emitted finite garbage
// ("eczeczecz...") instead of text. Two defects: the packed scale layout was
// reconstructed wrong, and the `- 32` scale bias was dropped. Every
// GPU_FORWARD_FINITE_CHECK line read nan=0 inf=0, so finiteness could not
// distinguish correct inference from well-behaved garbage.
//
// This harness fixes the class of bug by comparing INTERMEDIATES, not outputs:
//
//   scale_raw      reference vs candidate   exact integer equality required
//   scale_signed   reference vs candidate   exact
//   q              reference vs candidate   exact
//   weight         reference vs candidate   exact bit pattern
//
// Float comparison is only meaningful after the integer intermediates agree.
// Coverage is every one of the 256 elements of every block, across adversarial
// block patterns plus randomized blocks, because packing bugs typically hit
// specific lanes or nibbles and leave neighbouring lanes correct.
//
// The reference below is a transcription of dequant_q3_k() in
// QuantKernelRegistry.cpp:1439. It is written out longhand rather than called
// from the library so that a defect in the library implementation does not
// silently agree with itself.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <random>

namespace {

struct block_q3_K {
    uint8_t  hmask[32];
    uint8_t  qs[64];
    uint8_t  scales[12];
    uint16_t d;
};
static_assert(sizeof(block_q3_K) == 110, "GGUF block_q3_K must be 110 bytes");

float f16_to_f32(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t man  = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0u) {
        if (man == 0u) {
            bits = sign;
        } else {
            // subnormal: normalize
            int e = -1;
            uint32_t m = man;
            do { m <<= 1; ++e; } while (!(m & 0x400u));
            m &= 0x3FFu;
            bits = sign | (uint32_t(127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (man << 13);
    } else {
        bits = sign | ((exp + 127u - 15u) << 23) | (man << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ---------------------------------------------------------------- reference
// Verbatim structure of dequant_q3_k() (QuantKernelRegistry.cpp:1439).
// Emits the per-element intermediates so the candidate can be compared against
// them directly rather than only through the final product.
struct RefElement {
    int      scaleRaw;      // scales[is] before the -32 bias
    int      scaleSigned;   // scales[is] - 32
    uint32_t q;             // 2-bit code
    uint32_t hv;            // hmask penalty: 0 or 4
    float    weight;
};

void reference_q3_k(const uint8_t* src, RefElement out[256], float* weights) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(src);
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;
    const size_t numBlocks = 1;

    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        uint32_t aux[4];
        std::memcpy(aux, blocks[b].scales, 12);
        const uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
        const int8_t* scales = reinterpret_cast<const int8_t*>(aux);
        const uint8_t* q = blocks[b].qs;
        const uint8_t* hm = blocks[b].hmask;
        uint8_t m = 1;
        int is = 0;
        float* y = weights;
        for (int n128 = 0; n128 < 256; n128 += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                const int scRaw0 = scales[is++];
                const float dl0 = d * float(scRaw0 - 32);
                for (int l = 0; l < 16; ++l) {
                    const size_t idx = size_t(n128 + j * 32 + l);
                    const uint32_t qq = uint32_t((q[l] >> shift) & 3);
                    const uint32_t hh = (hm[l] & m) ? 0u : 4u;
                    out[idx].scaleRaw = scRaw0;
                    out[idx].scaleSigned = scRaw0 - 32;
                    out[idx].q = qq;
                    out[idx].hv = hh;
                    out[idx].weight = dl0 * float(int(qq) - int(hh));
                    y[idx] = dl0 * float(int(qq) - int(hh));
                }
                const int scRaw1 = scales[is++];
                const float dl1 = d * float(scRaw1 - 32);
                for (int l = 0; l < 16; ++l) {
                    const size_t idx = size_t(n128 + j * 32 + 16 + l);
                    const uint32_t qq = uint32_t((q[l + 16] >> shift) & 3);
                    const uint32_t hh = (hm[l + 16] & m) ? 0u : 4u;
                    out[idx].scaleRaw = scRaw1;
                    out[idx].scaleSigned = scRaw1 - 32;
                    out[idx].q = qq;
                    out[idx].hv = hh;
                    out[idx].weight = dl1 * float(int(qq) - int(hh));
                    y[idx] = dl1 * float(int(qq) - int(hh));
                }
                shift += 2;
                m <<= 1;
            }
            q += 32;
        }
    }
}

// ---------------------------------------------------------------- candidate
// Transcription of the FAILED GLSL q3k_weight() from the first B65 attempt,
// written in C++ so it can be diffed on the host. Reproduced here so the
// harness demonstrates the defect rather than merely asserting it.
//
// Both attempts are kept. `candidate_q3_k` is the first (broken) attempt;
// `candidate_q3_k_v2` is the corrected transcription. Both are diffed, because
// the point of this gate is to show which specific change moved which
// intermediate -- not just to report a green board.
struct CandidateResult {
    int      scaleRaw;
    int      scaleSigned;
    uint32_t q;
    uint32_t hv;
    float    weight;
};

using u32 = uint32_t;

// --- attempt 1: the shipped-broken form -------------------------------------
int cand1_scale16(const uint8_t b[110], u32 is) {
    auto rd32 = [&](u32 off) -> u32 {
        return u32(b[off]) | (u32(b[off + 1]) << 8) |
               (u32(b[off + 2]) << 16) | (u32(b[off + 3]) << 24);
    };
    const u32 a0 = rd32(96), a1 = rd32(100), tm = rd32(104);
    const u32 km2 = 0x0f0f0f0fu;
    const u32 km1 = 0x03030303u;
    u32 n2 = ((a0 >> 4) & km2) | (((tm >> 4) & km1) << 4);
    u32 n3 = ((a1 >> 4) & km2) | (((tm >> 6) & km1) << 4);
    u32 n0 = (a0 & km2) | (((tm) & km1) << 4);
    u32 n1 = (a1 & km2) | (((tm >> 2) & km1) << 4);
    (void)n2; (void)n3;
    // DEFECT 1: assumes the unpacked 16 scales live in n0[0..3] and n1[0..3].
    // The reference interleaves them across all four aux words.
    u32 packed = (is < 4u) ? n0 : n1;
    u32 byteIdx = (is < 4u) ? is : (is - 4u);
    u32 v = (packed >> (byteIdx * 8u)) & 255u;
    return v >= 128u ? int(v) - 256 : int(v);
}

CandidateResult candidate_q3_k(const uint8_t b[110], u32 col) {
    CandidateResult r{};
    u32 idx = col % 256u;
    u32 base = (col / 256u) * 110u;

    u32 n128 = idx / 128u;
    u32 inHalf = idx % 128u;
    u32 j = inHalf / 32u;
    u32 l = inHalf % 32u;
    u32 shift = j * 2u;
    u32 m = 1u << n128;

    u32 is = n128 * 8u + j * 2u + (l >= 16u ? 1u : 0u);
    int sc = cand1_scale16(b, is);

    u32 qsIdx = n128 * 32u + j * 32u + l;
    u32 hmIdx = n128 * 16u + (l >= 16u ? (l - 16u) : l);
    u32 qv = (b[base + 32u + qsIdx] >> shift) & 3u;
    u32 hv = (b[base + hmIdx] & m) != 0u ? 0u : 4u;

    float d = f16_to_f32(uint16_t(b[base + 108u]) | (uint16_t(b[base + 109u]) << 8));
    if (!(d == d) || std::fabs(d) > 3.4e38f) d = 0.0f;

    r.scaleRaw = sc;
    r.scaleSigned = sc;              // DEFECT 2: the -32 bias is missing
    r.q = qv;
    r.hv = hv;
    r.weight = d * float(sc) * float(int(qv) - int(hv));
    return r;
}

// --- attempt 2: corrected transcription -------------------------------------
// DEFECT 1 FIXED: rebuild the four aux words exactly as the reference does,
// keeping the temporaries that the reference overwrites, then read scale[is]
// as a SIGNED byte of the resulting 16-byte aux array.
// DEFECT 2 FIXED: apply the -32 bias.
int cand2_scale16(const uint8_t b[110], u32 is) {
    auto rd32 = [&](u32 off) -> u32 {
        return u32(b[off]) | (u32(b[off + 1]) << 8) |
               (u32(b[off + 2]) << 16) | (u32(b[off + 3]) << 24);
    };
    const u32 km1 = 0x03030303u;
    const u32 km2 = 0x0f0f0f0fu;
    // NOTE: aux[2] must be snapshotted BEFORE aux[0..3] are rewritten, exactly
    // as the reference does. Losing this is what broke attempt 1.
    u32 aux[4];
    aux[0] = rd32(96);
    aux[1] = rd32(100);
    const u32 tmp = aux[2] = rd32(104);
    aux[2] = ((aux[0] >> 4) & km2) | (((tmp >> 4) & km1) << 4);
    aux[3] = ((aux[1] >> 4) & km2) | (((tmp >> 6) & km1) << 4);
    aux[0] = (aux[0] & km2) | (((tmp >> 0) & km1) << 4);
    aux[1] = (aux[1] & km2) | (((tmp >> 2) & km1) << 4);
    // The 16 scales are the 16 SIGNED bytes of aux[0..3] in order.
    const u32 word = aux[is / 4u];
    const u32 byteIdx = is % 4u;
    const u32 v = (word >> (byteIdx * 8u)) & 255u;
    return v >= 128u ? int(v) - 256 : int(v);
}

CandidateResult candidate_q3_k_v2(const uint8_t b[110], u32 col) {
    CandidateResult r{};
    u32 idx = col % 256u;
    u32 base = (col / 256u) * 110u;

    const u32 n128 = idx / 128u;
    const u32 inHalf = idx % 128u;
    const u32 j = inHalf / 32u;
    const u32 l = inHalf % 32u;
    const u32 shift = j * 2u;
    // m is a uint8_t in the reference that is declared ONCE and shifted at the
    // END of every j iteration, so it is NOT reset between the two 128-halves.
    // Its eight used values are 1,2,4,8,16,32,64,128 indexed by
    // (n128*4 + j). Both attempts so far used 1<<n128, which is only correct
    // for n128==0 && j==0 -- that is 1/8 of the block.
    const u32 m = 1u << (n128 * 4u + j);

    const u32 is = n128 * 8u + j * 2u + (l >= 16u ? 1u : 0u);
    const int scRaw = cand2_scale16(b, is);
    const int scSigned = scRaw - 32;

    const u32 qsIdx = n128 * 32u + l;
    const u32 hmIdx = l;
    const u32 qv = (b[base + 32u + qsIdx] >> shift) & 3u;
    // hm is the block's 32-byte hmask and is NEVER advanced by the reference;
    // only the selector bit `m` moves (1 for the first 128-half, 2,4,...,2^15
    // as j advances). So the index is always l, and the half contributes only
    // through `m`.
    const u32 hv = (b[base + hmIdx] & m) != 0u ? 0u : 4u;

    float d = f16_to_f32(uint16_t(b[base + 108u]) | (uint16_t(b[base + 109u]) << 8));
    if (!(d == d) || std::fabs(d) > 3.4e38f) d = 0.0f;

    r.scaleRaw = scRaw;
    r.scaleSigned = scSigned;
    r.q = qv;
    r.hv = hv;
    r.weight = d * float(scSigned) * float(int(qv) - int(hv));
    return r;
}

// ------------------------------------------------------------------ driver

struct BlockCase {
    char     name[32];
    uint8_t  bytes[110];
};

bool bitsEqual(float a, float b) {
    uint32_t x, y;
    std::memcpy(&x, &a, 4);
    std::memcpy(&y, &b, 4);
    return x == y;
}

void fillDeterministic(uint8_t b[110], u32 seed) {
    for (u32 i = 0; i < 110; ++i) {
        switch (seed) {
        case 0: b[i] = 0x00; break;
        case 1: b[i] = 0xFF; break;
        case 2: b[i] = uint8_t(i & 1u ? 0x00 : 0xFF); break;
        case 3: b[i] = uint8_t(i); break;
        case 4: b[i] = uint8_t(0xAA); break;
        case 5: b[i] = uint8_t(0x55); break;
        case 6: b[i] = uint8_t(i * 37u); break;
        default: b[i] = uint8_t(i * 91u + 13u); break;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    std::vector<BlockCase> cases;
    const char* names[] = { "all_zero", "all_ff", "alt_ff00", "incrementing",
                            "aa", "55", "stride37", "stride91" };
    for (u32 s = 0; s < 8; ++s) {
        BlockCase c{};
        std::snprintf(c.name, sizeof(c.name), "%s", names[s]);
        fillDeterministic(c.bytes, s);
        cases.push_back(c);
    }
    // Randomized blocks: these catch packing interactions that deterministic
    // patterns miss.
    std::mt19937 rng(0xB65u);
    for (int r = 0; r < 64; ++r) {
        BlockCase c{};
        std::snprintf(c.name, sizeof(c.name), "random_%d", r);
        for (u32 i = 0; i < 110; ++i) c.bytes[i] = uint8_t(rng());
        // Keep d a sane fp16 (0x3C00 = 1.0) so weights stay comparable.
        c.bytes[108] = 0x00; c.bytes[109] = 0x3C;
        cases.push_back(c);
    }

    const int extra = (argc > 1) ? std::atoi(argv[1]) : 0;
    for (int r = 0; r < extra; ++r) {
        BlockCase c{};
        std::snprintf(c.name, sizeof(c.name), "random_extra_%d", r);
        for (u32 i = 0; i < 110; ++i) c.bytes[i] = uint8_t(rng());
        c.bytes[108] = 0x00; c.bytes[109] = 0x3C;
        cases.push_back(c);
    }

    // Both transcriptions are diffed in one pass. v1 is the version that
    // shipped in the failed GLSL and is expected to FAIL; v2 is the corrected
    // form that is expected to PASS. Reporting both makes the fix auditable
    // rather than merely asserted.
    struct Mismatch { uint64_t scaleRaw = 0, scaleSigned = 0, q = 0, hv = 0, weight = 0; };

    auto runCandidate = [&](auto&& candFn, const char* tag, Mismatch& m,
                            int& firstBlock, int& firstElem, std::string& detail) {
        for (size_t ci = 0; ci < cases.size(); ++ci) {
            RefElement ref[256];
            float refW[256];
            std::memset(ref, 0, sizeof(ref));
            reference_q3_k(cases[ci].bytes, ref, refW);

            for (u32 col = 0; col < 256; ++col) {
                const CandidateResult cand = candFn(cases[ci].bytes, col);
                bool bad = false;
                if (cand.scaleRaw    != ref[col].scaleRaw)    { ++m.scaleRaw;    bad = true; }
                if (cand.scaleSigned != ref[col].scaleSigned) { ++m.scaleSigned; bad = true; }
                if (cand.q           != ref[col].q)           { ++m.q;           bad = true; }
                if (cand.hv          != ref[col].hv)          { ++m.hv;          bad = true; }
                if (!bitsEqual(cand.weight, ref[col].weight)) { ++m.weight;      bad = true; }
                if (bad && firstBlock < 0) {
                    firstBlock = int(ci);
                    firstElem  = int(col);
                    char buf[512];
                    std::snprintf(buf, sizeof(buf),
                        "case=%s col=%u refScaleRaw=%d candScaleRaw=%d "
                        "refScaleSigned=%d candScaleSigned=%d refQ=%u candQ=%u "
                        "refHv=%u candHv=%u refWeight=%.9g candWeight=%.9g",
                        cases[ci].name, col,
                        ref[col].scaleRaw, cand.scaleRaw,
                        ref[col].scaleSigned, cand.scaleSigned,
                        ref[col].q, cand.q, ref[col].hv, cand.hv,
                        (double)ref[col].weight, (double)cand.weight);
                    detail = buf;
                }
            }
        }
        (void)tag;
    };

    const size_t elems = cases.size() * 256;
    std::printf("B65_Q3K_BLOCK_DIFF cases=%zu elements=%llu\n",
                cases.size(), (unsigned long long)elems);

    Mismatch m1; int b1=-1, e1=-1; std::string d1;
    runCandidate(candidate_q3_k, "v1", m1, b1, e1, d1);
    std::printf("\n--- v1 (shipped in failed GLSL) ---\n");
    std::printf("scaleRawMismatch=%llu scaleSignedMismatch=%llu qMismatch=%llu "
                "hvMismatch=%llu weightMismatch=%llu\n",
                (unsigned long long)m1.scaleRaw, (unsigned long long)m1.scaleSigned,
                (unsigned long long)m1.q, (unsigned long long)m1.hv,
                (unsigned long long)m1.weight);
    if (b1 >= 0) {
        std::printf("V1_FIRST_BAD block=%d (%s) elem=%d\n", b1,
                    cases[(size_t)b1].name, e1);
        std::printf("V1_FIRST_BAD_DETAIL %s\n", d1.c_str());
    }

    Mismatch m2; int b2=-1, e2=-1; std::string d2;
    runCandidate(candidate_q3_k_v2, "v2", m2, b2, e2, d2);
    std::printf("\n--- v2 (corrected transcription) ---\n");
    std::printf("scaleRawMismatch=%llu scaleSignedMismatch=%llu qMismatch=%llu "
                "hvMismatch=%llu weightMismatch=%llu\n",
                (unsigned long long)m2.scaleRaw, (unsigned long long)m2.scaleSigned,
                (unsigned long long)m2.q, (unsigned long long)m2.hv,
                (unsigned long long)m2.weight);
    if (b2 >= 0) {
        std::printf("V2_FIRST_BAD block=%d (%s) elem=%d\n", b2,
                    cases[(size_t)b2].name, e2);
        std::printf("V2_FIRST_BAD_DETAIL %s\n", d2.c_str());
    }

    const bool v1pass = (m1.scaleRaw==0 && m1.scaleSigned==0 && m1.q==0 &&
                         m1.hv==0 && m1.weight==0);
    const bool v2pass = (m2.scaleRaw==0 && m2.scaleSigned==0 && m2.q==0 &&
                         m2.hv==0 && m2.weight==0);
    std::printf("\nQ3K_BLOCK_PARITY_V1=%s\n", v1pass ? "PASS" : "FAIL");
    std::printf("Q3K_BLOCK_PARITY_V2=%s\n", v2pass ? "PASS" : "FAIL");
    // The gate is v2. v1 is retained as the documented defect.
    std::printf("Q3K_BLOCK_PARITY=%s\n", v2pass ? "PASS" : "FAIL");
    std::printf("GLSL_PORT_AUTHORIZED=%s\n", v2pass ? "YES" : "NO");
    std::printf("VERDICT=%s\n", v2pass ? "PASS" : "FAIL");
    return v2pass ? 0 : 1;
}