// q6k_block_trace.cpp
// RAWRXD_Q6K_LIVE_BLOCK_TRACE_001
//
// Goal: find the FIRST field at which two executions stop seeing the same thing.
// Element 0 of block 0 only. Snapshot first, so live mutation and aliasing are
// removed from the comparison before any field is inspected.
//
// Three decodes of one element:
//   A  direct, from the LIVE pointer
//   B  direct, from an immutable 210-byte snapshot
//   C  the gguf_loader ToFloat32 path (measured from its output buffer)
// plus C_local: the same algorithm transcribed from gguf_loader.cpp, run on the
// snapshot, which separates "algorithm differs" from "invocation differs".
#include "gguf_loader.hpp"
#include "deep2/k_quant_gemv_avx512.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

#pragma pack(push, 1)
struct BlockQ6KLayout {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};
#pragma pack(pop);
static constexpr int kQKK = 256;

static uint64_t Fnv1a64(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

static float FP16(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t e = (h >> 10) & 0x1Fu, m = h & 0x3FFu;
    uint32_t bits;
    if (e == 0) {
        if (m == 0) bits = sign;
        else { int sh = 0; uint32_t mm = m; while (!(mm & 0x400u)) { mm <<= 1; ++sh; }
               mm &= 0x3FFu; bits = sign | ((127 - 15 - sh) << 23) | (mm << 13); }
    } else if (e == 31) bits = sign | 0x7F800000u | (m << 13);
    else bits = sign | ((e + 112) << 23) | (m << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}

// One element, recording every intermediate. `src` is a block base.
struct Trace {
    const uint8_t* base;
    const uint8_t* ql; const uint8_t* qh; const int8_t* sc; const uint8_t* dp;
    uint16_t d_bits; float d_f32;
    uint8_t ql0, qh0, sc0_raw; int8_t sc0;
    int low_bits, high_bits, q6_raw, q6_signed;
    float d_times_scale, element0;
};
static Trace TraceElement0(const uint8_t* base) {
    Trace t{};
    t.base = base;
    t.ql = base + offsetof(BlockQ6KLayout, ql);
    t.qh = base + offsetof(BlockQ6KLayout, qh);
    t.sc = (const int8_t*)(base + offsetof(BlockQ6KLayout, scales));
    t.dp = base + offsetof(BlockQ6KLayout, d);
    std::memcpy(&t.d_bits, t.dp, sizeof(t.d_bits));
    t.d_f32 = FP16(t.d_bits);
    t.ql0 = t.ql[0];
    t.qh0 = t.qh[0];
    t.sc0_raw = (uint8_t)t.sc[0];
    t.sc0 = t.sc[0];
    t.low_bits  = t.ql0 & 0x0F;
    t.high_bits = t.qh0 & 0x03;
    t.q6_raw  = t.low_bits | (t.high_bits << 4);
    t.q6_signed = t.q6_raw - 32;
    t.d_times_scale = t.d_f32 * (float)t.sc0;
    t.element0 = t.d_times_scale * (float)t.q6_signed;
    return t;
}

// C_local: the gguf_loader.cpp DequantQ6_K algorithm, transcribed, on a snapshot.
// element 0 is the first write of the first 128-chunk (l=0, which=0, is=0).
static void CLocalElement0(const uint8_t* base, int& q6_signed, float& d_f32,
                           int& sc0, float& out) {
    const uint8_t* ql = base + 0;
    const uint8_t* qh = base + 128;
    const int8_t* scales = (const int8_t*)(base + 192);
    d_f32 = FP16((uint16_t)(base[208] | (base[209] << 8)));
    sc0 = scales[0];
    const int8_t q1 = static_cast<int8_t>((ql[0] & 0x0F) | (((qh[0] >> 0) & 3u) << 4)) - 32;
    q6_signed = q1;
    out = d_f32 * (float)scales[0] * (float)q1;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    const GGUFTensorInfo* ti = nullptr;
    for (const auto& t : m->tensors)
        if (t.ggml_type == GGMLType::Q6_K && t.shape.size() == 2) { ti = &t; break; }
    if (!ti) { std::printf("NO_Q6K\n"); return 3; }
    auto view = loader.GetTensor(ti->name);
    if (!view) { std::printf("LOOKUP=FAIL\n"); return 4; }

    const uint8_t* live = view->data<uint8_t>();

    // ---- snapshot FIRST, before any decode runs ----
    uint8_t snap[210];
    std::memcpy(snap, live, sizeof(snap));

    std::printf("TENSOR=%s\n", ti->name.c_str());
    std::printf("LIVE_ADDR=%p  SNAP_ADDR=%p\n", (const void*)live, (const void*)snap);
    std::printf("BLOCK_SHA_LIVE_BEFORE=%016llx\n",
                (unsigned long long)Fnv1a64(live, 210));
    std::printf("BLOCK_SHA_SNAPSHOT   =%016llx\n",
                (unsigned long long)Fnv1a64(snap, 210));
    const bool liveEqSnapBytes = (Fnv1a64(live, 210) == Fnv1a64(snap, 210));
    std::printf("LIVE_EQUALS_SNAPSHOT_BYTES=%d\n", liveEqSnapBytes ? 1 : 0);

    // ---- raw bytes, independent of any decode ----
    std::printf("\n; --- raw bytes ---\n");
    std::printf("ql0=%02X\n", snap[0]);
    std::printf("qh0=%02X\n", snap[128]);
    std::printf("sc0=%02X\n", (unsigned)(uint8_t)snap[192]);
    uint16_t dBits; std::memcpy(&dBits, snap + 208, sizeof(dBits));
    std::printf("d_bits=%04X\n", dBits);

    // ---- A: live, B: snapshot ----
    const Trace ta = TraceElement0(live);
    const Trace tb = TraceElement0(snap);
    std::printf("\n; --- A = DIRECT FROM LIVE ---\n");
    std::printf("BASE_ADDR=%p QL_ADDR=%p QH_ADDR=%p SCALES_ADDR=%p D_ADDR=%p\n",
                (const void*)ta.base, (const void*)ta.ql, (const void*)ta.qh,
                (const void*)ta.sc, (const void*)ta.dp);
    std::printf("QL0_HEX=%02X QH0_HEX=%02X SCALE0_HEX=%02X SCALE0_SIGNED=%d\n",
                ta.ql0, ta.qh0, ta.sc0_raw, ta.sc0);
    std::printf("D_BITS_HEX=%04X D_FP32=%.9g\n", ta.d_bits, (double)ta.d_f32);
    std::printf("LOW_BITS=%d HIGH_BITS=%d Q6_RAW=%d Q6_SIGNED=%d\n",
                ta.low_bits, ta.high_bits, ta.q6_raw, ta.q6_signed);
    std::printf("D_TIMES_SCALE=%.9g\nELEMENT0=%.9g\n",
                (double)ta.d_times_scale, (double)ta.element0);

    std::printf("\n; --- B = DIRECT FROM SNAPSHOT ---\n");
    std::printf("QL0_HEX=%02X QH0_HEX=%02X SCALE0_HEX=%02X SCALE0_SIGNED=%d\n",
                tb.ql0, tb.qh0, tb.sc0_raw, tb.sc0);
    std::printf("D_BITS_HEX=%04X D_FP32=%.9g\n", tb.d_bits, (double)tb.d_f32);
    std::printf("LOW_BITS=%d HIGH_BITS=%d Q6_RAW=%d Q6_SIGNED=%d\n",
                tb.low_bits, tb.high_bits, tb.q6_raw, tb.q6_signed);
    std::printf("D_TIMES_SCALE=%.9g\nELEMENT0=%.9g\n",
                (double)tb.d_times_scale, (double)tb.element0);

    // ---- C_local: gguf_loader's own algorithm, transcribed, on the snapshot ----
    int c_q6 = 0, c_sc = 0; float c_d = 0, c_out = 0;
    CLocalElement0(snap, c_q6, c_d, c_sc, c_out);
    std::printf("\n; --- C_LOCAL = gguf_loader ALGORITHM ON SNAPSHOT ---\n");
    std::printf("D_FP32=%.9g SCALE0=%d Q6_SIGNED=%d\n", (double)c_d, c_sc, c_q6);
    std::printf("ELEMENT0=%.9g\n", (double)c_out);

    // ---- C: the real ToFloat32 path ----
    std::vector<float> dec;
    if (!view->ToFloat32(dec) || dec.empty()) { std::printf("TOFLOAT32=FAIL\n"); return 5; }
    const float c_prod = dec[0];
    std::printf("\n; --- C = PRODUCTION ToFloat32[0] ---\n");
    std::printf("ELEMENT0=%.9g\n", (double)c_prod);

    // ---- E: the actual kquant::GemvQ6K scalar kernel, same bytes, row 0 ----
    {
        const size_t cols = (size_t)ti->shape[0];
        const size_t rows = (size_t)ti->shape[1];
        std::vector<float> x(cols);
        for (size_t i = 0; i < cols; ++i) x[i] = 0.5f * std::sin(0.017f * (float)(i + 1));
        std::vector<float> yG(rows, 0.0f);
        kquant::GemvQ6K(live, x.data(), yG.data(), rows, cols);
        // independent dot of the production buffer row 0
        double prodDot = 0.0;
        for (size_t c = 0; c < cols; ++c) prodDot += (double)dec[c] * (double)x[c];
        std::printf("\n; --- E = kquant::GemvQ6K ROW 0 vs PRODUCTION ROW 0 ---\n");
        std::printf("GEMV_ROW0=%.9g\n", (double)yG[0]);
        std::printf("PRODUCTION_ROW0_DOT=%.9g\n", prodDot);
        std::printf("GEMV_EQ_PRODUCTION=%d\n",
                    std::fabs((double)yG[0] - prodDot) <= 1e-6 * std::max(1.0, std::fabs(prodDot)) ? 1 : 0);
        // per-element: does GemvQ6K's implied weight match the production buffer?
        double worstEl = 0.0; int firstBadEl = -1;
        for (size_t c = 0; c < cols; ++c) {
            const double prod = (double)dec[c];
            // recover what GemvQ6K used by differencing with x[c] dominant term is
            // not separable; instead report whether prod decodes consistently by
            // checking the block-0 elements it must equal.
            if (c < 256) {
                float w;
                // recompute via the trace machinery
                (void)w;
            }
        }
        std::printf("WorstElUnused=%.9g firstBad=%d\n", worstEl, firstBadEl);
    }

    // ---- mutation checks ----
    std::printf("\n; --- mutation ---\n");
    std::printf("BLOCK_HASH_BEFORE_DIRECT=%016llx\n",
                (unsigned long long)Fnv1a64(live, 210));
    const Trace ta2 = TraceElement0(live);
    std::printf("BLOCK_HASH_AFTER_DIRECT=%016llx\n",
                (unsigned long long)Fnv1a64(live, 210));
    (void)ta2;
    const uint64_t hBefore = Fnv1a64(live, 210);
    (void)view->ToFloat32(dec);
    const uint64_t hAfter = Fnv1a64(live, 210);
    std::printf("BLOCK_HASH_BEFORE_TOFLOAT=%016llx\n", (unsigned long long)hBefore);
    std::printf("BLOCK_HASH_AFTER_TOFLOAT =%016llx\n", (unsigned long long)hAfter);
    std::printf("LIVE_BLOCK_MUTATED=%d\n", (hBefore != hAfter) ? 1 : 0);
    std::printf("ALL_BASE_POINTERS_EQUAL=%d\n", (live == snap) ? 1 : 0);

    // ---- component equality + first difference ----
    const bool sameQl  = (ta.ql0 == tb.ql0);
    const bool sameQh  = (ta.qh0 == tb.qh0);
    const bool sameSc  = (ta.sc0 == tb.sc0);
    const bool sameD   = (ta.d_bits == tb.d_bits);
    const bool sameDF  = (ta.d_f32 == tb.d_f32);
    const bool sameQ6  = (ta.q6_signed == tb.q6_signed);
    const bool sameDS  = (ta.d_times_scale == tb.d_times_scale);
    const bool sameEl  = (ta.element0 == tb.element0);
    const bool aEqB    = sameQl && sameQh && sameSc && sameD && sameQ6 && sameEl;
    const bool bEqCloc = (tb.q6_signed == c_q6) && (tb.d_f32 == c_d) &&
                         (tb.sc0 == c_sc) && (tb.element0 == c_out);
    const bool bEqProd = (tb.element0 == c_prod);

    std::printf("\n; --- certificate ---\n");
    std::printf("SAME_QL0=%d SAME_QH0=%d SAME_SCALE0=%d SAME_D_BITS=%d\n",
                sameQl, sameQh, sameSc, sameD);
    std::printf("SAME_D_FP32=%d SAME_Q6_SIGNED=%d SAME_D_X_SCALE=%d SAME_ELEMENT0=%d\n",
                sameDF, sameQ6, sameDS, sameEl);
    std::printf("DIRECT_LIVE_EQ_DIRECT_SNAPSHOT=%d\n", aEqB ? 1 : 0);
    std::printf("DIRECT_SNAPSHOT_EQ_C_LOCAL=%d\n", bEqCloc ? 1 : 0);
    std::printf("DIRECT_SNAPSHOT_EQ_TOFLOAT=%d\n", bEqProd ? 1 : 0);

    const char* first = "NONE";
    if (!liveEqSnapBytes)      first = "BLOCK_BYTES";
    else if (!aEqB)           first = "BASE_POINTER_OR_MUTATION";
    else if (!bEqCloc) {
        if (tb.q6_signed != c_q6)   first = "Q6_COMBINATION";
        else if (tb.d_f32 != c_d)   first = "D_BITS_OR_FP16_CONVERSION";
        else if (tb.sc0 != c_sc)    first = "SCALE_READ";
        else                         first = "FINAL_ARITHMETIC";
    } else if (!bEqProd) {
        first = "HARNESS_OR_TOFLT_INVOCATION";
    }
    std::printf("FIRST_DIFFERENCE=%s\n", first);
    return 0;
}
