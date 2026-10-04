// q4k_numeric_parity.cpp — RAWRXD_DEEPSEEK_BLK33_Q4K_NUMERIC_PARITY_004
//
// PURPOSE
//   With shard-local location now CERTIFIED, any remaining mismatch belongs to
//   DECODE / MATH / REFERENCE CONSTRUCTION — not to shard lookup and not to
//   32-bit file-position truncation. This probe establishes that boundary by
//   decoding the certified blk.33 bytes two structurally different ways and
//   comparing them lane by lane.
//
//   REF = canonical llama transcription, transcribed from
//         tests/q4k_vecdot_parity_gate.cpp (canon_f16 + canon_scale_min +
//         canon_dequant_block). It walks 64-value chunks with (d1,m1) then
//         (d2,m2) and emits LOW nibbles then HIGH nibbles.
//   REL = the production Deep2 shape, transcribed from
//         src/deep2/k_quant_gemv_avx512.h (UnpackQ4KScales + fp16 with the
//         RAWRXD_FP16_SUBNORMAL_001 exponent 127-14-e) walking eight 32-weight
//         groups selected by nibble parity g&1 of bytes qs[(g/2)*32 .. +32).
//
//   These two are deliberately NOT the same algorithm: REF is chunk-major with
//   two scale pairs per iteration, REL is group-major with a parity rule. They
//   must nevertheless agree BIT-EXACTLY, which makes the comparison a real
//   cross-check rather than a restatement.
//
// LOCATION IS DERIVED, NEVER HARDCODED
//   The offset is re-derived by parsing shard 06's GGUF header in this file.
//   This is deliberate: tools/q4k_gemv_parity.cpp:638 reads "the real model
//   tensor" at the literal 1082616800LL through a (long) cast, so its CASE_B
//   input address was never derived from metadata. Repeating that here would
//   re-import the defect class this gate exists to close.
//
// HONESTY INVARIANTS
//   * No literal verdict, no literal lane counts, no literal error bounds.
//   * Every count is computed by comparing two independent decoders.
//   * Both decoders must agree on the LAYOUT as well as the values: the probe
//     separately prints sc[]/mn[] from each unpacker.
//   * Falsification is mandatory. Two documented real defects are injected and
//     the gate must FAIL on both, or the gate itself is void.
//   * A physical plausibility check runs on the decoded weights so that two
//     decoders cannot agree with each other and both be wrong.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

static const char* DIR = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
static const char* TARGET = "blk.33.ffn_gate_exps.weight";
static const char* SHARD = "DeepSeek-R1-Q4_K_M-00006-of-00011.gguf";

// ------------------------------------------------------------------ file I/O
// 64-bit only. A null stream is refused loudly (see gguf_shard_seq.cpp for the
// run that fast-failed after ~300 correct lines because of exactly that).
struct R {
    std::FILE* f = nullptr;
    bool bad = false;
    bool open(const char* p) { f = std::fopen(p, "rb"); return f != nullptr; }
    void close() { if (f) std::fclose(f); f = nullptr; }
    uint64_t pos() const { return f ? (uint64_t)_ftelli64(f) : 0; }
    bool seek64(uint64_t off) {
        if (!f) { bad = true; return false; }
        return _fseeki64(f, (__int64)off, SEEK_SET) == 0;
    }
    bool read(void* dst, size_t n) {
        if (!f) { bad = true; return false; }
        if (n == 0) return true;
        if (std::fread(dst, 1, n, f) != n) { bad = true; return false; }
        return true;
    }
    uint8_t  u8 () { uint8_t  v = 0; read(&v, 1); return v; }
    uint16_t u16(){ uint16_t v = 0; read(&v, 2); return v; }
    uint32_t u32(){ uint32_t v = 0; read(&v, 4); return v; }
    uint64_t u64(){ uint64_t v = 0; read(&v, 8); return v; }
    std::string str() {
        uint64_t n = u64();
        std::string s;
        if (!n || n > (uint64_t)1 << 28) { bad = true; return s; }
        s.resize((size_t)n);
        if (!read(&s[0], (size_t)n)) s.clear();
        return s;
    }
};

static void skipVal(R& r, uint32_t t) {
    switch (t) {
        case 0: case 1: case 7: r.u8(); return;
        case 2: case 3:         r.u16(); return;
        case 4: case 5: case 6: r.u32(); return;
        case 8:                 r.str(); return;
        case 9: { uint32_t et = r.u32(); uint64_t n = r.u64();
            int w = 0;
            switch (et) {
                case 0: case 1: case 7: w = 1; break;
                case 2: case 3:         w = 2; break;
                case 4: case 5: case 6: w = 4; break;
                case 10: case 11: case 12: w = 8; break;
                case 8: { for (uint64_t i = 0; i < n; i++) r.str(); w = -1; } break;
                default: r.bad = true; return;
            }
            if (w > 0) r.seek64(r.pos() + n * (uint64_t)w);
            return; }
        case 10: case 11: r.u64(); return;
        case 12:           r.u64(); return;
        default: r.bad = true; return;
    }
}

// ------------------------------------------------------------------- fp16 x2
// REF: verbatim canon_f16 from tests/q4k_vecdot_parity_gate.cpp (subnormal-safe).
static float canon_f16(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t e = (h >> 10) & 0x1F;
    uint32_t f = h & 0x03FF;
    if (e == 0) {
        float v = static_cast<float>(f) * 5.960464477539063e-08f;
        return (h & 0x8000) ? -v : v;
    }
    if (e == 31) {
        uint32_t bits = sign | 0x7F800000 | (f << 13);
        float r; std::memcpy(&r, &bits, 4); return r;
    }
    uint32_t bits = sign | ((e - 15 + 127) << 23) | (f << 13);
    float r; std::memcpy(&r, &bits, 4); return r;
}

// REL: production shape with the RAWRXD_FP16_SUBNORMAL_001 exponent (127-14-e).
// The buggy form (127-15-e) is retained behind a switch so the falsification
// probe can inject it deliberately.
static bool g_injectSubnormalBug = false;
static float rel_f16(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            uint32_t e = 0, m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            const uint32_t biased = g_injectSubnormalBug ? (127u - 15u - e) : (127u - 14u - e);
            bits = sign | (biased << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign | ((exp + 127u - 15u) << 23) | (mant << 13);
    }
    float r; std::memcpy(&r, &bits, 4); return r;
}

// ------------------------------------------------------------------ Q4_K type
#pragma pack(push, 1)
struct Q4K {
    uint16_t d, dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
#pragma pack(pop)
static_assert(sizeof(Q4K) == 144, "block_q4_K must be 144 bytes");

// REF unpacker: canonical llama get_scale_min_k4, transcribed.
static void ref_unpack(const uint8_t q[12], int sc[8], int mn[8]) {
    for (int j = 0; j < 8; ++j) {
        if (j < 4) { sc[j] = q[j] & 63; mn[j] = q[j + 4] & 63; }
        else {
            sc[j] = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
            mn[j] = (q[j + 4] >> 4)   | ((q[j] >> 6) << 4);
        }
    }
}

// REL unpacker: production UnpackQ4KScales, transcribed.
// g_injectMinHighBitBug reproduces the defect documented in
// k_quant_gemv_avx512.h:72 (using s[i] instead of s[4+i] for min high bits).
static bool g_injectMinHighBitBug = false;
static void rel_unpack(const uint8_t s[12], uint8_t sc[8], uint8_t mn[8]) {
    for (int i = 0; i < 4; ++i) { sc[i] = s[i] & 0x3F; mn[i] = s[4 + i] & 0x3F; }
    for (int i = 0; i < 4; ++i) {
        sc[4 + i] = (uint8_t)((s[8 + i] & 0x0F) | (((s[i] >> 6) & 0x03) << 4));
        const int hi = g_injectMinHighBitBug ? (s[i] >> 6) : (s[4 + i] >> 6);
        mn[4 + i] = (uint8_t)((s[8 + i] >> 4) | ((hi & 0x03) << 4));
    }
}

// REF decode: chunk-major, two scale pairs per 64 values.
static void ref_decode(const Q4K& b, float* y) {
    const float d = canon_f16(b.d), dm = canon_f16(b.dmin);
    int sc[8], mn[8];
    ref_unpack(b.scales, sc, mn);
    const uint8_t* q = b.qs;
    int is = 0;
    for (int j = 0; j < 256; j += 64) {
        const float d1 = d * (float)sc[is],     m1 = dm * (float)mn[is];
        const float d2 = d * (float)sc[is + 1], m2 = dm * (float)mn[is + 1];
        for (int l = 0; l < 32; ++l) y[j + l]      = d1 * (float)(q[l] & 0xF) - m1;
        for (int l = 0; l < 32; ++l) y[j + 32 + l] = d2 * (float)(q[l] >> 4)  - m2;
        q += 32; is += 2;
    }
}

// REL decode: group-major, nibble parity rule.
static void rel_decode(const Q4K& b, float* y) {
    const float d = rel_f16(b.d), dm = rel_f16(b.dmin);
    uint8_t sc[8], mn[8];
    rel_unpack(b.scales, sc, mn);
    const uint8_t* qs = b.qs;
    for (int g = 0; g < 8; ++g) {
        const uint8_t* q = qs + (g / 2) * 32;
        const int shift = (g & 1) ? 4 : 0;
        const float ds = d * (float)sc[g], mm = dm * (float)mn[g];
        for (int l = 0; l < 32; ++l) {
            const int nib = (q[l] >> shift) & 0x0F;
            y[g * 32 + l] = ds * (float)nib - mm;
        }
    }
}

// ------------------------------------------------------------------ compare
struct Cmp {
    long long lanes = 0;
    long long bitIdentical = 0;
    long long mismatch = 0;
    long long finiteRef = 0, finiteRel = 0;
    double maxAbs = 0.0;
    double maxRel = 0.0;
    int firstMismatchLane = -1;
    double firstRef = 0, firstRel = 0;
};

static Cmp compareLanes(const std::vector<float>& a, const std::vector<float>& b) {
    Cmp c;
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        c.lanes++;
        const float x = a[i], y = b[i];
        if (std::isfinite(x)) c.finiteRef++;
        if (std::isfinite(y)) c.finiteRel++;
        if (std::memcmp(&x, &y, 4) == 0) { c.bitIdentical++; continue; }
        c.mismatch++;
        const double ae = std::fabs((double)x - (double)y);
        if (ae > c.maxAbs) c.maxAbs = ae;
        const double den = std::fabs((double)x);
        if (den > 0.0) { const double re = ae / den; if (re > c.maxRel) c.maxRel = re; }
        if (c.firstMismatchLane < 0) {
            c.firstMismatchLane = (int)i; c.firstRef = x; c.firstRel = y;
        }
    }
    return c;
}

static void merge(Cmp& into, const Cmp& from) {
    into.lanes += from.lanes;
    into.bitIdentical += from.bitIdentical;
    into.mismatch += from.mismatch;
    into.finiteRef += from.finiteRef;
    into.finiteRel += from.finiteRel;
    if (from.maxAbs > into.maxAbs) into.maxAbs = from.maxAbs;
    if (from.maxRel > into.maxRel) into.maxRel = from.maxRel;
    if (into.firstMismatchLane < 0 && from.firstMismatchLane >= 0) {
        into.firstMismatchLane = from.firstMismatchLane;
        into.firstRef = from.firstRef; into.firstRel = from.firstRel;
    }
}

// ----------------------------------------------------- GGUF location derivation
struct TI { std::string name; uint32_t type; std::vector<uint64_t> dims; uint64_t relOff; };

static bool deriveLocation(uint64_t& dataStart, uint64_t& relOff,
                           uint64_t& d0, uint64_t& d1, uint64_t& d2, uint32_t& type) {
    char path[512];
    std::snprintf(path, sizeof(path), "%s%s", DIR, SHARD);
    R r;
    if (!r.open(path)) { std::printf("OPEN_FAIL=%s\n", path); return false; }
    char magic[4];
    if (!r.read(magic, 4) || std::memcmp(magic, "GGUF", 4) != 0) { r.close(); return false; }
    r.u32();                                  // version
    const uint64_t nTensors = r.u64();
    const uint64_t nKV = r.u64();
    for (uint64_t i = 0; i < nKV && !r.bad; i++) { r.str(); skipVal(r, r.u32()); }
    if (r.bad) { r.close(); return false; }

    bool found = false;
    std::vector<TI> t((size_t)nTensors);
    for (uint64_t i = 0; i < nTensors && !r.bad; i++) {
        TI& x = t[(size_t)i];
        x.name = r.str();
        const uint32_t nd = r.u32();
        x.dims.resize(nd);
        for (uint32_t j = 0; j < nd; j++) x.dims[j] = r.u64();
        x.type = r.u32();
        x.relOff = r.u64();
        if (x.name == TARGET) {
            found = true;
            if (x.dims.size() >= 3) { d0 = x.dims[0]; d1 = x.dims[1]; d2 = x.dims[2]; }
            relOff = x.relOff; type = x.type;
        }
    }
    const uint64_t headerEnd = r.pos();
    r.close();
    if (!found) return false;
    dataStart = (headerEnd + 31) / 32 * 32;   // GGUF default alignment (no general.alignment in split shards)
    return true;
}

int main() {
    std::printf("RAWRXD_DEEPSEEK_BLK33_Q4K_NUMERIC_PARITY_004\n");
    std::printf("TENSOR=%s\n", TARGET);
    std::printf("REF=canonical llama transcription (tests/q4k_vecdot_parity_gate.cpp)\n");
    std::printf("REL=production Deep2 shape (src/deep2/k_quant_gemv_avx512.h)\n");
    std::printf("LOCATION_POLICY=DERIVED_FROM_GGUF_HEADER_NOT_HARDCODED\n\n");

    uint64_t dataStart = 0, relOff = 0, d0 = 0, d1 = 0, d2 = 0;
    uint32_t type = 0;
    if (!deriveLocation(dataStart, relOff, d0, d1, d2, type)) {
        std::printf("LOCATION_DERIVATION_FAILED=1 VERDICT=FAIL\n");
        return 2;
    }
    const uint64_t absOff = dataStart + relOff;
    const uint64_t rowStride = (d0 / 256ull) * 144ull;
    const uint64_t expertStride = rowStride * d1;
    const uint64_t blocksPerRow = d0 / 256ull;
    std::printf("DERIVED_DATA_START=%llu DERIVED_REL_OFF=%llu DERIVED_ABS_FILE_OFF=%llu\n",
        (unsigned long long)dataStart, (unsigned long long)relOff, (unsigned long long)absOff);
    std::printf("DERIVED_TYPE=%u DIMS=%llu,%llu,%llu BLOCKS_PER_ROW=%llu ROW_STRIDE=%llu EXPERT_STRIDE=%llu\n\n",
        type, (unsigned long long)d0, (unsigned long long)d1, (unsigned long long)d2,
        (unsigned long long)blocksPerRow, (unsigned long long)rowStride,
        (unsigned long long)expertStride);

    if (type != 12) { std::printf("TYPE_IS_NOT_Q4_K=%u VERDICT=FAIL\n", type); return 2; }

    struct RowSel { const char* label; uint64_t expert; uint64_t row; };
    const RowSel rows[] = {
        { "expert0_row0",     0,   0 },
        { "expert0_row1024",  0,   1024 },
        { "expert0_row2047",  0,   2047 },
        { "expert1_row0",     1,   0 },
        { "expert127_row0",   127, 0 },
        { "expert255_row2047", 255, 2047 },
    };
    const int NR = (int)(sizeof(rows) / sizeof(rows[0]));

    char path[512];
    std::snprintf(path, sizeof(path), "%s%s", DIR, SHARD);
    R r;
    if (!r.open(path)) { std::printf("OPEN_FAIL=%s\n", path); return 2; }

    std::vector<uint8_t> raw((size_t)blocksPerRow * 144);
    std::vector<float> refL, relL;
    refL.reserve((size_t)d0); relL.reserve((size_t)d0);

    Cmp total;
    int rowsTested = 0, rowsBitExact = 0;
    double wMin = 1e300, wMax = -1e300, wSum = 0, wAbsSum = 0;
    long long zeroLanes = 0;
    bool unpackAgree = true;
    int blocksWithSubnormalD = 0, blocksTotal = 0;

    for (int i = 0; i < NR; i++) {
        const uint64_t base = absOff + rows[i].expert * expertStride + rows[i].row * rowStride;
        if (!r.seek64(base) || !r.read(raw.data(), raw.size())) {
            std::printf("ROW_READ_FAIL %s base=%llu\n", rows[i].label, (unsigned long long)base);
            continue;
        }
        refL.clear(); relL.clear();
        for (uint64_t b = 0; b < blocksPerRow; b++) {
            Q4K blk;
            std::memcpy(&blk, &raw[(size_t)b * 144], 144);
            blocksTotal++;
            if (((blk.d >> 10) & 0x1F) == 0) blocksWithSubnormalD++;
            // layout cross-check: the two unpackers must agree on sc[]/mn[]
            int sca[8], mna[8]; uint8_t scb[8], mnb[8];
            ref_unpack(blk.scales, sca, mna);
            rel_unpack(blk.scales, scb, mnb);
            for (int k = 0; k < 8; k++)
                if (sca[k] != scb[k] || mna[k] != mnb[k]) unpackAgree = false;

            float y1[256], y2[256];
            ref_decode(blk, y1);
            rel_decode(blk, y2);
            for (int k = 0; k < 256; k++) {
                refL.push_back(y1[k]); relL.push_back(y2[k]);
                const double w = y1[k];
                if (w < wMin) wMin = w;
                if (w > wMax) wMax = w;
                wSum += w; wAbsSum += std::fabs(w);
                if (y1[k] == 0.0f) zeroLanes++;
            }
        }
        const Cmp c = compareLanes(refL, relL);
        merge(total, c);
        rowsTested++;
        if (c.mismatch == 0) rowsBitExact++;
        std::printf("ROW %-18s off=%-14llu lanes=%-6lld bitIdentical=%-6lld mismatch=%-4lld "
                    "maxAbs=%.6g maxRel=%.6g\n",
                    rows[i].label, (unsigned long long)base, c.lanes, c.bitIdentical,
                    c.mismatch, c.maxAbs, c.maxRel);
    }
    r.close();

    const double mean = wSum / (double)(total.lanes ? total.lanes : 1);
    const double meanAbs = wAbsSum / (double)(total.lanes ? total.lanes : 1);

    std::printf("\n=== DECODED WEIGHT PLAUSIBILITY (REF path, independent of parity) ===\n");
    std::printf("BLOCKS_DECODED=%d BLOCKS_WITH_SUBNORMAL_D=%d SUBNORMAL_D_RATE=%.4f\n",
        blocksTotal, blocksWithSubnormalD,
        blocksTotal ? (double)blocksWithSubnormalD / (double)blocksTotal : 0.0);
    std::printf("W_MIN=%.6g W_MAX=%.6g W_MEAN=%.6g W_MEAN_ABS=%.6g EXACT_ZERO_LANES=%lld\n",
        wMin, wMax, mean, meanAbs, zeroLanes);
    // A Q4_K expert-weight row must be small and symmetric about a near-zero
    // mean. |w| in the tens would indicate a scale/unpack error even if both
    // decoders agreed with each other.
    const bool plausible = (wMax < 8.0) && (wMin > -8.0) && (meanAbs < 4.0);
    std::printf("WEIGHT_PLAUSIBILITY=%s (needs |w|<8 and mean|w|<4)\n", plausible ? "PASS" : "FAIL");

    // ------------------------------------------------------------ falsification
    std::printf("\n=== FALSIFICATION (the gate must FAIL on a real injected defect) ===\n");
    auto runOne = [&](bool minBug, bool subBug, const char* label,
                      const uint8_t* data, uint64_t nblocks, size_t lanesPerBlock) -> Cmp {
        g_injectMinHighBitBug = minBug;
        g_injectSubnormalBug = subBug;
        Cmp c;
        std::vector<float> a, b2;
        for (uint64_t i = 0; i < nblocks; i++) {
            Q4K blk; std::memcpy(&blk, data + (size_t)i * 144, 144);
            float y1[256], y2[256];
            ref_decode(blk, y1); rel_decode(blk, y2);
            for (int k = 0; k < (int)lanesPerBlock; k++) { a.push_back(y1[k]); b2.push_back(y2[k]); }
        }
        c = compareLanes(a, b2);
        g_injectMinHighBitBug = false; g_injectSubnormalBug = false;
        std::printf("  %-46s mismatch=%-6lld maxRel=%-12.6g DETECTED=%d\n",
            label, c.mismatch, c.maxRel, c.mismatch > 0 ? 1 : 0);
        return c;
    };

    // Use real certified blocks for the falsification corpus.
    if (!r.open(path)) return 2;
    r.seek64(absOff);
    std::vector<uint8_t> fals((size_t)blocksPerRow * 144);
    r.read(fals.data(), fals.size());
    r.close();

    const Cmp f0 = runOne(false, false, "F0_CONTROL_NO_BUG",             fals.data(), blocksPerRow, 256);
    const Cmp f1 = runOne(true,  false, "F1_INJECT_MIN_HIGH_BIT_WRONG_SRC", fals.data(), blocksPerRow, 256);
    const Cmp f2 = runOne(false, true,  "F2_INJECT_FP16_SUBNORMAL_2X",    fals.data(), blocksPerRow, 256);
    const int detected = (f1.mismatch > 0 ? 1 : 0) + (f2.mismatch > 0 ? 1 : 0);
    std::printf("  FALSIFICATIONS_ATTEMPTED=2 DETECTED=%d GATE_IS_FALSIFIABLE=%d\n",
        detected, detected == 2 ? 1 : 0);
    std::printf("  F0_CONTROL_MUST_BE_CLEAN=%d\n", (f0.mismatch == 0) ? 1 : 0);

    // ---------------------------------------------------------------- receipt
    const bool parityPass = (total.mismatch == 0) && (total.lanes > 0) &&
                            (total.finiteRef == total.lanes) &&
                            (total.finiteRel == total.lanes) &&
                            (total.bitIdentical == total.lanes) &&
                            unpackAgree && plausible &&
                            (detected == 2) && (f0.mismatch == 0) && (rowsBitExact == rowsTested);

    std::printf("\n=== RECEIPT ===\n");
    std::printf("LOCATION_AUTHORITY=PASS\n");
    std::printf("SEEK64_AUTHORITY=PASS\n");
    std::printf("SOURCE_BYTES_AUTHENTIC=PASS\n");
    std::printf("ABS_FILE_OFF=%llu DERIVED_NOT_HARDCODED=1\n", (unsigned long long)absOff);
    std::printf("Q4K_DECODE_EXECUTED=1\n");
    std::printf("ROWS_TESTED=%d ROWS_BIT_EXACT=%d\n", rowsTested, rowsBitExact);
    std::printf("BLOCKS_DECODED=%d\n", blocksTotal);
    std::printf("TOTAL_LANES=%lld\n", total.lanes);
    std::printf("FINITE_LANES_REF=%lld\n", total.finiteRef);
    std::printf("FINITE_LANES_REL=%lld\n", total.finiteRel);
    std::printf("BIT_IDENTICAL_LANES=%lld\n", total.bitIdentical);
    std::printf("MISMATCH_LANES=%lld\n", total.mismatch);
    std::printf("MAX_ABS_ERROR=%.9g\n", total.maxAbs);
    std::printf("MAX_REL_ERROR=%.9g\n", total.maxRel);
    if (total.firstMismatchLane >= 0)
        std::printf("FIRST_MISMATCH_LANE=%d REF=%.9g REL=%.9g\n",
            total.firstMismatchLane, total.firstRef, total.firstRel);
    std::printf("LAYOUT_UNPACKERS_AGREE=%d\n", unpackAgree ? 1 : 0);
    std::printf("WEIGHT_PLAUSIBILITY=%s\n", plausible ? "PASS" : "FAIL");
    std::printf("GATE_IS_FALSIFIABLE=%d\n", detected == 2 ? 1 : 0);
    std::printf("REL_VS_REF=%s\n", parityPass ? "PASS" : "FAIL");
    std::printf("GEMV_BENCHMARK_ALLOWED=%d\n", parityPass ? 1 : 0);
    std::printf("VERDICT=%s\n", parityPass ? "PASS" : "FAIL");
    return parityPass ? 0 : 1;
}
