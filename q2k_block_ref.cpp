// q2k_block_ref.cpp — RAWRXD_LAYER0_ATTN_BISECT_003  PATH_C
//
// INDEPENDENT RAW Q2_K REFERENCE. Shares ONLY raw tensor bytes with production.
// It does NOT include LinearW, the grouped GEMV, the production Q2_K decoder,
// production block structs, or any SIMD helper. That is deliberate: PATH_A
// (grouped GEMV) and PATH_B (LinearW) both measured BAD, so any shared
// production decode could inherit the same defect and falsely agree with them.
//
// PATH_C interrogates ONE 84-byte block upward from raw bytes:
//   C0  ADDRESS IDENTITY   stride + field deltas
//   C1  FP16 D/DMIN        raw bits -> fp32, before any multiplication
//   C2  SINGLE WEIGHT      6-bit scale unpack + 2-bit quant reconstruction
// so the first failing cell names the root domain mechanically.
//
// Layout under test is the canonical block_q2_K, which is the REVERSE of Q4_K:
//   scales[16] @ 0..15 | qs[64] @ 16..79 | d @ 80..81 | dmin @ 82..83 | stride 84
// The Q4_K-style reading (d@0, dmin@2, scales@4) is printed alongside purely
// as a comparison, never used to produce the reference weight.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

static const char* MODEL =
    "F:\\OllamaModels\\_r1_iso\\03_llama32_3b\\llama3.2-3b-Q2_K.gguf";
static const char* TARGET = "blk.0.attn_q.weight";
static const size_t Q2K_BLOCK_BYTES = 84;

struct R {
    std::FILE* f = nullptr;
    bool bad = false;
    bool open(const char* p) { f = std::fopen(p, "rb"); return f != nullptr; }
    void close() { if (f) std::fclose(f); f = nullptr; }
    uint64_t pos() const { return f ? (uint64_t)_ftelli64(f) : 0; }
    bool seek64(uint64_t o) { if (!f) { bad = true; return false; }
                               return _fseeki64(f, (__int64)o, SEEK_SET) == 0; }
    bool read(void* d, size_t n) { if (!f) { bad = true; return false; }
                                   if (!n) return true;
                                   if (std::fread(d, 1, n, f) != n) { bad = true; return false; }
                                   return true; }
    uint32_t u32() { uint32_t v = 0; read(&v, 4); return v; }
    uint64_t u64() { uint64_t v = 0; read(&v, 8); return v; }
    std::string str() { uint64_t n = u64(); std::string s;
        if (!n || n > (uint64_t)1 << 28) { bad = true; return s; }
        s.resize((size_t)n); if (!read(&s[0], (size_t)n)) s.clear(); return s; }
};

static void skipVal(R& r, uint32_t t) {
    switch (t) {
        case 0: case 1: case 7: { uint8_t v=0; r.read(&v,1); return; }
        case 2: case 3:         { uint16_t v=0; r.read(&v,2); return; }
        case 4: case 5: case 6: { uint32_t v=0; r.read(&v,4); return; }
        case 8: r.str(); return;
        case 9: { uint32_t et=r.u32(); uint64_t n=r.u64(); int w=0;
            switch (et) {
                case 0: case 1: case 7: w=1; break;
                case 2: case 3:         w=2; break;
                case 4: case 5: case 6: w=4; break;
                case 10: case 11: case 12: w=8; break;
                case 8: { for (uint64_t i=0;i<n;i++) r.str(); w=-1; } break;
                default: r.bad = true; return; }
            if (w>0) r.seek64(r.pos() + n*(uint64_t)w); return; }
        case 10: case 11: case 12: { uint64_t v=0; r.read(&v,8); return; }
        default: r.bad = true; return;
    }
}

// Independent fp16 -> fp32. Exact for normal, subnormal, inf and nan, and it
// cannot silently substitute a sentinel, so finiteness stays testable.
static float fp16ref(uint16_t h) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t e    = (h >> 10) & 0x1Fu;
    const uint32_t m    = h & 0x3FFu;
    uint32_t bits;
    if (e == 0) {
        if (m == 0) bits = sign;
        else { uint32_t sh = 0, mm = m;
               while ((mm & 0x400u) == 0) { mm <<= 1; ++sh; }
               mm &= 0x3FFu;
               bits = sign | ((127u - 14u - sh) << 23) | (mm << 13); }
    } else if (e == 0x1Fu) {
        bits = sign | 0x7F800000u | (m << 13);
    } else {
        bits = sign | ((e + 127u - 15u) << 23) | (m << 13);
    }
    float f; std::memcpy(&f, &bits, 4); return f;
}

// canonical get_scale_min_k2
static void k2(int j, const uint8_t* q, int* d, int* mn) {
    if (j < 4) { *d = q[j] & 63; *mn = q[j + 4] & 63; }
    else { *d = (q[j+4] & 0xF) | ((q[j-4] >> 6) << 4);
           *mn = (q[j+4] >> 4)   | ((q[j-0] >> 6) << 4); }
}

int main() {
    std::printf("RAWRXD_LAYER0_ATTN_BISECT_003  PATH_C_RAW_Q2K_REFERENCE\n");
    std::printf("MODEL=%s\nTENSOR=%s\n", MODEL, TARGET);
    std::printf("INDEPENDENCE=raw_bytes_only (no LinearW, no grouped GEMV, no production decode)\n");
    std::printf("ASSUMED_BLOCK_BYTES=%zu\n\n", Q2K_BLOCK_BYTES);

    R r;
    if (!r.open(MODEL)) { std::printf("OPEN_FAIL=1\n"); return 2; }
    char magic[4];
    if (!r.read(magic,4) || std::memcmp(magic,"GGUF",4)!=0) {
        std::printf("NOT_GGUF=1\n"); r.close(); return 2; }
    r.u32();
    const uint64_t nTensors = r.u64();
    const uint64_t nKV = r.u64();
    for (uint64_t i = 0; i < nKV && !r.bad; i++) { r.str(); skipVal(r, r.u32()); }

    bool found = false;
    uint64_t relOff = 0, ne0 = 0, ne1 = 0;
    uint32_t type = 0, nd = 0;
    for (uint64_t i = 0; i < nTensors && !r.bad; i++) {
        const std::string name = r.str();
        nd = r.u32();
        uint64_t dims[4] = {0,0,0,0};
        for (uint32_t j = 0; j < nd && j < 4; j++) dims[j] = r.u64();
        for (uint32_t j = 4; j < nd; j++) r.u64();
        const uint32_t ty = r.u32();
        const uint64_t ro = r.u64();
        if (name == TARGET) { found = true; relOff = ro; type = ty;
                              ne0 = dims[0]; ne1 = dims[1]; }
    }
    const uint64_t headerEnd = r.pos();
    r.close();
    if (!found) { std::printf("TENSOR_NOT_FOUND=1\n"); return 2; }

    const uint64_t dataStart = (headerEnd + 31) / 32 * 32;
    const uint64_t absOff = dataStart + relOff;

    std::printf("== C0 ADDRESS IDENTITY ==\n");
    std::printf("GGUF_TYPE=%u  (10=Q2_K)\n", type);
    std::printf("NE0=%llu NE1=%llu\n", (unsigned long long)ne0, (unsigned long long)ne1);
    std::printf("HEADER_END=%llu DATA_START=%llu REL_OFF=%llu\n",
        (unsigned long long)headerEnd, (unsigned long long)dataStart, (unsigned long long)relOff);
    std::printf("WEIGHT_PTR=%llu BLOCK0_PTR=%llu\n",
        (unsigned long long)absOff, (unsigned long long)absOff);
    const uint64_t blocksPerRow = ne0 ? ne0 / 256ull : 0;
    const uint64_t stride = blocksPerRow * Q2K_BLOCK_BYTES;
    std::printf("BLOCKS_PER_ROW=%llu BLOCK_STRIDE_ACTUAL=%llu (assumes %zu-byte blocks)\n",
        (unsigned long long)blocksPerRow, (unsigned long long)stride, Q2K_BLOCK_BYTES);
    std::printf("ROW1_PTR=%llu BLOCK1_DELTA=%llu\n",
        (unsigned long long)(absOff + stride), (unsigned long long)stride);

    uint8_t b[Q2K_BLOCK_BYTES];
    R rr; rr.open(MODEL);
    if (!rr.seek64(absOff) || !rr.read(b, Q2K_BLOCK_BYTES)) {
        std::printf("BLOCK_READ_FAIL=1\n"); rr.close(); return 2; }
    rr.close();

    std::printf("\n== RAW EVIDENCE ==\nRAW84=");
    for (size_t i = 0; i < Q2K_BLOCK_BYTES; i++) std::printf("%02x", b[i]);
    std::printf("\n");

    // Field deltas under the layout under test.
    const uint64_t dOff = 80, dminOff = 82, scOff = 0, qsOff = 16;
    std::printf("\n== C0 FIELD DELTAS (canonical block_q2_K) ==\n");
    std::printf("SCALES_DELTA=%llu QS_DELTA=%llu D_DELTA=%llu DMIN_DELTA=%llu\n",
        (unsigned long long)scOff, (unsigned long long)qsOff,
        (unsigned long long)dOff, (unsigned long long)dminOff);

    uint16_t dBits = 0, dmBits = 0;
    std::memcpy(&dBits,  b + dOff, 2);
    std::memcpy(&dmBits, b + dminOff, 2);
    const float d = fp16ref(dBits), dmn = fp16ref(dmBits);

    std::printf("\n== C1 FP16 D/DMIN (before any multiplication) ==\n");
    std::printf("RAW_D_BITS=0x%04X D_FP32=%.9g D_FINITE=%d\n",
        dBits, d, std::isfinite(d) ? 1 : 0);
    std::printf("RAW_DMIN_BITS=0x%04X DMIN_FP32=%.9g DMIN_FINITE=%d\n",
        dmBits, dmn, std::isfinite(dmn) ? 1 : 0);

    // Comparison only: what a Q4_K-style read of the same bytes would claim.
    uint16_t aliasD = 0, aliasDm = 0;
    std::memcpy(&aliasD,  b + 0, 2);
    std::memcpy(&aliasDm, b + 2, 2);
    std::printf("COMPARISON_ONLY_Q4K_STYLE_D_BITS=0x%04X -> %.9g\n",
        aliasD, fp16ref(aliasD));
    std::printf("COMPARISON_ONLY_Q4K_STYLE_DMIN_BITS=0x%04X -> %.9g\n",
        aliasDm, fp16ref(aliasDm));

    std::printf("\n== C2 SINGLE WEIGHT RECONSTRUCTION ==\n");
    const uint8_t* sc = b + scOff;
    const uint8_t* qs = b + qsOff;
    int sc0 = 0, mn0 = 0;
    k2(0, sc, &sc0, &mn0);
    const int q0 = qs[0] & 3;
    const float w0 = d * (float)sc0 * (float)q0 - dmn * (float)mn0;
    std::printf("SCALE6_RAW_0=0x%02X SCALE6_RAW_1=0x%02X\n", sc[0], sc[1]);
    std::printf("SCALE0=%d MIN0=%d\n", sc0, mn0);
    std::printf("Q_PACKED_BYTE0=0x%02X Q_VALUE=%d\n", qs[0], q0);
    std::printf("WEIGHT_REF_ELEMENT0=%.9g FINITE=%d\n", w0, std::isfinite(w0) ? 1 : 0);

    // A whole-block magnitude census so one bad block cannot hide in one element.
    double mn = 0, mx = 0, absSum = 0;
    int   nnz = 0, bad = 0;
    const int groupsPerBlock = 8;
    for (int g = 0; g < groupsPerBlock; g++) {
        int s = 0, m = 0;
        k2(g, sc, &s, &m);
        const uint8_t* q = qs + (g >> 1) * 32;
        const int sh = (g & 1) ? 2 : 0;
        for (int l = 0; l < 32; l++) {
            const int qv = (q[l] >> sh) & 3;
            const float w = d * (float)s * (float)qv - dmn * (float)m;
            if (!std::isfinite(w)) ++bad;
            if (w != 0.0f) ++nnz;
            absSum += std::fabs((double)w);
            if (g == 0 && l == 0) { mn = w; mx = w; }
        }
    }
    std::printf("BLOCK_ELEMENT_COUNT=256 NONFINITE=%d NONZERO=%d\n", bad, nnz);
    std::printf("BLOCK_ABS_SUM=%.9g  (d=%.6g dmin=%.6g scale0=%d min0=%d)\n",
        absSum, d, dmn, sc0, mn0);

    std::printf("\n== VERDICT DOMAIN ==\n");
    const bool saneD = std::isfinite(d) && std::isfinite(dmn) &&
                       d > 0.0f && dmn > 0.0f && d < 1.0f && dmn < 1.0f;
    if (!saneD) {
        std::printf("C1_FAIL -> FP16_D_DMIN_OR_BLOCK_BASE_ROOT\n");
        std::printf("NOTE: if D_DELTA/STRIDE are canonical but these bits are absurd,\n");
        std::printf("      the block base or weight pointer is wrong, not the field offset.\n");
    } else if (bad > 0 || nnz == 0) {
        std::printf("C2_FAIL -> Q2K_SCALE_OR_QUANT_UNPACK_ROOT\n");
    } else {
        std::printf("C0_C1_C2_PASS -> raw block is interpretable; divergence must lie\n");
        std::printf("             in the PRODUCTION dequant/GEMV kernel (PATH_C good, A/B bad)\n");
    }
    std::printf("TPS_CLAIM=HOLD\n");
    return 0;
}
