// q2k_block_census.cpp — RAWRXD_Q2K_BLOCK_CORRUPTION_CENSUS_001
//
// WHY THIS EXISTS
//   RAWRXD_Q2K_SCALE_WIDTH_PRIMARY was falsified: both the 4-bit and 6-bit
//   unpack arms produce ~7e6 / ~2.9e7 on a tensor whose independent decode
//   (q2k_block_ref.cpp) yields element0 = -0.852 and d = 0.00706. Neither
//   arm is correct and the worst case that correct d/dmin permits is ~8.6e3,
//   so the ~1e6-1e7 magnitudes cannot come from scale arithmetic on good data.
//
//   RAWRXD_Q6K_BLOCK_SKIP_FAST_001 measured 47,418 blocks with non-finite fp16
//   scales in token_embd.weight of the SAME MODEL FAMILY. q2k_block_ref.cpp
//   validated attn_q BLOCK 0 ONLY — 1 block out of 36,864. If a meaningful
//   fraction of the remaining blocks carry garbage fp16 d, then every downstream
//   decode was correct arithmetic over corrupt input, and "block 0 is clean"
//   was true by luck.
//
//   This settles it with a count rather than an inference.
//
// SHARES NOTHING WITH PRODUCTION
//   Raw file bytes + a from-spec fp16 reader. No QuantKernelRegistry, no
//   LinearW, no GEMV, no engine headers. Independent by construction.
//
// OUTPUT
//   BLOCKS_TOTAL, BLOCKS_NONFINITE_D/DMIN, BLOCKS_ABSURD_D, FIRST_BAD_INDEX,
//   ROWS_WITH_>=1_BAD_BLOCK, and the fraction of rows poisoned. That last
//   number decides whether the Q2_K investigation was ever a decoder defect.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

static const char* MODEL =
    "F:\\OllamaModels\\_r1_iso\\03_llama32_3b\\llama3.2-3b-Q2_K.gguf";
static const size_t Q2K_BYTES = 84;   // scales[16] qs[64] d dmin

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

// Independent fp16 -> double. Reports finiteness rather than substituting a
// sentinel, because "non-finite" is the measurement.
static double fp16(uint16_t h, bool* finite, bool* absurd) {
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t e    = (h >> 10) & 0x1Fu;
    const uint32_t m    = h & 0x3FFu;
    double v;
    *finite = true; *absurd = false;
    if (e == 0) {
        if (m == 0) { v = 0.0; }
        else { uint32_t sh = 0, mm = m;
               while ((mm & 0x400u) == 0) { mm <<= 1; ++sh; }
               mm &= 0x3FFu;
               v = (double)(mm << 13) * 5.9604644775390625e-08; }
    } else if (e == 0x1Fu) {
        *finite = false; v = (m == 0) ? INFINITY : NAN;
    } else {
        v = (1.0 + (double)m / 1024.0) * std::pow(2.0, (double)((int)e - 15));
        // A K-quant super-scale is O(1e-3..1e-1). Anything past 1e3 is garbage.
        if (v > 1e3 || v < -1e3) *absurd = true;
    }
    return sign ? -v : v;
}

struct TensorInfo {
    bool found = false;
    uint64_t relOff = 0, ne0 = 0, ne1 = 0;
    uint32_t type = 0;
};

static TensorInfo find(R& r, const char* want, uint64_t nTensors) {
    TensorInfo t;
    for (uint64_t i = 0; i < nTensors && !r.bad; i++) {
        const std::string name = r.str();
        const uint32_t nd = r.u32();
        uint64_t dims[4] = {0,0,0,0};
        for (uint32_t j = 0; j < nd && j < 4; j++) dims[j] = r.u64();
        for (uint32_t j = 4; j < nd; j++) r.u64();
        const uint32_t ty = r.u32();
        const uint64_t ro = r.u64();
        if (name == want) {
            t.found = true; t.relOff = ro; t.type = ty;
            t.ne0 = dims[0]; t.ne1 = dims[1];
        }
    }
    return t;
}

int main() {
    std::printf("RAWRXD_Q2K_BLOCK_CORRUPTION_CENSUS_001\n");
    std::printf("MODEL=%s\n", MODEL);
    std::printf("INDEPENDENCE=raw bytes + from-spec fp16 only (no engine, no GEMV, no registry)\n");
    std::printf("CRITERION: d or dmin non-finite, or |value| > 1e3 = BAD BLOCK\n\n");

    R r;
    if (!r.open(MODEL)) { std::printf("OPEN_FAIL=1\n"); return 2; }
    char magic[4];
    if (!r.read(magic,4) || std::memcmp(magic,"GGUF",4)!=0) { std::printf("NOT_GGUF=1\n"); return 2; }
    r.u32();
    const uint64_t nTensors = r.u64();
    const uint64_t nKV = r.u64();
    for (uint64_t i = 0; i < nKV && !r.bad; i++) { r.str(); skipVal(r, r.u32()); }
    const uint64_t headerEnd = r.pos();

    const char* names[] = { "blk.0.attn_q.weight", "blk.0.attn_k.weight",
                            "blk.0.attn_v.weight", "blk.0.attn_output.weight",
                            "blk.0.ffn_gate.weight" };
    const int NT = 5;

    std::vector<TensorInfo> infos;
    // One pass to collect all of them (the reader is sequential).
    {
        R r2;
        r2.open(MODEL);
        r2.seek64(headerEnd - 0);   // not used; parse below instead
        r2.close();
    }
    // Re-parse properly from a fresh handle.
    r.close();
    {
        R p;
        p.open(MODEL);
        char m2[4]; p.read(m2,4); p.u32();
        const uint64_t nt = p.u64(); const uint64_t nk = p.u64();
        for (uint64_t i = 0; i < nk && !p.bad; i++) { p.str(); skipVal(p, p.u32()); }
        // Walk all tensors once, matching any of the wanted names.
        for (uint64_t i = 0; i < nt && !p.bad; i++) {
            const std::string name = p.str();
            const uint32_t nd = p.u32();
            uint64_t dims[4] = {0,0,0,0};
            for (uint32_t j = 0; j < nd && j < 4; j++) dims[j] = p.u64();
            for (uint32_t j = 4; j < nd; j++) p.u64();
            const uint32_t ty = p.u32();
            const uint64_t ro = p.u64();
            for (int k = 0; k < NT; k++) {
                if (name == names[k] && !infos[(size_t)k].found) {
                    infos[(size_t)k].found = true; infos[(size_t)k].relOff = ro;
                    infos[(size_t)k].type = ty;
                    infos[(size_t)k].ne0 = dims[0]; infos[(size_t)k].ne1 = dims[1];
                }
            }
        }
        const uint64_t hdr = p.pos();
        p.close();
        const uint64_t dataStart = (hdr + 31) / 32 * 32;

        for (int k = 0; k < NT; k++) {
            const TensorInfo& t = infos[(size_t)k];
            if (!t.found) { std::printf("%-30s NOT_FOUND\n", names[k]); continue; }
            const uint64_t rowStride = (t.ne0 / 256ull) * Q2K_BYTES;
            const uint64_t blocksPerRow = t.ne0 / 256ull;
            const uint64_t totalBlocks = blocksPerRow * t.ne1;
            std::printf("=== %s ===\n", names[k]);
            std::printf("  TYPE=%u ne0=%llu ne1=%llu row_bytes=%llu BLOCKS_TOTAL=%llu\n",
                        t.type, (unsigned long long)t.ne0, (unsigned long long)t.ne1,
                        (unsigned long long)rowStride, (unsigned long long)totalBlocks);

            R br; br.open(MODEL);
            const uint64_t base = dataStart + t.relOff;
            uint64_t badD = 0, badDmin = 0, badEither = 0, absurdD = 0;
            long long firstBad = -1, rowsWithBad = 0, rowsTotal = 0;
            double dMax = 0, dminMax = 0;
            std::vector<uint8_t> row((size_t)rowStride);
            for (uint64_t rr = 0; rr < t.ne1; ++rr) {
                if (!br.seek64(base + rr * rowStride) || !br.read(row.data(), row.size())) {
                    std::printf("  READ_FAIL at row %llu\n", (unsigned long long)rr); break;
                }
                rowsTotal++;
                bool rowBad = false;
                for (uint64_t b = 0; b < blocksPerRow; ++b) {
                    const uint8_t* p = &row[(size_t)b * Q2K_BYTES];
                    uint16_t db, mb;
                    std::memcpy(&db, p + 80, 2);
                    std::memcpy(&mb, p + 82, 2);
                    bool fd = false, fm = false, ad = false, am = false;
                    const double dv = fp16(db, &fd, &ad);
                    const double mv = fp16(mb, &fm, &am);
                    if (std::fabs(dv) > dMax) dMax = std::fabs(dv);
                    if (std::fabs(mv) > dminMax) dminMax = std::fabs(mv);
                    const bool bd = !fd || ad;
                    const bool bm = !fm || am;
                    if (bd) ++badD;
                    if (bm) ++badDmin;
                    if (bd || bm) {
                        ++badEither;
                        if (!rowBad) { rowBad = true; ++rowsWithBad; }
                        if (firstBad < 0) firstBad = (long long)(rr * blocksPerRow + b);
                    }
                    if (ad) ++absurdD;
                }
            }
            br.close();
            const double pctRows = rowsTotal ? (100.0 * rowsWithBad / rowsTotal) : 0.0;
            const double pctBlk  = totalBlocks ? (100.0 * badEither / totalBlocks) : 0.0;
            std::printf("  BLOCKS_BAD_D=%llu BLOCKS_BAD_DMIN=%llu BLOCKS_BAD_EITHER=%llu (%.4f%%)\n",
                        (unsigned long long)badD, (unsigned long long)badDmin,
                        (unsigned long long)badEither, pctBlk);
            std::printf("  BLOCKS_ABSURD_D=%llu  FIRST_BAD_BLOCK_INDEX=%lld\n",
                        (unsigned long long)absurdD, firstBad);
            std::printf("  ROWS_WITH_>=1_BAD=%lld of %lld (%.4f%%)   <-- decisive\n",
                        rowsWithBad, rowsTotal, pctRows);
            std::printf("  MAX_ABS_D=%.6g MAX_ABS_DMIN=%.6g  (sane K-quant scales are 1e-3..1e-1)\n\n",
                        dMax, dminMax);
        }
    }
    return 0;
}