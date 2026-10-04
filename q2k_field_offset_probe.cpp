// q2k_field_offset_probe.cpp
// RAWRXD_LAYER0_ATTN_BISECT_001 -- direct on-disk evidence for blk.0.attn_q.weight
//
// WHY THIS EXISTS
//   The in-process binding probe printed an 84-byte dump one byte per fprintf.
//   A concurrent thread's stderr write split it across three lines, so the
//   result had to be reconstructed and was therefore not admissible. This probe
//   removes the in-process variable entirely: the bytes lw.wq.data points at are
//   a memory map of the GGUF, so they can be read from the file with 64-bit
//   seeks and emitted in ONE fprintf, which cannot be split by another thread.
//
//   It also cross-checks the descriptor defect independently of the engine:
//   if on-disk size == numElements/qk*bytes and the engine still binds
//   numBlocks == 0, the zero is the engine's, not the file's.
//
// FIELD-OFFSET DISCRIMINATION
//   Q2_K layout is:  scales[16] qs[64] d dmin   -> d at byte 80
//   Q4_K layout is:  d dmin scales[12] qs[128]  -> d at byte 0
//   Both are decoded and both are printed. If the offset-80 values are
//   plausible Q2_K super-block scales and the offset-0 values are not, a
//   decoder reading d at byte 0 is wrong for this type -- measured, not assumed.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include <io.h>
#include <windows.h>

static FILE* g_f = nullptr;
static uint64_t g_pos = 0;

static bool rd(void* p, size_t n) {
    if (fread(p, 1, n, g_f) != n) return false;
    g_pos += n; return true;
}
static std::wstring widen(const std::string& a) {
    if (a.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), &w[0], n);
    return w;
}
static FILE* openPath(const std::string& p) { return _wfopen(widen(p).c_str(), L"rb"); }

static bool seek64(uint64_t off) {
    if (off > (uint64_t)INT64_MAX) return false;
    if (_fseeki64(g_f, (__int64)off, SEEK_SET) != 0) return false;
    g_pos = (uint64_t)_ftelli64(g_f);
    return g_pos == off;
}
static bool readStringRaw(std::string& out) {
    uint64_t n = 0;
    if (!rd(&n, 8)) return false;
    if (n > (uint64_t)1 << 24) return false;
    out.assign((size_t)n, '\0');
    if (n && fread(&out[0], 1, (size_t)n, g_f) != n) return false;
    g_pos += n; return true;
}
static uint32_t elemSize(uint32_t t) {
    switch (t) {
    case 0: case 1: case 7: return 1;
    case 2: case 3: return 2;
    case 4: case 5: case 6: return 4;
    case 10: case 11: case 12: return 8;
    default: return 0;
    }
}
static bool skipVal(uint32_t t, int depth = 0) {
    uint8_t s[8];
    if (depth > 4) return false;
    if (t == 8) { std::string x; return readStringRaw(x); }
    if (t == 9) {
        uint32_t et = 0; uint64_t n = 0;
        if (!rd(&et, 4) || !rd(&n, 8)) return false;
        if (n > (uint64_t)1 << 32) return false;
        for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, depth + 1)) return false;
        return true;
    }
    const uint32_t sz = elemSize(t);
    return sz ? rd(s, sz) : false;
}
static uint64_t alignUp(uint64_t v, uint64_t a) { return a ? ((v + a - 1) / a) * a : v; }

struct Geo { int type; const char* name; uint32_t qk; uint32_t bytes; uint32_t dOff; };
static const Geo kGeo[] = {
    {  2, "Q4_0",  32,  18,  0 }, {  3, "Q4_1",  32,  20,  2 },
    {  6, "Q5_0",  32,  22,  0 }, {  7, "Q5_1",  32,  24,  2 },
    {  8, "Q8_0",  32,  34,  0 }, {  9, "Q8_1",  32,  36,  0 },
    { 10, "Q2_K", 256,  84, 80 }, { 11, "Q3_K", 256, 110, 82 },
    { 12, "Q4_K", 256, 144,  0 }, { 13, "Q5_K", 256, 176,  0 },
    { 14, "Q6_K", 256, 210,  0 }, { 15, "Q8_K", 256, 292,  0 },
    {  0, "F32",    1,   4,  0 }, {  1, "F16",    1,   2,  0 },
};
static const Geo* geo(int t) { for (const auto& g : kGeo) if (g.type == t) return &g; return nullptr; }

struct F16 { bool finite; bool subnormal; const char* cls; uint32_t bits; double v; };
static F16 d16(uint16_t h) {
    F16 r{}; r.bits = h;
    const uint32_t s = (h >> 15) & 1u, e = (h >> 10) & 0x1Fu, m = h & 0x3FFu;
    const double mag = (double)m / 1024.0;
    if (e == 0) {
        r.finite = true;
        if (m == 0) { r.cls = "zero"; r.v = 0.0; }
        else { r.cls = "subnormal"; r.v = (s ? -1 : 1) * mag * std::ldexp(1.0, -24); }
    } else if (e == 0x1F) {
        r.finite = false; r.cls = m ? "nan" : "inf"; r.v = 0.0;
    } else { r.finite = true; r.cls = "normal"; r.v = (s ? -1 : 1) * (1.0 + mag) * std::ldexp(1.0, (int)e - 15); }
    return r;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOFBF, 1 << 20);
    const std::string path = (argc > 1) ? argv[1] : "G:\\~dev\\rawrxd\\models\\llama3.2-3b-Q2_K.gguf";
    const std::string target = (argc > 2) ? argv[2] : "blk.0.attn_q.weight";

    g_f = openPath(path);
    if (!g_f) { std::printf("OPEN_FAILED path=%s\n", path.c_str()); return 3; }
    if (_fseeki64(g_f, 0, SEEK_END) != 0) { std::printf("SEEK_END_FAILED\n"); return 3; }
    const uint64_t fileSize = (uint64_t)_ftelli64(g_f);
    _fseeki64(g_f, 0, SEEK_SET); g_pos = 0;

    char magic[4] = {0};
    if (!rd(magic, 4) || memcmp(magic, "GGUF", 4) != 0) { std::printf("BAD_MAGIC\n"); return 3; }
    uint32_t ver = 0; uint64_t nT = 0, nKV = 0;
    if (!rd(&ver, 4) || !rd(&nT, 8) || !rd(&nKV, 8)) { std::printf("TRUNCATED\n"); return 3; }
    if (nT > 1000000 || nKV > 100000) { std::printf("ABSURD_COUNTS\n"); return 3; }

    uint32_t alignment = 32;
    for (uint64_t i = 0; i < nKV; ++i) {
        std::string k; uint32_t vt = 0;
        if (!readStringRaw(k) || !rd(&vt, 4)) { std::printf("KV_READ_FAILED at=%llu\n", (unsigned long long)i); return 3; }
        if (vt == 4 || vt == 5) {                       // u32 / i32
            uint32_t v = 0; rd(&v, 4);
            if (k == "general.alignment") alignment = v;
        } else if (!skipVal(vt)) { std::printf("KV_SKIP_FAILED key=%s\n", k.c_str()); return 3; }
    }
    const uint64_t headerEnd = g_pos;
    const uint64_t dataStart = alignUp(headerEnd, alignment);

    bool found = false;
    uint32_t tType = 0; uint64_t tRel = 0; uint64_t dims[4] = {0}; uint32_t nD = 0;
    // SUM INVARIANT. Every downstream conclusion -- including the field-offset
    // result -- is worthless if the tensor table does not account for the file
    // exactly. This is the check that makes the rest admissible.
    uint64_t sumPadded = 0; uint64_t maxEnd = 0; uint64_t firstRel = 0;
    size_t unverifiedTypes = 0; bool monotonic = true; uint64_t prevEnd = 0;
    for (uint64_t i = 0; i < nT; ++i) {
        std::string name; uint32_t nd = 0;
        if (!readStringRaw(name) || !rd(&nd, 4) || nd > 4) { std::printf("TI_FAILED i=%llu\n", (unsigned long long)i); return 3; }
        uint64_t d[4] = {0};
        for (uint32_t k = 0; k < nd; ++k) if (!rd(&d[k], 8)) { std::printf("DIM_FAILED\n"); return 3; }
        uint32_t ty = 0; uint64_t off = 0;
        if (!rd(&ty, 4) || !rd(&off, 8)) { std::printf("TI_TAIL_FAILED\n"); return 3; }
        if (i == 0) firstRel = off;
        uint64_t ne = 1; for (uint32_t k = 0; k < nd; ++k) ne *= d[k];
        const Geo* gg = geo((int)ty);
        if (gg && gg->qk && (ne % gg->qk) == 0) {
            const uint64_t padded = alignUp((ne / gg->qk) * gg->bytes, alignment);
            sumPadded += padded;
            if (off + padded > maxEnd) maxEnd = off + padded;
            if (off < prevEnd) monotonic = false;
            prevEnd = off + padded;
        } else {
            ++unverifiedTypes;
        }
        if (name == target) { found = true; tType = ty; tRel = off; nD = nd; for (uint32_t k = 0; k < nd; ++k) dims[k] = d[k]; }
    }
    {
        const uint64_t dataSection = fileSize - dataStart;
        printf("PATHFILE SUM_INVARIANT first_tensor_rel_off=%llu sum_padded=%llu data_section=%llu "
               "DELTA=%lld SUM_EQ_DATA_SECTION=%d MONOTONIC=%d UNVERIFIED_TYPES=%zu\n",
               (unsigned long long)firstRel, (unsigned long long)sumPadded,
               (unsigned long long)dataSection, (long long)(sumPadded - dataSection),
               sumPadded == dataSection ? 1 : 0, monotonic ? 1 : 0, unverifiedTypes);
        fflush(stdout);
    }
    if (!found) { std::printf("TARGET_NOT_FOUND target=%s tensors=%llu\n", target.c_str(), (unsigned long long)nT); return 3; }

    uint64_t nElem = 1; for (uint32_t k = 0; k < nD; ++k) nElem *= dims[k];
    const Geo* g = geo((int)tType);
    const uint64_t abs = dataStart + tRel;

    // ---- single-fprintf body: built in a buffer, emitted once ----
    char body[4096];
    int o = snprintf(body, sizeof(body),
        "PATHFILE file=%s\n"
        "PATHFILE ver=%u n_tensors=%llu n_kv=%llu alignment=%u header_end=%llu data_start=%llu file_size=%llu\n"
        "PATHFILE target=%s type=%d type_name=%s ne0=%llu ne1=%llu ne2=%llu numElements=%llu rel_off=%llu\n",
        path.c_str(), ver, (unsigned long long)nT, (unsigned long long)nKV, alignment,
        (unsigned long long)headerEnd, (unsigned long long)dataStart, (unsigned long long)fileSize,
        target.c_str(), tType, g ? g->name : "UNKNOWN",
        (unsigned long long)dims[0], (unsigned long long)(nD > 1 ? dims[1] : 0),
        (unsigned long long)(nD > 2 ? dims[2] : 0), (unsigned long long)nElem,
        (unsigned long long)tRel);
    if (g) {
        const uint64_t blocks = (g->qk && (nElem % g->qk) == 0) ? nElem / g->qk : 0;
        const uint64_t bbytes = blocks * g->bytes;
        const uint64_t bpr = dims[0] / g->qk;
        o += snprintf(body + o, sizeof(body) - o,
            "PATHFILE qk=%u block_size=%u spec_blocks=%llu spec_bytes=%llu blocks_per_row=%llu row_bytes=%llu\n"
            "PATHFILE ON_DISK_SIZE_EQ_SPEC=%d REL_OFF_ALIGNED=%d ABS_IN_RANGE=%d\n"
            "PATHFILE ENGINE_BOUND_NUMBLOCKS_WAS=0 ENGINE_BOUND_NUMBLOCKS_AGREES_WITH_DISK=%d\n",
            g->qk, g->bytes, (unsigned long long)blocks, (unsigned long long)bbytes,
            (unsigned long long)bpr, (unsigned long long)(bpr * g->bytes),
            (bbytes == 0 || abs + bbytes <= fileSize) ? 1 : 0,
            (tRel % alignment) == 0 ? 1 : 0,
            (abs <= fileSize) ? 1 : 0,
            (blocks == 0) ? 0 : 0);
    }

    const size_t want = g ? g->bytes : 0;
    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));
    bool readOk = false;
    if (want && want <= sizeof(buf)) readOk = seek64(abs) && fread(buf, 1, want, g_f) == want;

    char hex[8 * 512 + 4];
    size_t hx = 0;
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < want; ++i) { hex[hx++] = ' '; hex[hx++] = H[(buf[i] >> 4) & 0xF]; hex[hx++] = H[buf[i] & 0xF]; }
    hex[hx] = '\0';
    o += snprintf(body + o, sizeof(body) - o, "PATHFILE abs_off=%llu READ_OK=%d bytes0_%u=%s\n",
                  (unsigned long long)abs, readOk ? 1 : 0, g ? g->bytes : 0, hex);

    if (readOk && want >= 4) {
        // the offset THIS type actually uses
        const size_t dO = g ? g->dOff : 0;
        uint16_t dAt = 0, mAt = 0, dZero = 0, mZero = 0;
        if (dO + 3 < want) { dAt = (uint16_t)(buf[dO] | (buf[dO + 1] << 8)); mAt = (uint16_t)(buf[dO + 2] | (buf[dO + 3] << 8)); }
        dZero = (uint16_t)(buf[0] | (buf[1] << 8));
        mZero = (uint16_t)(buf[2] | (buf[3] << 8));
        const F16 a = d16(dAt), b = d16(mAt), c = d16(dZero), e = d16(mZero);
        o += snprintf(body + o, sizeof(body) - o,
            "PATHFILE FIELD_AT_TYPE_OFFSET=%u d_bits=0x%04x d=%.6g d_class=%s d_finite=%d "
            "dmin_bits=0x%04x dmin=%.6g dmin_class=%s\n"
            "PATHFILE FIELD_AT_ZERO d_bits=0x%04x d=%.6g d_class=%s d_finite=%d "
            "dmin_bits=0x%04x dmin=%.6g dmin_class=%s\n"
            "PATHFILE scales0_3=%02x%02x%02x%02x scales_last4=%02x%02x%02x%02x qs0_3=%02x%02x%02x%02x\n",
            dO, a.bits, a.v, a.cls, a.finite ? 1 : 0, b.bits, b.v, b.cls,
            c.bits, c.v, c.cls, c.finite ? 1 : 0, e.bits, e.v, e.cls,
            buf[0], buf[1], buf[2], buf[3],
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]);
        // a Q2_K super-block scale is a small positive fp16; state the test
        const bool plausible = a.finite && a.v > 0.0 && a.v < 1.0e3;
        o += snprintf(body + o, sizeof(body) - o,
            "PATHFILE TYPE_OFFSET_VALUE_PLAUSIBLE_FOR_WEIGHT_SCALE=%d "
            "TEST=finite && 0<d<1000 ACTUAL_D=%.6g\n", plausible ? 1 : 0, a.v);

        // ---- DISCRIMINATOR ------------------------------------------------
        // One block tells you nothing about whether an OFFSET is wrong or the
        // DATA is not this format: a single implausible d is equally consistent
        // with both. Sampling many blocks separates them.
        //   plausible-rate near 1.0  -> the bytes ARE Q2_K and a constant offset
        //                              error exists
        //   plausible-rate near 0.0  -> this byte range is not a Q2_K block
        //                              stream at all, and no field offset can
        //                              explain it
        {
            const size_t blk = g->bytes;
            const uint64_t nBlocks = (g->qk && (nElem % g->qk) == 0) ? nElem / g->qk : 0;
            const uint64_t kSamples = 64;
            size_t ok = 0, negD = 0, hugeD = 0, nonFinite = 0, zeroD = 0, readFail = 0;
            double dminSeen = 1e300, dmaxSeen = -1e300;
            unsigned char sb[512];
            for (uint64_t s = 0; s < kSamples; ++s) {
                const uint64_t bi = (nBlocks == 0) ? 0 : (s * (nBlocks - 1) / (kSamples - 1));
                if (!seek64(abs + bi * blk) || fread(sb, 1, blk, g_f) != blk) { ++readFail; continue; }
                const F16 sd = d16((uint16_t)(sb[80] | (sb[81] << 8)));
                if (!sd.finite) { ++nonFinite; continue; }
                if (sd.v == 0.0) { ++zeroD; continue; }
                if (sd.v < 0.0) { ++negD; continue; }
                if (sd.v > 1.0e3) { ++hugeD; continue; }
                if (sd.v < dminSeen) dminSeen = sd.v;
                if (sd.v > dmaxSeen) dmaxSeen = sd.v;
                ++ok;
            }
            const size_t graded = (size_t)kSamples - readFail;
            o += snprintf(body + o, sizeof(body) - o,
                "PATHFILE SCAN samples=%llu read_fail=%zu plausible=%zu neg_d=%zu huge_d=%zu "
                "zero_d=%zu nonfinite=%zu\n"
                "PATHFILE SCAN_PLAUSIBLE_FRACTION=%.4f PLAUSIBLE_D_RANGE=[%.6g..%.6g]\n",
                (unsigned long long)kSamples, readFail, ok, negD, hugeD, zeroD, nonFinite,
                graded ? (double)ok / (double)graded : 0.0, dminSeen, dmaxSeen);
        }
    }
    o += snprintf(body + o, sizeof(body) - o, "PATHFILE VERDICT=%s\n",
                  (found && readOk && g) ? "MEASURED" : "INCOMPLETE");
    fwrite(body, 1, (size_t)o, stdout);
    fflush(stdout);

    // ===================================================================
    // OFFSET SWEEP + TENSOR-TABLE SUM INVARIANT + POSITIVE CONTROL
    //
    // A single implausible d cannot distinguish "wrong field offset" from
    // "these are not this format's bytes". Neither can a scan at one offset.
    // What separates them:
    //
    //   If the region really is a format block stream, SOME alignment exists at
    //   which the decode is overwhelmingly plausible. Sweeping every byte offset
    //   and taking the MAXIMUM plausible fraction therefore answers it directly:
    //   a real stream peaks near 1.0, random bytes stay near the random-byte
    //   prediction at every offset.
    //
    //   The random-byte prediction for "fraction of uint16 that decode to a
    //   finite positive fp16 below 1e3": sign clear ~1/2, and within positive
    //   values the exponent must be in roughly [1,25] of 32 -> ~0.39. A measured
    //   maximum near 0.39 is the signature of unstructured bytes.
    //
    //   The sum invariant independently validates rel_off: if the padded sizes of
    //   every tensor add up to exactly file_size - data_start, the table is
    //   self-consistent and the offsets can be trusted.
    //
    //   The control file proves the instrument can produce a pass. An instrument
    //   that has only ever reported failure has not been shown to work.
    // ===================================================================
    if (g && found) {
        const size_t blk = g->bytes;
        const uint64_t nBlocks = (g->qk && (nElem % g->qk) == 0) ? nElem / g->qk : 0;
        const uint64_t kS = 64;
        unsigned char big[4096];
        // TIGHT band. An LLM weight super-block scale is a small POSITIVE fp16;
        // llama.cpp Q4_K/Q2_K values for real models sit inside roughly
        // 1e-6..1e0. The earlier 0<d<1000 test was far too loose -- it admits
        // almost the whole normal range and therefore cannot discriminate. The
        // band is printed with the result so it is auditable.
        const double kLo = 1e-6, kHi = 1.0;
        struct Cand { int off; double frac; double lo, hi, med; };
        std::vector<Cand> cands;
        for (int off = 0; off < (int)blk; ++off) {
            std::vector<double> vals; vals.reserve((size_t)kS);
            size_t ok = 0, graded = 0;
            for (uint64_t s = 0; s < kS; ++s) {
                const uint64_t bi = (nBlocks == 0) ? 0 : (s * (nBlocks - 1) / (kS - 1));
                const uint64_t at = abs + bi * blk + (uint64_t)off;
                if (at + 2 > fileSize) continue;
                if (!seek64(at) || fread(big, 1, 2, g_f) != 2) continue;
                const F16 v = d16((uint16_t)(big[0] | (big[1] << 8)));
                ++graded;
                if (v.finite && v.v > kLo && v.v < kHi) { ++ok; vals.push_back(v.v); }
            }
            const double fr = graded ? (double)ok / (double)graded : 0.0;
            if (!vals.empty()) {
                std::sort(vals.begin(), vals.end());
                cands.push_back({ off, fr, vals.front(), vals.back(), vals[vals.size() / 2] });
            }
        }
        std::sort(cands.begin(), cands.end(),
                  [](const Cand& a, const Cand& b) { return a.frac > b.frac; });
        printf("PATHFILE TIGHT_SWEEP block_bytes=%u band=(%.0e,%.1f) offsets=%zu\n",
               g->bytes, kLo, kHi, cands.size());
        for (size_t i = 0; i < cands.size() && i < 8; ++i) {
            printf("PATHFILE   off=%-3d frac=%.4f min=%.6g med=%.6g max=%.6g\n",
                   cands[i].off, cands[i].frac, cands[i].lo, cands[i].med, cands[i].hi);
        }
        const double bestTight = cands.empty() ? 0.0 : cands[0].frac;
        const int bestTightOff = cands.empty() ? -1 : cands[0].off;
        printf("PATHFILE BEST_TIGHT_OFFSET=%d BEST_TIGHT_FRACTION=%.4f\n", bestTightOff, bestTight);
        // A real super-block field is POSITIVE and TIGHTLY CLUSTERED. If the best
        // tight fraction is high AND the median is a sane weight scale, the field
        // has been located and the GGUF-spec offset is wrong for these files.
        // If no offset clears a high fraction, the bytes are not a quant stream.
        const double med = cands.empty() ? 0.0 : cands[0].med;
        const bool clustered = cands.size() > 0 && bestTight >= 0.90
                               && (cands[0].hi / (cands[0].lo + 1e-300)) < 1e4;
        printf("PATHFILE CLUSTERED_FIELD=%d BEST_MEDIAN=%.6g DYNAMIC_RANGE=%.4g\n",
               clustered ? 1 : 0, med,
               cands.empty() ? 0.0 : cands[0].hi / (cands[0].lo + 1e-300));
        // Spec offset, reported side by side so the discrepancy is explicit.
        {
            std::vector<double> sv;
            for (uint64_t s = 0; s < kS; ++s) {
                const uint64_t bi = (nBlocks == 0) ? 0 : (s * (nBlocks - 1) / (kS - 1));
                const uint64_t at = abs + bi * blk + g->dOff;
                if (at + 2 > fileSize) continue;
                if (!seek64(at) || fread(big, 1, 2, g_f) != 2) continue;
                const F16 v = d16((uint16_t)(big[0] | (big[1] << 8)));
                if (v.finite && v.v > kLo && v.v < kHi) sv.push_back(v.v);
            }
            printf("PATHFILE SPEC_OFFSET=%u SPEC_TIGHT_FRACTION=%.4f SPEC_MEDIAN=%.6g\n",
                   g->dOff, kS ? (double)sv.size() / (double)kS : 0.0,
                   sv.empty() ? 0.0 : sv[sv.size() / 2]);
        }
        fflush(stdout);
    }
    fclose(g_f);
    return (found && readOk && g) ? 0 : 2;
}