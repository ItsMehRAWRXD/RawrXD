// gguf_shard_seq.cpp — RAWRXD_DEEPSEEK_SHARD06_TENSOR_OFFSET_SEQUENCE_001
//
// PURPOSE
//   Prove or disprove, without inferring anything from weight-byte magnitudes,
//   whether GGUF tensor offsets in these shards are LOCAL to each shard's own
//   tensor-data blob (standard GGUF) or something globalized.
//
//   The decisive structural invariant of a standard GGUF file is that the
//   tensor offsets form one gapless, alignment-padded chain starting at 0:
//
//       tensor[0].offset = 0
//       tensor[i].offset = tensor[i-1].offset + align_up(nbytes(tensor[i-1]), A)
//
//   and, as an independent corroboration that does not depend on per-tensor
//   traits at all, that the sum of all padded tensor sizes equals the size of
//   the shard's data section (file_size - data_start).
//
// INSTRUMENT DEFECTS THIS FILE CORRECTS (see locate_blk33.cpp, SHA256
// E66BDB1126D0BCDAF5AECA88181B6F81D79CFDC66F74AA05A65525099EA4DBE4 — RETAINED
// AS EVIDENCE, DO NOT TRUST ITS BYTE DUMPS):
//
//   D-1  32-bit seek truncation.  locate_blk33.cpp:76 used
//        std::fseek(f,(long)off,SEEK_SET).  On MSVC `long` is 32 bits, so any
//        offset above 2^31-1 is silently converted modulo 2^32.  The target
//        offset is ~18.28e9 = 4*2^32 + 1,100,888,896, so the "corrected"
//        Q4_K header bytes reported previously were read from byte 1,100,888,896
//        instead of 18,280,758,080 — a 17,179,869,184-byte displacement, while
//        still landing inside the file and therefore returning plausible
//        bytes.  THIS FILE USES _fseeki64/_ftelli64 ONLY and counts every seek
//        that a 32-bit long would have truncated.
//
//   D-2  Split-KV decoder accepted only type 4 (UINT32).  gguf-split writes
//        split.no / split.count as UINT16 (type 2) and split.tensors.count as
//        UINT32/INT32.  The old reader therefore never matched, silently fell
//        through to skip_val, and reported the pre-initialised 0 as if it were
//        a decoded value — "not found" rendered as "zero".  THIS FILE RECORDS
//        THE RAW TYPE ID, A FOUND FLAG, AND THE VALUE PER ACTUAL TYPE.
//
//   D-3  fp16 decoder could not express NaN/Inf.  The old helper deliberately
//        substituted sentinel doubles (-888888 / ±999999) because "a NaN scale
//        is a diagnostic string, not a number".  That makes finiteness
//        untestable, which is the exact measurement being requested.  THIS FILE
//        RETURNS A CLASSIFICATION (zero/subnormal/normal/inf/nan) PLUS THE
//        VALUE, so non-finite data cannot masquerade as a plausible scale.
//
//   D-4  Position was tracked by hand in R::pos, which can desync from the real
//        file pointer without any error.  THIS FILE USES _ftelli64() AS THE
//        SINGLE SOURCE OF TRUTH for position.
//
//   D-5  No type-trait provenance.  A wrong ggml type_size would turn a good
//        file into a false FAIL and a bad file into a false PASS, silently.
//        THIS FILE PRINTS THE TRAIT USED FOR EVERY DISTINCT TYPE ENCOUNTERED,
//        MARKS TRAITS IT CANNOT VOUCH FOR AS UNVERIFIED, AND RETURNS
//        INCONCLUSIVE RATHER THAN A VERDICT IF AN UNVERIFIED TYPE APPEARS.
//
// HONESTY INVARIANTS
//   * An unknown / unverified ggml type  => INCONCLUSIVE, never PASS, never FAIL.
//   * "key absent"                      => FOUND=0, never a value of 0.
//   * A seek that a 32-bit long would truncate is reported, not performed.
//   * Every printed number is measured in this run. No literal verdicts.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <set>

// ---------------------------------------------------------------- file reader

static uint64_t g_truncSeeks = 0;   // seeks a 32-bit long would have corrupted
static int      g_scanDiscriminating = 0;
static int      g_scanJointRate = 0;
static int      g_wrapTestOk = 0;

struct R {
    std::FILE* f = nullptr;
    bool  eof = false;
    bool  bad = false;

    bool open(const char* p) { f = std::fopen(p, "rb"); return f != nullptr; }
    void close() { if (f) std::fclose(f); f = nullptr; }

    uint64_t pos() const { return f ? (uint64_t)_ftelli64(f) : 0; }
    uint64_t size() {
        if (!f) { bad = true; return 0; }
        std::fseek(f, 0, SEEK_END);
        uint64_t n = (uint64_t)_ftelli64(f);
        std::fseek(f, 0, SEEK_SET);
        return n;
    }
    // 64-bit seek. Records (never performs) a long-truncating seek.
    // A null/closed stream is refused LOUDLY instead of being passed to fread:
    // an earlier draft of this probe called fread on a closed FILE* and the run
    // fast-failed, destroying the entire receipt after ~300 correct lines.
    bool seek64(uint64_t off) {
        if (!f) { bad = true; return false; }
        if ((uint64_t)(long)off != off) ++g_truncSeeks;
        if (_fseeki64(f, (__int64)off, SEEK_SET) != 0) { bad = true; return false; }
        return true;
    }
    bool read(void* dst, size_t n) {
        if (!f) { bad = true; return false; }
        if (n == 0) return true;
        if (std::fread(dst, 1, n, f) != n) { bad = true; eof = true; return false; }
        return true;
    }
    uint8_t  u8 () { uint8_t  v = 0; read(&v, 1); return v; }
    uint16_t u16(){ uint16_t v = 0; read(&v, 2); return v; }
    uint32_t u32(){ uint32_t v = 0; read(&v, 4); return v; }
    uint64_t u64(){ uint64_t v = 0; read(&v, 8); return v; }
    int32_t  i32(){ int32_t  v = 0; read(&v, 4); return v; }
    std::string str() {
        uint64_t n = u64();
        std::string s;
        if (n == 0) return s;
        if (n > (uint64_t)1 << 28) { bad = true; return s; }  // refuse absurd length
        s.resize((size_t)n);
        if (!read(&s[0], (size_t)n)) s.clear();
        return s;
    }
};

// GGUF v3 value types (0-based, per spec):
//  0 u8  1 i8  2 u16  3 i16  4 u32  5 i32  6 f32  7 bool
//  8 STRING  9 ARRAY  10 u64  11 i64  12 f64
static const char* typeName(uint32_t t) {
    switch (t) {
        case 0: return "u8";   case 1: return "i8";
        case 2: return "u16";  case 3: return "i16";
        case 4: return "u32";  case 5: return "i32";
        case 6: return "f32";  case 7: return "bool";
        case 8: return "string"; case 9: return "array";
        case 10: return "u64"; case 11: return "i64";
        case 12: return "f64";
        default: return "UNKNOWN_TYPE";
    }
}

// Consume one value of type t. If capture != null and the value is a scalar,
// record it sign-extended.
struct KV {
    bool     found = false;
    bool     scalar = false;
    int64_t  ival = 0;
    uint32_t rawType = 0xFFFFFFFFu;
    std::string sval;
};

static void readValue(R& r, uint32_t t, KV* cap) {
    switch (t) {
        case 0: case 1: { uint8_t v = r.u8();
            if (cap) { cap->found = true; cap->scalar = true; cap->ival = (t == 0) ? v : (int8_t)v; } return; }
        case 2: case 3: { uint16_t v = r.u16();
            if (cap) { cap->found = true; cap->scalar = true; cap->ival = (t == 2) ? v : (int16_t)v; } return; }
        case 4: case 5: { uint32_t v = r.u32();
            if (cap) { cap->found = true; cap->scalar = true; cap->ival = (t == 4) ? (int64_t)v : (int64_t)(int32_t)v; } return; }
        case 6: { uint32_t v = r.u32(); (void)v; return; }          // f32, not captured
        case 7: { uint8_t v = r.u8(); if (cap) { cap->found = true; cap->scalar = true; cap->ival = v; } return; }
        case 8: { std::string s = r.str();
            if (cap) { cap->found = true; cap->scalar = false; cap->sval = s; } return; }
        case 9: { uint32_t et = r.u32(); uint64_t n = r.u64();
            int w = 0;
            switch (et) {
                case 0: case 1: case 7:               w = 1; break;
                case 2: case 3:                       w = 2; break;
                case 4: case 5: case 6:               w = 4; break;
                case 10: case 11: case 12:            w = 8; break;
                case 8: { for (uint64_t i = 0; i < n; i++) r.str(); w = -1; } break;
                default: break;
            }
            if (w > 0) {
                uint64_t bytes = n * (uint64_t)w;
                if (r.seek64(r.pos() + bytes)) { /* consumed by seek */ }
            } else if (w == 0) {
                r.bad = true;   // unknown element type: refuse to desync silently
            }
            return; }
        case 10: { uint64_t v = r.u64(); if (cap) { cap->found = true; cap->scalar = true; cap->ival = (int64_t)v; } return; }
        case 11: { uint64_t v = r.u64(); if (cap) { cap->found = true; cap->scalar = true; cap->ival = (int64_t)v; } return; }
        case 12: { uint64_t v = r.u64(); (void)v; return; }
        default: r.bad = true; return;
    }
}

// ---------------------------------------------------------------- fp16 decode

enum FpClass { FC_ZERO, FC_SUBNORMAL, FC_NORMAL, FC_INF, FC_NAN };

static const char* fpClassName(FpClass c) {
    switch (c) {
        case FC_ZERO:      return "zero";
        case FC_SUBNORMAL: return "subnormal";
        case FC_NORMAL:    return "normal";
        case FC_INF:       return "inf";
        case FC_NAN:       return "nan";
    }
    return "?";
}

// Returns the mathematical value INCLUDING real +/-inf and NaN (unlike D-3),
// plus an independent classification so finiteness is decidable without
// comparing against a sentinel.
static double fp16(uint16_t h, FpClass* cls) {
    const int sign = (h >> 15) & 1;
    const int exp  = (h >> 10) & 0x1F;
    const int frac = h & 0x3FF;
    double v;
    if (exp == 0) {
        if (frac == 0) { *cls = FC_ZERO; v = 0.0; }
        else           { *cls = FC_SUBNORMAL; v = (double)frac * 5.9604644775390625e-08; }
    } else if (exp == 31) {
        if (frac == 0) { *cls = FC_INF; v = sign ? -INFINITY : INFINITY; }
        else           { *cls = FC_NAN; v = (double)NAN; }
    } else {
        *cls = FC_NORMAL;
        v = (1.0 + (double)frac / 1024.0) * std::pow(2.0, (double)(exp - 15));
    }
    return sign ? -v : v;
}
static bool fpFinite(uint16_t h) {
    const int exp = (h >> 10) & 0x1F;
    return exp != 31;
}

struct Hdr { uint16_t bits; double val; const char* cls; bool finite; };
static Hdr dec16(uint16_t h) {
    FpClass c;
    const double v = fp16(h, &c);
    Hdr o; o.bits = h; o.val = v; o.cls = fpClassName(c); o.finite = fpFinite(h);
    return o;
}

// ------------------------------------------------------------ ggml type traits

// VERIFIED: trait derived from the ggml-common.h layout and cross-checked
//           against the standard K-quant size table (Q2_K=84 Q4_K=144
//           Q5_K=176 Q6_K=210).
// UNVERIFIED: this build will not certify a chain that depends on it.
enum TraitSrc { TR_VERIFIED, TR_UNVERIFIED };

struct Trait { const char* name; uint64_t blck; uint64_t size; TraitSrc src; };

static const Trait kTrait[40] = {
    {"F32",      1,   4, TR_VERIFIED},   {"F16",      1,   2, TR_VERIFIED},   // 0,1
    {"Q4_0",    32,  18, TR_VERIFIED},   {"Q4_1",    32,  20, TR_VERIFIED},   // 2,3
    {"?",        0,   0, TR_UNVERIFIED}, {"?",        0,   0, TR_UNVERIFIED}, // 4,5 reserved
    {"Q5_0",    32,  22, TR_VERIFIED},   {"Q5_1",    32,  24, TR_VERIFIED},   // 6,7
    {"Q8_0",    32,  34, TR_VERIFIED},   {"Q8_1",    32, 136, TR_UNVERIFIED}, // 8,9 (layout changed across ggml versions)
    {"Q2_K",   256,  84, TR_VERIFIED},   {"Q3_K",   256, 110, TR_UNVERIFIED}, // 10,11 (struct sums to 112; refusing to guess)
    {"Q4_K",   256, 144, TR_VERIFIED},   {"Q5_K",   256, 176, TR_VERIFIED},   // 12,13
    {"Q6_K",   256, 210, TR_VERIFIED},   {"Q8_K",   256, 292, TR_UNVERIFIED}, // 14,15
    {"IQ2_XXS",256,  66, TR_UNVERIFIED}, {"IQ2_XS", 256,  74, TR_UNVERIFIED}, // 16,17
    {"IQ3_XXS",256,  98, TR_UNVERIFIED}, {"IQ1_S",  256,  50, TR_UNVERIFIED}, // 18,19
    {"IQ4_NL", 32,  18, TR_UNVERIFIED}, {"IQ3_S",  256,  86, TR_UNVERIFIED}, // 20,21
    {"IQ2_S",  256,  82, TR_UNVERIFIED}, {"IQ4_XS", 256, 136, TR_UNVERIFIED}, // 22,23
    {"I8",      1,   1, TR_VERIFIED},   {"I16",     1,   2, TR_VERIFIED},   // 24,25
    {"I32",     1,   4, TR_VERIFIED},   {"I64",     1,   8, TR_VERIFIED},   // 26,27
    {"F64",     1,   8, TR_VERIFIED},   {"IQ1_M",  256,  56, TR_UNVERIFIED}, // 28,29
    {"BF16",    1,   2, TR_VERIFIED},   {"?",       0,   0, TR_UNVERIFIED}, // 30,31
    {"?",       0,   0, TR_UNVERIFIED}, {"?",       0,   0, TR_UNVERIFIED}, // 32,33
    {"TQ1_0", 256,  54, TR_UNVERIFIED}, {"TQ2_0",  256,  66, TR_UNVERIFIED}, // 34,35
    {"?",       0,   0, TR_UNVERIFIED}, {"?",       0,   0, TR_UNVERIFIED}, // 36,37
    {"MXFP4",  32,  17, TR_UNVERIFIED}, {"?",       0,   0, TR_UNVERIFIED}, // 38,39
};

struct NBytes { uint64_t n = 0; bool ok = false; const char* why = ""; };

static NBytes tensorNBytes(const Trait& t, const std::vector<uint64_t>& dims) {
    NBytes r;
    if (t.src != TR_VERIFIED) { r.why = "unverified_trait"; return r; }
    if (t.blck == 0)           { r.why = "zero_block_size";   return r; }
    uint64_t nel = 1;
    for (uint64_t d : dims) {
        if (d == 0) { r.why = "zero_dimension"; return r; }
        nel *= d;
    }
    if (dims.empty()) { r.why = "no_dimensions"; return r; }
    if (dims[0] % t.blck != 0) { r.why = "dim0_not_multiple_of_block"; return r; }
    r.n = (nel / t.blck) * t.size;
    r.ok = true;
    return r;
}

// ------------------------------------------------------------------ structures

struct TI {
    std::string name;
    uint32_t type = 0;
    std::vector<uint64_t> dims;
    uint64_t relOff = 0;
    NBytes   nb;
    uint64_t padded = 0;
    bool     sizeKnown = false;
};

struct ShardKV {
    KV splitNo, splitCount, splitTensorsCount, alignment, architecture;
    uint64_t headerEnd = 0, dataStart = 0, effectiveAlignment = 32;
    bool     alignmentFound = false, alignmentDefaulted = false;
    uint64_t nTensors = 0, nKV = 0;
    uint32_t ver = 0;
    std::vector<TI> t;
};

static bool interesting(const std::string& k) {
    return k == "split.no" || k == "split.count" || k == "split.tensors.count" ||
           k == "general.alignment" || k == "general.architecture";
}

static bool parseShard(const char* path, ShardKV& s) {
    R r;
    if (!r.open(path)) return false;
    char magic[4];
    if (!r.read(magic, 4)) { r.close(); return false; }
    if (std::memcmp(magic, "GGUF", 4) != 0) {
        std::printf("  MAGIC_FAIL first4=%02x%02x%02x%02x\n",
                    (uint8_t)magic[0], (uint8_t)magic[1], (uint8_t)magic[2], (uint8_t)magic[3]);
        r.close(); return false;
    }
    s.ver       = r.u32();
    s.nTensors  = r.u64();
    s.nKV       = r.u64();

    for (uint64_t i = 0; i < s.nKV && !r.bad; i++) {
        std::string key = r.str();
        uint32_t vt = r.u32();
        KV* cap = nullptr;
        if (interesting(key)) {
            cap = &s.splitNo;
            if      (key == "split.count")          cap = &s.splitCount;
            else if (key == "split.tensors.count")  cap = &s.splitTensorsCount;
            else if (key == "general.alignment")    cap = &s.alignment;
            else if (key == "general.architecture")  cap = &s.architecture;
        }
        if (cap) cap->rawType = vt;
        readValue(r, vt, cap);
    }
    if (r.bad) { std::printf("  KV_PARSE_FAIL pos=%llu\n", (unsigned long long)r.pos()); r.close(); return false; }

    s.t.resize((size_t)s.nTensors);
    for (uint64_t i = 0; i < s.nTensors && !r.bad; i++) {
        TI& t = s.t[(size_t)i];
        t.name = r.str();
        uint32_t nd = r.u32();
        t.dims.resize(nd);
        for (uint32_t j = 0; j < nd; j++) t.dims[j] = r.u64();
        t.type  = r.u32();
        t.relOff = r.u64();
    }
    if (r.bad) { std::printf("  TENSOR_PARSE_FAIL pos=%llu\n", (unsigned long long)r.pos()); r.close(); return false; }

    s.headerEnd = r.pos();
    // alignment provenance: general.alignment if present, else the GGUF default 32
    s.effectiveAlignment = s.alignmentFound ? (uint64_t)s.alignment.ival : 32u;
    s.alignmentDefaulted = !s.alignmentFound;
    uint64_t a = s.effectiveAlignment ? s.effectiveAlignment : 1;
    s.dataStart = (s.headerEnd + a - 1) / a * a;
    r.close();
    return true;
}

static uint64_t alignUp(uint64_t n, uint64_t a) {
    if (a == 0) return n;
    return (n + a - 1) / a * a;
}

struct Census {
    uint64_t checked = 0, pass = 0, fail = 0;
    bool     conclusive = true;          // false if any trait is unverified
    std::vector<std::string> unverifiedTypes;
    std::vector<std::string> failures;   // formatted
    uint64_t sumPadded = 0;
};

static Census runCensus(ShardKV& s, bool verbose) {
    Census c;
    std::map<uint32_t, uint64_t> typeCount;
    for (auto& t : s.t) {
        if (t.type < 40) typeCount[t.type]++;
        const Trait& tr = kTrait[t.type < 40 ? t.type : 39];
        t.nb = tensorNBytes(tr, t.dims);
        t.sizeKnown = t.nb.ok;
        t.padded = t.nb.ok ? alignUp(t.nb.n, s.effectiveAlignment) : 0;
        if (!t.nb.ok) {
            c.conclusive = false;
            std::string s2 = "name=" + t.name + " type=" +
                std::to_string((int)t.type) + "/" + (t.type < 40 ? tr.name : "?") +
                " reason=" + t.nb.why;
            c.unverifiedTypes.push_back(s2);
        }
    }
    if (verbose) {
        std::printf("  TYPE_INVENTORY (traits actually applied to the arithmetic):\n");
        for (auto& kv : typeCount) {
            const Trait& tr = kTrait[kv.first < 40 ? kv.first : 39];
            std::printf("    type=%-3u name=%-8s count=%-4llu blck=%-4llu size=%-4llu src=%s\n",
                kv.first, tr.name, (unsigned long long)kv.second,
                (unsigned long long)tr.blck, (unsigned long long)tr.size,
                (tr.src == TR_VERIFIED) ? "VERIFIED" : "UNVERIFIED");
        }
    }

    uint64_t expected = 0;
    for (size_t i = 0; i < s.t.size(); i++) {
        const TI& t = s.t[i];
        c.checked++;
        c.sumPadded += t.padded;
        if (!t.sizeKnown) continue;                 // already recorded as inconclusive
        const bool okSeq = (t.relOff == expected);
        if (okSeq) c.pass++; else {
            c.fail++;
            if (c.failures.size() < 16) {
                char buf[512];
                std::snprintf(buf, sizeof(buf),
                    "SEQ[%zu] %s actual=%llu expected=%llu delta=%lld bytes=%llu padded=%llu FAIL",
                    i, t.name.c_str(), (unsigned long long)t.relOff,
                    (unsigned long long)expected,
                    (long long)((int64_t)t.relOff - (int64_t)expected),
                    (unsigned long long)t.nb.n, (unsigned long long)t.padded);
                c.failures.push_back(buf);
            }
        }
        expected += t.padded;
    }
    return c;
}

// ------------------------------------------------------------------- reporting

static void printKV(const char* label, const KV& k) {
    if (!k.found) { std::printf("  %s_FOUND=0\n", label); return; }
    std::printf("  %s_FOUND=1 %s_TYPE=%u %s_TYPE_NAME=%s", label, label,
                k.rawType, label, typeName(k.rawType));
    if (k.scalar) std::printf(" %s_VALUE=%lld\n", label, (long long)k.ival);
    else          std::printf(" %s_VALUE=\"%s\"\n", label, k.sval.c_str());
}

static void hex32(std::FILE* f, const uint8_t* b) {
    for (int i = 0; i < 32; i++) std::fprintf(f, "%02x", b[i]);
}

// ------------------------------------------------- contiguous Q4_K header scan
//
// Why this exists, and why it uses no guessed bit-unpacking:
//   The 6-bit scale/min fields of block_q4_K are interleaved across 12 bytes and
//   a wrong unpacking would manufacture a false FAIL, so it is NOT implemented.
//   Instead we test a property that needs no knowledge of the scales layout:
//   if the read offset is correct, EVERY consecutive 144-byte window starting
//   at it begins with two positive finite fp16 values of tightly clustered
//   magnitude. At any nonzero displacement the 4-byte header positions slide off
//   block boundaries and the pass rate collapses. The NEGATIVE CONTROL below
//   re-runs the identical scan at +1/+7/+16/+64 bytes to prove the scan can fail.
struct ScanStats {
    int      blocks = 0;
    int      finiteD = 0, finiteDmin = 0, positiveD = 0, positiveDmin = 0;
    double   dMin = 0, dMax = 0, dSum = 0;
    double   mMin = 0, mMax = 0, mSum = 0;
    bool     ok = false;
    const char* why = "";
};

static void scanQ4K(R& r, uint64_t off, int nblocks, ScanStats& s) {
    const int CH = 64;                       // blocks per read chunk
    std::vector<uint8_t> buf((size_t)CH * 144);
    s.blocks = nblocks;
    s.dMin = s.mMin = 1e300; s.dMax = s.mMax = -1e300;
    for (int done = 0; done < nblocks; ) {
        const int want = (nblocks - done < CH) ? (nblocks - done) : CH;
        if (!r.seek64(off + (uint64_t)done * 144ull) ||
            !r.read(buf.data(), (size_t)want * 144)) { s.ok = false; s.why = "read_fail"; return; }
        for (int i = 0; i < want; i++) {
            const uint8_t* b = &buf[(size_t)i * 144];
            const uint16_t db = (uint16_t)(b[0] | (b[1] << 8));
            const uint16_t mb = (uint16_t)(b[2] | (b[3] << 8));
            FpClass cd, cm;
            const double dv = fp16(db, &cd);
            const double mv = fp16(mb, &cm);
            if (cd != FC_INF && cd != FC_NAN) { s.finiteD++; s.dSum += dv; if (dv < s.dMin) s.dMin = dv; if (dv > s.dMax) s.dMax = dv; if (dv > 0) s.positiveD++; }
            if (cm != FC_INF && cm != FC_NAN) { s.finiteDmin++; s.mSum += mv; if (mv < s.mMin) s.mMin = mv; if (mv > s.mMax) s.mMax = mv; if (mv > 0) s.positiveDmin++; }
        }
        done += want;
    }
    s.ok = true;
}

static void printScan(const char* label, const ScanStats& s) {
    if (!s.ok) { std::printf("  %-22s SCAN_FAIL=%s\n", label, s.why); return; }
    const int good = s.positiveDmin;   // finite AND positive dmin is the strictest joint condition
    std::printf("  %-22s blocks=%-6d d_finite=%-6d dmin_finite=%-6d d_pos=%-6d dmin_pos=%-6d "
                "JOINT_PASS=%-6d JOINT_RATE=%.4f d[min=%.3e max=%.3e mean=%.3e] dmin[min=%.3e max=%.3e mean=%.3e]\n",
        label, s.blocks, s.finiteD, s.finiteDmin, s.positiveD, s.positiveDmin,
        good, (double)good / (double)(s.blocks ? s.blocks : 1),
        s.dMin, s.dMax, s.dSum / (double)(s.finiteD ? s.finiteD : 1),
        s.mMin, s.mMax, s.mSum / (double)(s.finiteDmin ? s.finiteDmin : 1));
}

struct Q4KSample { const char* label; uint64_t off; };

// ------------------------------------------- wrap-boundary regression self-test
//
// Platform fact this pins down: MSVC `long` is 32-bit on x64, so every
// std::fseek(f,(long)off,...) silently wraps modulo 2^32. The cases below span
// the wrap boundary and the exact target offset, so a regression to a 32-bit
// path cannot pass here.
static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
static_assert(sizeof(__int64) == 8, "__int64 must be 8 bytes");
static_assert(sizeof(long) == 4, "this regression is only meaningful where long is 32-bit");

// Hostile contract: never trust a seek. Verify the resulting position equals
// what was requested, so a wrapped or clamped seek is caught at the call site.
static bool readAt(R& r, uint64_t abs, void* dst, size_t n, uint64_t* posVerified) {
    if (posVerified) *posVerified = r.pos();
    if (!r.seek64(abs)) return false;
    const uint64_t p = r.pos();          // verified BEFORE the read
    if (posVerified) *posVerified = p;
    if (p != abs) { r.bad = true; return false; }
    return r.read(dst, n);
}

static int wrapBoundarySelfTest(const char* path) {
    struct T { uint64_t off; const char* name; };
    const T cases[] = {
        { 0x00000000FFFFFFFFull, "TEST_OFFSET_A_0x00000000FFFFFFFF" },
        { 0x0000000100000000ull, "TEST_OFFSET_B_0x0000000100000000" },
        { 0x0000000400000000ull, "TEST_OFFSET_C_0x0000000400000000" },
        { 18280760608ull,         "TEST_OFFSET_D_TARGET_ABS"        },
    };
    std::printf("\n=== WRAP-BOUNDARY REGRESSION SELF-TEST (64-bit path contract) ===\n");
    std::printf("  sizeof(long)=%zu (32-bit on MSVC x64 -> std::fseek(f,(long)off) wraps mod 2^32)\n", sizeof(long));
    R r;
    if (!r.open(path)) { std::printf("  SELFTEST_OPEN_FAIL=%s\n", path); return 0; }
    int readbackOk = 0, aliasFree = 0, aliasesDetected = 0;
    const int NC = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < NC; i++) {
        uint8_t good[32], bad[32];
        std::memset(good, 0xAA, sizeof(good));
        std::memset(bad,  0x55, sizeof(bad));
        // Position is verified immediately AFTER the seek and BEFORE the read, by
        // readAt(). Comparing after the read would compare off+bytes against off.
        uint64_t posAfterSeek = 0;
        const bool readOk = readAt(r, cases[i].off, good, 32, &posAfterSeek);
        const bool posOk = readOk && (posAfterSeek == cases[i].off);
        const uint64_t aliased = (uint64_t)(long)cases[i].off;
        const bool hasAlias = (aliased != cases[i].off);
        // A 32-bit path fails in TWO distinct ways and both must be caught:
        //   * wrap   -> a valid but wrong in-file offset (B, C, D)
        //   * sign-ext -> 0xFFFFFFFF as `long` is -1, so the seek FAILS (A)
        bool aliasFailed = false, aliasDiffers = false;
        if (hasAlias) {
            if (!r.seek64(aliased) || !r.read(bad, 32)) aliasFailed = true;
            else aliasDiffers = (std::memcmp(good, bad, 32) != 0);
        }
        const bool aliasCaught = hasAlias && (aliasFailed || aliasDiffers);
        if (posOk && readOk) ++readbackOk;
        if (!hasAlias) ++aliasFree;
        if (aliasCaught) ++aliasesDetected;
        std::printf("  %-34s req=%-14llu pos_after_seek=%-14llu POSITION_MATCH=%d READ_OK=%d "
                    "32BIT_ALIAS=%-20llu ALIAS_MODE=%-9s ALIAS_CAUGHT=%d\n",
                    cases[i].name, (unsigned long long)cases[i].off,
                    (unsigned long long)posAfterSeek, posOk ? 1 : 0, readOk ? 1 : 0,
                    (unsigned long long)aliased,
                    !hasAlias ? "none" : (aliasFailed ? "seek_fail" : "wrong_bytes"),
                    aliasCaught ? 1 : 0);
        std::printf("      true_bytes = "); hex32(stdout, good); std::printf("\n");
    }
    r.close();
    std::printf("  READBACK_POSITION_MUST_EQUAL_REQUEST=%d (%d/%d)\n",
                readbackOk == NC ? 1 : 0, readbackOk, NC);
    std::printf("  NO_32BIT_ALIAS_AT_4G_BOUNDARY=%d (%d of %d offsets are 64-bit-only)\n",
                aliasFree == 0 ? 1 : 0, NC - aliasFree, NC);
    std::printf("  ALIASED_READS_CAUGHT=%d (%d/%d 64-bit-only offsets; modes: seek_fail=sign-extension, wrong_bytes=wrap)\n",
                aliasesDetected == (NC - aliasFree) ? 1 : 0, aliasesDetected, NC - aliasFree);
    g_wrapTestOk = (readbackOk == NC && aliasFree == 0 &&
                    aliasesDetected == (NC - aliasFree)) ? 1 : 0;
    return g_wrapTestOk;
}

int main(int argc, char** argv) {
    const char* target = (argc > 1) ? argv[1] : "blk.33.ffn_gate_exps.weight";
    const char* dir    = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
    const bool  verbose = true;

    setvbuf(stdout, nullptr, _IONBF, 0);   // unbuffered: a fast-fail must not eat the receipt

    std::printf("RAWRXD_DEEPSEEK_SHARD06_TENSOR_OFFSET_SEQUENCE_001\n");
    std::printf("TARGET=%s\n", target);
    std::printf("INVARIANT=first_off==0 AND off[i]==off[i-1]+align_up(nbytes[i-1],A)\n");
    std::printf("PRIOR_INSTRUMENT=locate_blk33.cpp SHA256=E66BDB1126D0BCDAF5AECA88181B6F81D79CFDC66F74AA05A65525099EA4DBE4"
                " (RETAINED, ITS BYTE DUMPS ARE NOT TRUSTWORTHY: 32-bit fseek truncation)\n\n");

    int  totalMatch = 0;
    int  targetShard = -1;
    bool allConclusive = true;
    uint64_t allSeqPass = 0, allSeqFail = 0, allChecked = 0;
    int  shardsSeen = 0, sumEqDataSec = 0, firstOffZero = 0;
    std::vector<std::string> allUnverified;
    std::set<int> shardsWithTarget;

    for (int sh = 1; sh <= 11; sh++) {
        char path[512];
        std::snprintf(path, sizeof(path), "%sDeepSeek-R1-Q4_K_M-%05d-of-00011.gguf", dir, sh);
        ShardKV s;
        std::printf("=== SHARD %02d ===\n", sh);
        if (!parseShard(path, s)) { std::printf("  OPEN_OR_PARSE_FAIL=%s\n\n", path); allConclusive = false; continue; }
        uint64_t fsize = 0; { R r; r.open(path); fsize = r.size(); r.close(); }

        printKV("ARCH", s.architecture);
        printKV("SPLIT_NO", s.splitNo);
        printKV("SPLIT_COUNT", s.splitCount);
        printKV("SPLIT_TENSORS_COUNT", s.splitTensorsCount);
        printKV("GENERAL_ALIGNMENT", s.alignment);
        std::printf("  SHARD%02d_GENERAL_ALIGNMENT_FOUND=%d\n", sh, s.alignmentFound ? 1 : 0);
        std::printf("  SHARD%02d_GENERAL_ALIGNMENT_DEFAULTED_TO_GGUF_DEFAULT_32=%d\n", sh, s.alignmentDefaulted ? 1 : 0);
        std::printf("  SHARD%02d_EFFECTIVE_ALIGNMENT=%llu\n", sh, (unsigned long long)s.effectiveAlignment);
        std::printf("  VER=%u N_KV=%llu LOCAL_TENSORS=%llu HEADER_END=%llu DATA_START=%llu FILE_SIZE=%llu\n",
            s.ver, (unsigned long long)s.nKV, (unsigned long long)s.nTensors,
            (unsigned long long)s.headerEnd, (unsigned long long)s.dataStart,
            (unsigned long long)fsize);

        Census c = runCensus(s, verbose);
        allChecked += c.checked; allSeqPass += c.pass; allSeqFail += c.fail;
        if (!c.conclusive) { allConclusive = false; }
        for (auto& u : c.unverifiedTypes) allUnverified.push_back("shard" + std::to_string(sh) + " " + u);

        uint64_t dataSection = (fsize > s.dataStart) ? fsize - s.dataStart : 0;
        std::printf("  SEQ_CHECKED=%llu SEQ_PASS=%llu SEQ_FAIL=%llu CONCLUSIVE=%d\n",
            (unsigned long long)c.checked, (unsigned long long)c.pass,
            (unsigned long long)c.fail, c.conclusive ? 1 : 0);
        for (auto& u : c.unverifiedTypes) std::printf("  UNVERIFIED_TYPE: %s\n", u.c_str());
        for (auto& f : c.failures)         std::printf("  %s\n", f.c_str());
        std::printf("  FIRST_TENSOR_NAME=%s\n", s.t.empty() ? "(none)" : s.t[0].name.c_str());
        std::printf("  FIRST_TENSOR_REL_OFF=%llu\n", s.t.empty() ? 0ull : (unsigned long long)s.t[0].relOff);
        std::printf("  SUM_PADDED_TENSOR_BYTES=%llu\n", (unsigned long long)c.sumPadded);
        std::printf("  DATA_SECTION_BYTES=file_size-data_start=%llu\n", (unsigned long long)dataSection);
        std::printf("  SUM_PADDED_EQ_DATA_SECTION=%d DELTA=%lld\n",
            (c.sumPadded == dataSection) ? 1 : 0,
            (long long)((int64_t)c.sumPadded - (int64_t)dataSection));
        ++shardsSeen;
        if (c.sumPadded == dataSection) ++sumEqDataSec;
        if (!s.t.empty() && s.t[0].relOff == 0) ++firstOffZero;

        // locate target
        long idx = -1;
        for (size_t i = 0; i < s.t.size(); i++) if (s.t[i].name == target) { idx = (long)i; break; }
        if (idx >= 0) {
            shardsWithTarget.insert(sh);
            totalMatch++;
            targetShard = sh;
            const TI& t = s.t[(size_t)idx];
            std::printf("\n  TARGET_FOUND=1 TARGET=%s\n", target);
            std::printf("  BLK33_INDEX_IN_SHARD=%ld OF_LOCAL_TENSORS=%llu\n", idx, (unsigned long long)s.nTensors);
            std::printf("  BLK33_TYPE=%u (%s) NDIM=%llu DIMS=", t.type,
                        t.type < 40 ? kTrait[t.type].name : "?", (unsigned long long)t.dims.size());
            for (size_t j = 0; j < t.dims.size(); j++)
                std::printf("%s%llu", j ? "," : "", (unsigned long long)t.dims[j]);
            std::printf("\n");
            std::printf("  BLK33_REL_OFF=%llu\n", (unsigned long long)t.relOff);
            std::printf("  BLK33_TENSOR_BYTES=%llu SIZE_KNOWN=%d\n",
                        (unsigned long long)t.nb.n, t.sizeKnown ? 1 : 0);
            std::printf("  BLK33_ABS_FILE_OFF=data_start+rel_off=%llu\n",
                        (unsigned long long)(s.dataStart + t.relOff));

            if (idx > 0) {
                const TI& p = s.t[(size_t)idx - 1];
                std::printf("  PREVIOUS_TENSOR=%s\n", p.name.c_str());
                std::printf("  PREVIOUS_REL_OFF=%llu\n", (unsigned long long)p.relOff);
                std::printf("  PREVIOUS_BYTES=%llu SIZE_KNOWN=%d\n", (unsigned long long)p.nb.n, p.sizeKnown ? 1 : 0);
                std::printf("  PREVIOUS_PADDED_END=%llu\n", (unsigned long long)(p.relOff + p.padded));
                std::printf("  PREVIOUS_PADDED_END_EQUALS_BLK33_REL_OFF=%d\n",
                    ((p.relOff + p.padded) == t.relOff) ? 1 : 0);
            } else {
                std::printf("  PREVIOUS_TENSOR=(none, target is tensor 0)\n");
            }
            if (sh == 6 && verbose) {
                std::printf("\n  FULL SEQUENCE, SHARD 06 (%zu tensors):\n", s.t.size());
                uint64_t exp2 = 0;
                for (size_t i = 0; i < s.t.size(); i++) {
                    const TI& q = s.t[i];
                    std::printf("    SEQ[%02zu] name=%-38s actual=%-14llu expected=%-14llu bytes=%-13llu padded=%-13llu %s\n",
                        i, q.name.c_str(), (unsigned long long)q.relOff, (unsigned long long)exp2,
                        (unsigned long long)q.nb.n, (unsigned long long)q.padded,
                        q.sizeKnown ? (q.relOff == exp2 ? "PASS" : "FAIL") : "SKIP_SIZE_UNKNOWN");
                    exp2 += q.padded;
                }
            }
        }
        std::printf("\n");
    }

    // ------------------------------------------------------ truncation forensics
    std::printf("=== 32-BIT SEEK TRUNCATION FORENSICS ===\n");
    std::printf("(compares what the prior instrument read against a 64-bit read at the same nominal offset)\n");
    if (targetShard > 0) {
        char path[512];
        std::snprintf(path, sizeof(path), "%sDeepSeek-R1-Q4_K_M-%05d-of-00011.gguf", dir, targetShard);
        ShardKV s;
        if (parseShard(path, s)) {
            long idx = -1;
            for (size_t i = 0; i < s.t.size(); i++) if (s.t[i].name == target) { idx = (long)i; break; }
            if (idx >= 0) {
                const uint64_t absOff = s.dataStart + s.t[(size_t)idx].relOff;
                const uint64_t asLong  = (uint64_t)(long)absOff;   // what fseek(f,(long)off) did
                const uint64_t delta   = absOff - asLong;
                uint8_t bTrue[32], bTrunc[32];
                R r; r.open(path);
                r.seek64(absOff); r.read(bTrue, 32);
                r.seek64(asLong);  r.read(bTrunc, 32);
                r.close();
                std::printf("  NOMINAL_ABS_FILE_OFF=%llu\n", (unsigned long long)absOff);
                std::printf("  AS_32BIT_LONG=%llu\n", (unsigned long long)asLong);
                std::printf("  DISPLACEMENT_CAUGHT_BY_LONG_TRUNCATION=%llu (=%llu x 2^32)\n",
                            (unsigned long long)delta, (unsigned long long)(delta / (1ull << 32)));
                std::printf("  TRUNCATION_OCCURS=%d\n", (asLong != absOff) ? 1 : 0);
                std::printf("  TRUE_READ_64BIT   : "); hex32(stdout, bTrue);    std::printf("\n");
                std::printf("  PRIOR_READ_LONG   : "); hex32(stdout, bTrunc);   std::printf("\n");
                std::printf("  PRIOR_READ_EQUALS_TRUE_READ=%d\n",
                    (std::memcmp(bTrue, bTrunc, 32) == 0) ? 1 : 0);
                {
                    const Hdr dt  = dec16((uint16_t)(bTrue[0] | (bTrue[1] << 8)));
                    const Hdr dm  = dec16((uint16_t)(bTrue[2] | (bTrue[3] << 8)));
                    const Hdr dp  = dec16((uint16_t)(bTrunc[0] | (bTrunc[1] << 8)));
                    const Hdr dmp = dec16((uint16_t)(bTrunc[2] | (bTrunc[3] << 8)));
                    std::printf("  TRUE_64BIT d=bits 0x%04X finite=%d class=%-9s value=%-14.7g | dmin=bits 0x%04X finite=%d class=%-9s value=%-14.7g\n",
                        dt.bits, dt.finite ? 1 : 0, dt.cls, dt.val,
                        dm.bits, dm.finite ? 1 : 0, dm.cls, dm.val);
                    std::printf("  PRIOR_LONG d=bits 0x%04X finite=%d class=%-9s value=%-14.7g | dmin=bits 0x%04X finite=%d class=%-9s value=%-14.7g\n",
                        dp.bits, dp.finite ? 1 : 0, dp.cls, dp.val,
                        dmp.bits, dmp.finite ? 1 : 0, dmp.cls, dmp.val);
                }

                wrapBoundarySelfTest(path);

                // ---- Q4_K header sweep over STRUCTURALLY SEPARATED headers ----
                std::printf("\n=== Q4_K HEADER SWEEP AT STRUCTURALLY SEPARATED LOCATIONS ===\n");
                if (allConclusive && allSeqFail == 0) {
                    const uint64_t d0 = s.t[(size_t)idx].dims[0];
                    const uint64_t d1 = s.t[(size_t)idx].dims[1];
                    const uint64_t d2 = s.t[(size_t)idx].dims[2];
                    const uint64_t rowStride    = (d0 / 256ull) * 144ull;
                    const uint64_t expertStride = rowStride * d1;
                    const uint64_t blkBytes     = kTrait[12].size;   // Q4_K = 144, VERIFIED trait
                    Q4KSample samples[] = {
                        { "expert0_row0_blk0",     absOff },
                        { "expert0_row0_blk1",     absOff + blkBytes },
                        { "expert0_row1_blk0",     absOff + rowStride },
                        { "expert0_row1024_blk0",  absOff + rowStride * 1024ull },
                        { "expert0_row2047_blk27", absOff + rowStride * 2047ull + blkBytes * 27ull },
                        { "expert1_row0_blk0",     absOff + expertStride },
                        { "expert127_row0_blk0",   absOff + expertStride * 127ull },
                        { "expert255_row2047_blk27", absOff + expertStride * 255ull + rowStride * 2047ull + blkBytes * 27ull },
                    };
                    const int NS = (int)(sizeof(samples) / sizeof(samples[0]));
                    int nfD = 0, nfDmin = 0;
                    r.open(path);
                    for (int i = 0; i < NS; i++) {
                        uint8_t b[32];
                        if (!r.seek64(samples[i].off) || !r.read(b, 32)) {
                            std::printf("  [%d] %-24s READ_FAIL off=%llu\n", i, samples[i].label,
                                        (unsigned long long)samples[i].off);
                            nfD++; nfDmin++; continue;
                        }

                        const uint16_t db = (uint16_t)(b[0] | (b[1] << 8));
                        const uint16_t mb = (uint16_t)(b[2] | (b[3] << 8));
                        FpClass cd, cm;
                        double dv = fp16(db, &cd), mv = fp16(mb, &cm);
                        if (!fpFinite(db))  nfD++;
                        if (!fpFinite(mb))  nfDmin++;
                        std::printf("  [%d] %-24s off=%-14llu hex=", i, samples[i].label,
                                    (unsigned long long)samples[i].off);
                        hex32(stdout, b);
                        std::printf("\n");
                        std::printf("      %-24s D_BITS=0x%04X D_FINITE=%d D=%-14.7g "
                                    "DMIN_BITS=0x%04X DMIN_FINITE=%d DMIN=%-14.7g D_CLASS=%s DMIN_CLASS=%s\n",
                            "", db, fpFinite(db) ? 1 : 0, dv,
                            mb, fpFinite(mb) ? 1 : 0, mv,
                            fpClassName(cd), fpClassName(cm));
                    }
                    // NOTE: r stays OPEN here — the contiguous scan below needs it.
                    // An earlier draft closed the stream at this point and scanQ4K
                    // then called fread on a null FILE*, fast-failing the whole run
                    // and destroying the receipt. R now also rejects a null stream.
                    std::printf("  Q4K_HEADERS_SAMPLED=%d NONFINITE_D=%d NONFINITE_DMIN=%d\n", NS, nfD, nfDmin);
                    std::printf("  ROW_STRIDE=%llu EXPERT_STRIDE=%llu Q4K_BLOCK_BYTES=%llu TENSOR_DIMS=%llu,%llu,%llu\n",
                        (unsigned long long)rowStride, (unsigned long long)expertStride,
                        (unsigned long long)blkBytes,
                        (unsigned long long)d0, (unsigned long long)d1, (unsigned long long)d2);

                    std::printf("\n=== CONTIGUOUS Q4_K HEADER SCAN FROM TARGET START (alignment/offset proof) ===\n");
                    const int NSCAN = 4096;
                    ScanStats sGood;
                    scanQ4K(r, absOff, NSCAN, sGood);
                    printScan("AT_EXACT_OFFSET", sGood);
                    int ctrlRate[4]; const int cdisp[4] = { 1, 7, 16, 64 };
                    for (int i = 0; i < 4; i++) {
                        ScanStats s2;
                        scanQ4K(r, absOff + (uint64_t)cdisp[i], NSCAN, s2);
                        char nm[40]; std::snprintf(nm, sizeof(nm), "NEGCTRL_PLUS_%d_BYTE", cdisp[i]);
                        printScan(nm, s2);
                        ctrlRate[i] = s2.ok ? (s2.positiveDmin * 10000 / NSCAN) : -1;
                    }
                    const int goodRate = sGood.ok ? (sGood.positiveDmin * 10000 / NSCAN) : -1;
                    g_scanDiscriminating = (sGood.ok && goodRate == 10000 &&
                        ctrlRate[0] < goodRate && ctrlRate[1] < goodRate &&
                        ctrlRate[2] < goodRate && ctrlRate[3] < goodRate) ? 1 : 0;
                    g_scanJointRate = goodRate;
                    std::printf("  JOINT_PASS_RATE_AT_EXACT_OFFSET=%.4f\n", (double)goodRate / 10000.0);
                    std::printf("  NEGCTRL_JOINT_RATES_AT_PLUS_1_7_16_64=%.4f,%.4f,%.4f,%.4f\n",
                        (double)ctrlRate[0] / 10000.0, (double)ctrlRate[1] / 10000.0,
                        (double)ctrlRate[2] / 10000.0, (double)ctrlRate[3] / 10000.0);
                    std::printf("  SCAN_IS_DISCRIMINATING=%d (exact rate must exceed every displaced rate)\n",
                        g_scanDiscriminating);
                    std::printf("  PRIOR_DATA_START_CLAIM=3904 MEASURED_SHARD06_DATA_START=%llu PRIOR_DISCREPANCY=%lld\n",
                        (unsigned long long)s.dataStart, (long long)(3904ll - (long long)s.dataStart));
                    r.close();
                } else {
                    std::printf("  SWEEP_WITHHELD=1 reason=offset_sequence_not_proven "
                                "(CONCLUSIVE=%d SEQ_FAIL=%llu)\n", allConclusive ? 1 : 0,
                                (unsigned long long)allSeqFail);
                }
            }
        }
    }

    std::printf("\n=== RECEIPT ===\n");
    std::printf("TARGET_NAME_MATCH=%s\n", totalMatch == 1 ? "PASS" : "FAIL");
    std::printf("TARGET_MATCH_COUNT=%d\n", totalMatch);
    std::printf("OFFSET_SEQUENCE_CHECKED=%llu\n", (unsigned long long)allChecked);
    std::printf("OFFSET_SEQUENCE_PASS=%llu\n", (unsigned long long)allSeqPass);
    std::printf("OFFSET_SEQUENCE_FAIL=%llu\n", (unsigned long long)allSeqFail);
    std::printf("OFFSET_SEQUENCE_PASS_ALL_SHARDS=%d\n", (allSeqFail == 0 && allChecked > 0) ? 1 : 0);
    std::printf("SHARDS_PARSED=%d\n", shardsSeen);
    std::printf("FIRST_TENSOR_REL_OFF_ZERO_SHARDS=%d OF %d\n", firstOffZero, shardsSeen);
    std::printf("SUM_PADDED_EQ_DATA_SECTION_SHARDS=%d OF %d\n", sumEqDataSec, shardsSeen);
    std::printf("TRAIT_COVERAGE_CONCLUSIVE=%d\n", allConclusive ? 1 : 0);
    std::printf("UNVERIFIED_TYPE_INSTANCES=%llu\n", (unsigned long long)allUnverified.size());
    for (auto& u : allUnverified) std::printf("  %s\n", u.c_str());
    std::printf("SEEKS_A_32BIT_LONG_WOULD_TRUNCATE=%llu (diagnostic: this build performs ONLY _fseeki64 seeks)\n",
                (unsigned long long)g_truncSeeks);
    std::printf("Q4K_CONTIGUOUS_SCAN_JOINT_PASS_RATE=%.4f\n", (double)g_scanJointRate / 10000.0);
    std::printf("Q4K_CONTIGUOUS_SCAN_DISCRIMINATING=%d\n", g_scanDiscriminating);
    std::printf("WRAP_BOUNDARY_SELFTEST=%d\n", g_wrapTestOk);
    // Verdict conditions are all MEASURED STRUCTURE. g_truncSeeks is deliberately
    // NOT a condition: it counts offsets this build correctly sought with
    // _fseeki64 that a 32-bit long would have corrupted, so requiring it to be
    // zero would fail every run that legitimately inspects high offsets. An
    // earlier draft of this receipt contained exactly that condition.
    const bool certified = (totalMatch == 1) && (allSeqFail == 0) && (allChecked == 1025) &&
                           allConclusive && (shardsSeen == 11) &&
                           (sumEqDataSec == shardsSeen) && (firstOffZero == shardsSeen) &&
                           (g_scanJointRate == 10000) && g_scanDiscriminating && g_wrapTestOk;
    std::printf("LOCATION_CORRECTNESS=%s\n", certified ? "CERTIFIED_LOCAL_OFFSETS" : "NOT_CERTIFIED");
    return certified ? 0 : 1;
}
