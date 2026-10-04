// gguf_ds_start_probe.cpp
// RAWRXD_GGUF_DATA_START_AUTHORITY_005
//
// PURPOSE
//   Resolve an unresolved contradiction in RAWRXD_DEEPSEEK_LOCATION_AUTHORITY_003:
//     shard 06 sweep printed DATA_START=3904  -> ABS_FILE_OFF=18280758080
//     Q4_K header sweep used  ABS_FILE_OFF=18280760608  (= REL_OFF + 6432)
//   6432 was obtained by SUBTRACTING the read address from REL_OFF, i.e. it was
//   chosen so the read WOULD land on a block boundary. That is fitting the
//   conclusion to the observation. This probe measures DATA_START from the file
//   itself and does not assume the answer.
//
// WHAT IT MEASURES (all from bytes on disk, no literals)
//   1. every shard: split.* KVs, general.alignment, HEADER_END, DATA_START
//   2. blk.33.ffn_gate_exps.weight: type, dims, REL_OFF, computed ABS
//   3. invariants: first REL_OFF==0, strictly increasing, no overlap after
//      32-byte alignment, SUM(padded sizes) == file_size - DATA_START
//   4. block geometry: REL_OFF mod BLOCK_BYTES, and whether each read position
//      is block-aligned RELATIVE TO DATA_START (the only alignment that matters)
//   5. 144-byte Q4_K block dump at BASE and at BASE+BLOCK_BYTES, with d/dmin
//      decoded by an independent bit-exact decoder
//
// EXIT: 0 all invariants pass, 2 a structural invariant failed, 3 target absent

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>

#ifndef _WIN32
#error "win64 only: this probe asserts _fseeki64/tell semantics"
#endif
#include <io.h>
#include <windows.h>

static FILE* g_f = nullptr;
static bool g_fail = false;

// narrow -> wide, so a path can never be truncated by an ANSI code page
static std::wstring widen(const std::string& a) {
    if (a.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), &w[0], n);
    return w;
}
static FILE* openPath(const std::string& p) { return _wfopen(widen(p).c_str(), L"rb"); }

static bool rdExact(void* p, size_t n) {
    return fread(p, 1, n, g_f) == n;
}
static uint64_t g_pos = 0;
static bool rd(void* p, size_t n) {
    if (!rdExact(p, n)) { g_fail = true; return false; }
    g_pos += n;
    return true;
}
static bool seek64(uint64_t off) {
    if (off > (uint64_t)INT64_MAX) return false;
    if (_fseeki64(g_f, (__int64)off, SEEK_SET) != 0) return false;
    g_pos = (uint64_t)_ftelli64(g_f);
    return true;
}
static uint64_t tellHere() { return (uint64_t)_ftelli64(g_f); }

// ---------------------------------------------------------------- GGUF types
enum GgufType {
    GT_U8 = 0, GT_I8, GT_U16, GT_I16, GT_U32, GT_I32, GT_F32, GT_BOOL,
    GT_STR, GT_ARR, GT_U64, GT_I64, GT_F64
};
static const char* ggufTypeName(uint32_t t) {
    switch (t) {
    case GT_U8:  return "u8";   case GT_I8:  return "i8";
    case GT_U16: return "u16";  case GT_I16: return "i16";
    case GT_U32: return "u32";  case GT_I32: return "i32";
    case GT_F32: return "f32";  case GT_BOOL: return "bool";
    case GT_STR: return "str";  case GT_ARR: return "arr";
    case GT_U64: return "u64";  case GT_I64: return "i64";
    case GT_F64: return "f64";
    default: return "?";
    }
}
static bool readStringRaw(std::string& out) {
    uint64_t n = 0;
    if (!rd(&n, 8)) return false;
    if (n > (uint64_t)1 << 24) return false;          // hostile input guard
    out.assign((size_t)n, '\0');
    if (n && !rdExact(&out[0], (size_t)n)) return false;
    g_pos += n;
    return true;
}
static uint32_t ggufElemSize(uint32_t t) {             // fixed-width only
    switch (t) {
    case GT_U8: case GT_I8: case GT_BOOL: return 1;
    case GT_U16: case GT_I16: return 2;
    case GT_U32: case GT_I32: case GT_F32: return 4;
    case GT_U64: case GT_I64: case GT_F64: return 8;
    default: return 0;                                // str / arr handled by caller
    }
}
// skip a value of type t (no length prefix consumed for t itself)
static bool skipVal(uint32_t t, int depth = 0) {
    uint8_t scratch[8];
    if (depth > 4) return false;
    if (t == GT_STR) { std::string s; return readStringRaw(s); }
    if (t == GT_ARR) {
        uint32_t et = 0; uint64_t n = 0;
        if (!rd(&et, 4)) return false;
        if (!rd(&n, 8)) return false;
        if (n > (uint64_t)1 << 32) return false;
        for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, depth + 1)) return false;
        return true;
    }
    uint32_t sz = ggufElemSize(t);
    if (!sz) return false;
    return rd(scratch, sz);
}

// ------------------------------------------------------------ ggml tensor type
struct TypeTraits { uint32_t id; const char* name; uint32_t blck; uint64_t bytes; };
static const TypeTraits kTypes[] = {
    {  0, "F32",     1,     4 }, {  1, "F16",     1,     2 },
    {  2, "Q4_0",  32,    18 }, {  3, "Q4_1",  32,    20 },
    {  6, "Q5_0",  32,    22 }, {  7, "Q5_1",  32,    24 },
    {  8, "Q8_0",  32,    34 }, {  9, "Q8_1",  32,    36 },
    { 10, "Q2_K", 256,    84 }, { 11, "Q3_K", 256,   110 },
    { 12, "Q4_K", 256,   144 }, { 13, "Q5_K", 256,   176 },
    { 14, "Q6_K", 256,   210 }, { 15, "Q8_K", 256,   292 },
    { 30, "BF16",    1,     2 },
};
static const TypeTraits* traits(uint32_t id) {
    for (const auto& t : kTypes) if (t.id == id) return &t;
    return nullptr;
}
static uint64_t tensorBytes(const TypeTraits* t, uint64_t nElem) {
    if (!t || t->blck == 0 || (nElem % t->blck) != 0) return 0;
    return (nElem / t->blck) * t->bytes;
}
static uint64_t alignUp(uint64_t v, uint64_t a) { return a ? ((v + a - 1) / a) * a : v; }

// ------------------------------------------------------- independent fp16 decoder
struct F16 { bool finite; bool subnormal; bool zero; uint32_t bits; double value; };
static F16 decodeF16(uint16_t h) {                    // bit-exact, no hardware path
    F16 r{}; r.bits = h;
    const uint32_t sign = (h >> 15) & 1u;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t man  = h & 0x3FFu;
    const double mag = (double)man / 1024.0;
    if (exp == 0) {
        if (man == 0) { r.finite = true; r.zero = (sign == 0); r.value = (sign ? -0.0 : 0.0); }
        else { r.finite = true; r.subnormal = true; r.value = (sign ? -1 : 1) * mag * std::ldexp(1.0, -24); }
    } else if (exp == 0x1F) {
        r.finite = false; r.value = man ? NAN : (sign ? -INFINITY : INFINITY);
    } else {
        r.finite = true; r.value = (sign ? -1 : 1) * (1.0 + mag) * std::ldexp(1.0, (int)exp - 15);
    }
    return r;
}

// --------------------------------------------------------------------- structs
struct TensorInfo {
    std::string name;
    uint32_t nDims = 0;
    uint64_t dims[8] = {0};
    uint32_t type = 0;
    uint64_t relOff = 0;
    uint64_t endPos = 0;
};

struct ShardReport {
    std::string path;
    uint32_t ver = 0, nKV = 0, nTensors = 0;
    uint64_t headerEnd = 0, dataStart = 0, fileSize = 0;
    uint32_t alignment = 32;
    bool alignKV = false;
    long long splitNo = -1, splitCount = -1, splitTensorsCount = -1;
    std::vector<TensorInfo> t;
};

static bool parseShard(const std::string& path, ShardReport& R, std::string& err) {
    g_fail = false;
    g_f = openPath(path);
    if (!g_f) { err = "open_failed"; return false; }
    R.path = path;
    if (_fseeki64(g_f, 0, SEEK_END) != 0) { err = "seek_end_failed"; fclose(g_f); return false; }
    R.fileSize = (uint64_t)_ftelli64(g_f);
    if (_fseeki64(g_f, 0, SEEK_SET) != 0) { err = "rewind_failed"; fclose(g_f); return false; }
    g_pos = 0;
    char magic[4] = {0};
    if (!rd(magic, 4) || memcmp(magic, "GGUF", 4) != 0) { err = "bad_magic"; fclose(g_f); return false; }
    // read the two counts into 64-bit locals: writing 8 bytes into a uint32_t
    // member silently corrupts the neighbouring member (measured, not reasoned)
    uint32_t ver32 = 0; uint64_t nT64 = 0, nKV64 = 0;
    if (!rd(&ver32, 4) || !rd(&nT64, 8) || !rd(&nKV64, 8)) { err = "truncated_hdr"; fclose(g_f); return false; }
    R.ver = ver32; R.nTensors = nT64; R.nKV = nKV64;
    if (R.nTensors > 1000000u || R.nKV > 100000u) { err = "absurd_counts"; fclose(g_f); return false; }
    R.alignment = 32;
    for (uint64_t i = 0; i < R.nKV && !g_fail; ++i) {
        std::string key; uint32_t vt = 0;
        if (!readStringRaw(key) || !rd(&vt, 4)) { err = "kv_read_failed"; fclose(g_f); return false; }
        // numeric KVs we need are u32 (alignment, split counts) or i32/u16/i16
        bool consumed = false;
        if (vt == GT_U32 || vt == GT_I32 || vt == GT_U16 || vt == GT_I16) {
            uint32_t sz = ggufElemSize(vt);
            uint8_t b[8] = {0};
            if (rd(b, sz)) {
                consumed = true;
                long long v = 0;
                switch (sz) {
                case 2: { uint16_t t2; memcpy(&t2, b, 2); memcpy(&v, &t2, 2); } break;
                case 4: { uint32_t t4; memcpy(&t4, b, 4); memcpy(&v, &t4, 4); } break;
                }
                if (key == "general.alignment")            { R.alignment = (uint32_t)v; R.alignKV = true; }
                else if (key == "split.no")                { R.splitNo = v; }
                else if (key == "split.count")             { R.splitCount = v; }
                else if (key == "split.tensors.count")     { R.splitTensorsCount = v; }
            }
        }
        if (!consumed && !skipVal(vt)) { err = "kv_skip_failed:" + key; fclose(g_f); return false; }
    }
    R.t.reserve(R.nTensors);
    for (uint64_t i = 0; i < R.nTensors && !g_fail; ++i) {
        TensorInfo ti;
        if (!readStringRaw(ti.name) || !rd(&ti.nDims, 4)) { err = "ti_name_failed"; fclose(g_f); return false; }
        if (ti.nDims > 8) { err = "too_many_dims"; fclose(g_f); return false; }
        for (uint32_t d = 0; d < ti.nDims; ++d) if (!rd(&ti.dims[d], 8)) { err = "ti_dim_failed"; fclose(g_f); return false; }
        if (!rd(&ti.type, 4) || !rd(&ti.relOff, 8)) { err = "ti_tail_failed"; fclose(g_f); return false; }
        ti.endPos = g_pos;
        R.t.push_back(ti);
    }
    if (g_fail) { err = "truncated_during_tensor_infos"; fclose(g_f); return false; }
    R.headerEnd = g_pos;
    R.dataStart = alignUp(R.headerEnd, R.alignment);
    fclose(g_f); g_f = nullptr;
    return true;
}

static void hex32(const uint8_t* p) {
    for (int i = 0; i < 32; ++i) printf("%02x", p[i]);
}

static bool dumpQ4KBlock(uint64_t absOff, const char* label, uint64_t blockBytes) {
    uint8_t buf[512];
    if (!seek64(absOff)) { printf("  %-24s off=%llu SEEK_FAILED\n", label, (unsigned long long)absOff); return false; }
    const uint64_t after = tellHere();
    if (after != absOff) { printf("  %-24s off=%llu TELL_MISMATCH=%llu\n", label, (unsigned long long)absOff, (unsigned long long)after); return false; }
    if (!rdExact(buf, blockBytes)) { printf("  %-24s off=%llu SHORT_READ\n", label, (unsigned long long)absOff); return false; }
    const uint16_t db = (uint16_t)(buf[0] | (buf[1] << 8));
    const uint16_t mb = (uint16_t)(buf[2] | (buf[3] << 8));
    const F16 d = decodeF16(db), dm = decodeF16(mb);
    printf("  %-24s off=%-14llu hex=", label, (unsigned long long)absOff);
    hex32(buf);
    printf("  D_BITS=0x%04X D=%.6e D_FINITE=%d D_CLASS=%s | DMIN_BITS=0x%04X DMIN=%.6e DMIN_FINITE=%d\n",
        db, d.value, d.finite ? 1 : 0,
        (!d.finite ? "nonfinite" : (d.zero ? "zero" : (d.subnormal ? "subnormal" : "normal"))),
        mb, dm.value, dm.finite ? 1 : 0);
    return d.finite && dm.finite;
}

// ---------------------------------------------------------------------- main
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOFBF, 1 << 20);
    std::string dir = (argc > 1) ? argv[1] : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE";
    const char* target = "blk.33.ffn_gate_exps.weight";

    // 0. the 64-bit contract, re-asserted before anything claims a byte address
    printf("=== 64BIT POSITION CONTRACT ===\n");
    printf("  sizeof(long)=%zu  sizeof(long long)=%zu\n", sizeof(long), sizeof(long long));
    {
        static_assert(sizeof(uint64_t) == 8, "uint64_t must be 64-bit");
        static_assert(sizeof(long) == 4, "long is 32-bit on win64: fseek() truncates");
        static_assert(sizeof(__int64) == 8, "__int64 must be 64-bit");
        // the self-test subject is a file we already know is >4 GiB: use a shard
        std::string selfPath = dir + "\\DeepSeek-R1-Q4_K_M-00006-of-00011.gguf";
        FILE* t = openPath(selfPath);
        if (!t) { printf("  SELFTEST_OPEN_FAILED path=%s\n", selfPath.c_str()); return 3; }
        uint64_t probes[4] = { 0x00000000FFFFFFFFull, 0x0000000100000000ull,
                               0x0000000400000000ull, 18280760608ull };
        int pass = 0, alias = 0;
        for (uint64_t p : probes) {
            bool posOk = (_fseeki64(t, (__int64)p, SEEK_SET) == 0) && ((uint64_t)_ftelli64(t) == p);
            long asLong = (long)p;                              // the defective form
            const bool longWouldTruncate = ((uint64_t)(unsigned long)asLong != p);
            alias += longWouldTruncate ? 1 : 0;
            printf("  probe=0x%016llx req=%-14llu POSITION_MATCH=%d  LONG32_ALIAS=%d\n",
                (unsigned long long)p, (unsigned long long)p, posOk ? 1 : 0, longWouldTruncate ? 1 : 0);
            pass += posOk ? 1 : 0;
        }
        fclose(t);
        printf("  READBACK_POSITION_MUST_EQUAL_REQUEST=%d (%d/4)\n", pass == 4 ? 1 : 0, pass);
        printf("  LONG32_WOULD_TRUNCATE_PROBES=%d OF 4\n", alias);
    }

    printf("\n=== PER-SHARD MEASURED DATA_START CENSUS ===\n");
    printf("%-8s %-4s %-5s %-6s %-6s %-6s %-11s %-11s %-13s %-6s %-6s %-6s %s\n",
        "SHARD", "VER", "NKV", "SPLIT", "COUNT", "ALIGN", "HEADER_END", "DATA_START", "FILE_SIZE", "NTENS", "SEQ", "SUMPAD", "VERDICT");

    std::vector<ShardReport> reps;
    int shardFail = 0, shardSeqPass = 0, shardSumPass = 0, firstZero = 0;
    for (int s = 1; s <= 11; ++s) {
        char nm[128];
        snprintf(nm, sizeof(nm), "%s\\DeepSeek-R1-Q4_K_M-%05d-of-00011.gguf", dir.c_str(), s);
        ShardReport R; std::string err;
        if (!parseShard(nm, R, err)) { printf("%-8d PARSE_FAILED %s\n", s, err.c_str()); ++shardFail; continue; }
        // structural invariants, all computed
        bool seqOk = true, unverified = false;
        uint64_t cursor = 0;
        for (size_t i = 0; i < R.t.size(); ++i) {
            const TensorInfo& ti = R.t[i];
            const TypeTraits* tr = traits(ti.type);
            uint64_t nElem = 1; for (uint32_t d = 0; d < ti.nDims; ++d) nElem *= ti.dims[d];
            uint64_t tb = tensorBytes(tr, nElem);
            if (!tr || tb == 0) { unverified = true; }
            uint64_t padded = tb ? alignUp(tb, R.alignment) : 0;
            if (i == 0 && ti.relOff != 0) seqOk = false;
            if (i > 0) {
                uint64_t prevEnd = cursor;
                if (ti.relOff < prevEnd) seqOk = false;          // overlap
            }
            if (tb) cursor = ti.relOff + padded;
        }
        const uint64_t dataSection = (R.fileSize > R.dataStart) ? (R.fileSize - R.dataStart) : 0;
        const bool sumOk = (cursor == dataSection);
        if (seqOk) ++shardSeqPass;
        if (sumOk)  ++shardSumPass;
        if (!R.t.empty() && R.t[0].relOff == 0) ++firstZero;
        printf("%-8d %-4u %-5llu %-6lld %-6lld %-6u %-11llu %-11llu %-13llu %-6zu %-6s %-6s %s%s\n",
            s, R.ver, (unsigned long long)R.nKV, (long long)R.splitNo, (long long)R.splitCount,
            R.alignment, (long long)R.headerEnd, (long long)R.dataStart, (long long)R.fileSize,
            R.t.size(), seqOk ? "PASS" : "FAIL", sumOk ? "PASS" : "FAIL",
            unverified ? "UNVERIFIED_TYPE_PRESENT" : "", (seqOk && sumOk) ? "PASS" : "FAIL");
        if (!seqOk || sumOk == false) { /* verdict column already carries it */ }
        reps.push_back(R);
    }

    printf("\n=== TARGET TENSOR ===\n");
    const ShardReport* owner = nullptr; size_t ti = 0;
    int matches = 0;
    for (const auto& R : reps)
        for (size_t i = 0; i < R.t.size(); ++i)
            if (R.t[i].name == target) { ++matches; owner = &R; ti = i; }
    printf("TARGET=%s\nTARGET_MATCH_COUNT=%d\n", target, matches);
    if (matches != 1) { printf("VERDICT=FAIL_TARGET_CARDINALITY\n"); return 3; }
    const TensorInfo& T = owner->t[ti];
    printf("TARGET_SHARD_SPLIT_NO=%lld\nSPLIT_COUNT=%lld\nSPLIT_TENSORS_COUNT=%lld\n",
        (long long)owner->splitNo, (long long)owner->splitCount, (long long)owner->splitTensorsCount);
    printf("SHARD_FILE_SIZE=%llu\n", (unsigned long long)owner->fileSize);

    const TypeTraits* tr = traits(T.type);
    if (!tr) { printf("VERDICT=FAIL_UNKNOWN_TYPE=%u\n", T.type); return 2; }
    uint64_t nElem = 1; for (uint32_t d = 0; d < T.nDims; ++d) nElem *= T.dims[d];
    const uint64_t tb = tensorBytes(tr, nElem);
    printf("TYPE=%u\nTYPE_NAME=%s\n", T.type, tr->name);
    printf("NE0=%llu\nNE1=%llu\nNE2=%llu\nNELEMS=%llu\n",
        (unsigned long long)T.dims[0], (unsigned long long)(T.nDims > 1 ? T.dims[1] : 0),
        (unsigned long long)(T.nDims > 2 ? T.dims[2] : 0), (unsigned long long)nElem);
    printf("BLOCK_QK=%u\nBLOCK_BYTES=%llu\n", tr->blck, (unsigned long long)tr->bytes);
    printf("REL_OFF=%llu\nREL_OFF_MOD_32=%llu\nREL_OFF_ALIGNED=%d\nREL_OFF_MOD_BLOCK=%llu\n",
        (unsigned long long)T.relOff, (unsigned long long)(T.relOff % 32),
        (T.relOff % 32 == 0) ? 1 : 0, (unsigned long long)(T.relOff % tr->bytes));
    printf("MEASURED_DATA_START=%llu\n", (unsigned long long)owner->dataStart);
    printf("MEASURED_ALIGNMENT=%u\nALIGNMENT_KV_PRESENT=%d\n", owner->alignment, owner->alignKV ? 1 : 0);

    const uint64_t ABS = owner->dataStart + T.relOff;
    printf("ABS_FILE_OFF=%llu\n", (unsigned long long)ABS);
    printf("ABS_MOD_BLOCK_FROM_DATA_START=%llu\n", (unsigned long long)(T.relOff % tr->bytes));
    const uint64_t rangeEnd = ABS + tb;
    printf("TENSOR_BYTES=%llu\nRANGE_END=%llu\nRANGE_WITHIN_FILE=%d\nBYTES_AFTER_TENSOR=%llu\n",
        (unsigned long long)tb, (unsigned long long)rangeEnd,
        (ABS <= owner->fileSize && tb <= owner->fileSize - ABS) ? 1 : 0,
        (unsigned long long)(rangeEnd <= owner->fileSize ? owner->fileSize - rangeEnd : 0));

    // THE CONTRADICTION, resolved by measurement rather than by subtraction
    printf("\n=== CONTRADICTION RESOLUTION ===\n");
    printf("CLAIMED_DATA_START_A=3904   -> ABS_A=%llu\n", (unsigned long long)(3904ull + T.relOff));
    printf("CLAIMED_DATA_START_B=6432   -> ABS_B=%llu\n", (unsigned long long)(6432ull + T.relOff));
    printf("MEASURED_DATA_START=%llu -> ABS=%llu\n",
        (unsigned long long)owner->dataStart, (unsigned long long)ABS);
    const uint64_t dA = (3904ull + T.relOff) == ABS ? 0 : (3904ull + T.relOff) - ABS;
    const uint64_t dB = (6432ull + T.relOff) == ABS ? 0 : (6432ull + T.relOff) - ABS;
    printf("DELTA_OF_3904=%llu  DELTA_OF_6432=%llu\n", (unsigned long long)dA, (unsigned long long)dB);
    printf("READ_POSITION_18280760608_EQUALS_MEASURED_ABS=%d\n", (18280760608ull == ABS) ? 1 : 0);
    if (18280760608ull != ABS) {
        const int64_t off = (int64_t)18280760608ll - (int64_t)ABS;
        printf("PRIOR_READ_OFFSET_DELTA=%lld\nPRIOR_READ_OFFSET_DELTA_MOD_144=%lld\n",
            (long long)off, (long long)(off % 144));
        printf("PRIOR_READ_WAS_BLOCK_ALIGNED=%d\n", (off % 144 == 0) ? 1 : 0);
    }

    printf("\n=== Q4_K BLOCK DUMP AT MEASURED ADDRESSES ===\n");
    const uint64_t bpr = (T.dims[0] + tr->blck - 1) / tr->blck;      // blocks per row
    const uint64_t rowStride = bpr * tr->bytes;
    const uint64_t expertStride = rowStride * T.dims[1];
    printf("BLOCKS_PER_ROW=%llu\nROW_STRIDE=%llu\nEXPERT_STRIDE=%llu\n",
        (unsigned long long)bpr, (unsigned long long)rowStride, (unsigned long long)expertStride);
    g_f = openPath(owner->path);
    if (!g_f) { printf("REOPEN_FAILED\n"); return 2; }
    int finite = 0, total = 0;
    struct { const char* l; uint64_t o; } pts[] = {
        { "expert0_row0_blk0", ABS },
        { "expert0_row0_blk1", ABS + tr->bytes },
        { "expert0_row1_blk0", ABS + rowStride },
        { "expert1_row0_blk0", ABS + expertStride },
    };
    for (auto& p : pts) { if (dumpQ4KBlock(p.o, p.l, tr->bytes)) ++finite; ++total; }
    // the disputed position, dumped for the record whatever the measurement says
    if (18280760608ull != ABS) dumpQ4KBlock(18280760608ull, "PRIOR_READ_18280760608", tr->bytes);
    if (3904ull + T.relOff != ABS) dumpQ4KBlock(3904ull + T.relOff, "CLAIM_3904_BASE", tr->bytes);
    fclose(g_f); g_f = nullptr;

    printf("\n=== RECEIPT ===\n");
    printf("SHARDS_PARSED=%zu\n", reps.size());
    printf("SHARD_FIRST_REL_OFF_ZERO=%d OF %d\n", firstZero, (int)reps.size());
    printf("SHARD_SEQ_PASS=%d\nSHARD_SUMPAD_PASS=%d\n", shardSeqPass, shardSumPass);
    printf("TARGET_MATCH_COUNT=%d\n", matches);
    printf("Q4K_SAMPLED_BLOCKS=%d\nQ4K_SAMPLED_FINITE_SCALES=%d\n", total, finite);
    const bool pass = (shardFail == 0) && (matches == 1) && (firstZero == (int)reps.size())
                   && (shardSeqPass == (int)reps.size()) && (shardSumPass == (int)reps.size())
                   && (ABS <= owner->fileSize) && (tb <= owner->fileSize - ABS) && (total == finite);
    printf("DATA_START_MEASURED_NOT_FITTED=1\n");
    printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    return pass ? 0 : 2;
}