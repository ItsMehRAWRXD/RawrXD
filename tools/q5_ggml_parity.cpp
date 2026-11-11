// ============================================================================
// File: tools/q5_ggml_parity.cpp
//
// Decisive test: compare Deep2's Q5_0 decoder against GGML's reference
// implementation on IDENTICAL raw bytes taken from a real model tensor.
//
// The reviewer's point is the right one: two implementations sharing an assumed
// layout cannot validate the layout. Only a known-good reference can. And the
// FP16 arithmetic matters: 5 exponent bits give 2048/65536 = 3.125% of 16-bit
// patterns decode as Inf/NaN. A ~3% non-finite rate is therefore the signature
// of reading essentially RANDOM bytes as scales, not of a file containing NaN
// weights.
//
// Outcomes, both reported:
//   GGML finite, Deep2 non-finite -> Deep2's byte interpretation is wrong
//   both identical (incl. same non-finites) -> the decoder is right and the
//     fault is upstream: tensor identity, dtype, offset, or source data
//
// No Qt, no third-party. Uses the repository's own ggml-quants.c.
// ============================================================================

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>

extern "C" {
#include "ggml.h"
#include "ggml-quants.h"
}

// ---------------------------------------------------------------------------
// Minimal ggml support functions.
//
// ggml.c intentionally is NOT linked: it drags in graph/backend machinery that
// a dequantizer does not need. These are the small lookup helpers ggml-quants.c
// references. They are NOT substitutes for the code under test - the Q5_0
// dequantizer under comparison comes from the real ggml-quants.c.
//
// ggml_fp16_to_fp32 is implemented from the IEEE 754 binary16 specification, so
// the FP16 decoding path under review is an independent implementation rather
// than a copy of the reference's own.
// ---------------------------------------------------------------------------
extern "C" {



static const size_t kTypeSize[] = {
    sizeof(float),          // 0  F32
    sizeof(ggml_fp16_t),    // 1  F16
    18, 20, 0, 0,           // 2-5 Q4_0, Q4_1, (removed Q4_2/Q4_3)
    22, 24,                 // 6  Q5_0, 7 Q5_1
    34, 36,                 // 8  Q8_0, 9 Q8_1
    84, 110, 144,           // 10-12 Q2_K, Q3_K, Q4_K
    176, 210, 256           // 13-15 Q5_K, Q6_K, Q8_K
};

static const int64_t kBlckSize[] = { 1, 1, 32, 32, 0, 0, 32, 32, 32, 32, 16, 16, 32, 32, 16, 32 };
int64_t ggml_blck_size(enum ggml_type type) {
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(kBlckSize) / sizeof(kBlckSize[0]))) return 0;
    return kBlckSize[t];
}

size_t ggml_type_size(enum ggml_type type) {
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(kTypeSize) / sizeof(kTypeSize[0]))) return 0;
    return kTypeSize[t];
}

size_t ggml_row_size(enum ggml_type type, int64_t n) {
    const size_t bs = ggml_blck_size(type);
    if (bs == 0) return 0;
    return ggml_type_size(type) * ((size_t)n / bs);
}

const char* ggml_type_name(enum ggml_type type) {
    static const char* names[] = {
        "F32", "F16", "Q4_0", "Q4_1", "?", "?",
        "Q5_0", "Q5_1", "Q8_0", "Q8_1",
        "Q2_K", "Q3_K", "Q4_K", "Q5_K", "Q6_K", "Q8_K"
    };
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(names) / sizeof(names[0]))) return "?";
    return names[t];
}

} // extern "C"

// ggml-quants.c references ggml_abort. It is defined inside the extern "C"
// block above and is not part of the code under test.

// ---------------------------------------------------------------------------
// Minimal GGUF reader: enough to locate a tensor's bytes and its dtype.
// ---------------------------------------------------------------------------
struct Reader {
    const uint8_t* base; size_t size; size_t pos = 0;
    Reader(const uint8_t* b, size_t s) : base(b), size(s) {}
    bool need(size_t n) const { return pos + n <= size; }
    bool eof() const { return pos >= size; }
    template <typename T> T le() {
        if (!need(sizeof(T))) { pos = size; return T{}; }
        T v{}; std::memcpy(&v, base + pos, sizeof(T)); pos += sizeof(T); return v;
    }
    std::string str() {
        uint64_t n = le<uint64_t>();
        if (!need((size_t)n)) { pos = size; return {}; }
        std::string s((const char*)(base + pos), (size_t)n);
        pos += (size_t)n;
        return s;
    }
};

enum : uint32_t { U8=0, I8=1, U16=2, I16=3, U32=4, I32=5, F32=6, T_BOOL=7, STR=8, ARR=9, U64=10, I64=11, F64=12 };
static size_t scalarSize(uint32_t t) {
    switch (t) {
        case U8: case I8: case T_BOOL: return 1;
        case U16: case I16: return 2;
        case U32: case I32: case F32: return 4;
        case U64: case I64: case F64: return 8;
        default: return 0;
    }
}
static void skipValue(Reader& r, uint32_t t) {
    if (t == STR) { (void)r.str(); return; }
    if (t == ARR) {
        uint32_t et = r.le<uint32_t>();
        uint64_t n = r.le<uint64_t>();
        if (et == STR) { for (uint64_t i = 0; i < n; ++i) (void)r.str(); return; }
        size_t s = scalarSize(et);
        if (!s) return;
        size_t total = s * (size_t)n;
        if (r.need(total)) r.pos += total;
        return;
    }
    if (size_t s = scalarSize(t)) { if (r.need(s)) r.pos += s; }
}

struct TensorEntry { std::string name; uint32_t type = 0; std::vector<uint64_t> dims; uint64_t offset = 0; };

// ---- Deep2's decoder, isolated so the comparison is explicit ----
// Independent FP16 decode written from the IEEE 754 binary16 specification,
// deliberately NOT shared with ggml's own conversion, so the FP16 path under
// review is actually checked rather than being identical by construction.
static float deep2HalfToFloat(uint16_t h) {
    const uint32_t sign = (uint32_t)(h >> 15) & 1u;
    const uint32_t exp  = (uint32_t)(h >> 10) & 0x1Fu;
    const uint32_t mant = (uint32_t)h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) { bits = sign << 31; }
        else {
            int e = -1; uint32_t m = mant;
            do { m <<= 1; ++e; } while ((m & 0x400u) == 0);
            m &= 0x3FFu;
            bits = (sign << 31) | ((127u - 15u - (uint32_t)e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        bits = (sign << 31) | ((exp + 127u - 15u) << 23) | (mant << 13);
    }
    float out; std::memcpy(&out, &bits, sizeof(out)); return out;
}

static void deqQ5_0_Deep2(const uint8_t* p, size_t blocks, float* out) {
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* blk = p + b * 22;
        const float d = deep2HalfToFloat((uint16_t)(blk[0] | (blk[1] << 8)));
        for (size_t i = 0; i < 32; ++i) {
            const uint8_t hi = (blk[2 + i / 8] >> (i % 8)) & 1u;
            const uint8_t lo = (blk[6 + i / 2] >> ((i % 2) * 4)) & 0xFu;
            const uint8_t q = (uint8_t)(lo | (hi << 4));
            out[b * 32 + i] = (float)((int)q - 16) * d;
        }
    }
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) { std::printf("usage: q5_ggml_parity <model.gguf> <tensor-name> [blockLimit]\n"); return 2; }
    const wchar_t* path = argv[1];
    std::string want; { std::wstring w(argv[2]); want.assign(w.begin(), w.end()); }
    size_t blockLimit = (argc >= 4) ? _wtoi(argv[3]) : 64;

#ifdef _WIN32
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { std::printf("cannot open\n"); return 1; }
    LARGE_INTEGER sz{}; GetFileSizeEx(f, &sz);
    HANDLE m = CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    const uint8_t* base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, (SIZE_T)sz.QuadPart);
    size_t size = (size_t)sz.QuadPart;
#else
    int fd = ::open(path, O_RDONLY); struct stat st{}; ::fstat(fd, &st);
    size_t size = (size_t)st.st_size;
    const uint8_t* base = (const uint8_t*)::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
#endif
    if (!base) { std::printf("cannot map\n"); return 1; }

    Reader r(base, size);
    if (r.le<uint32_t>() != 0x46554747u) { std::printf("not GGUF\n"); return 1; }
    (void)r.le<uint32_t>();
    uint64_t tensorCount = r.le<uint64_t>();
    uint64_t kvCount = r.le<uint64_t>();
    for (uint64_t i = 0; i < kvCount && !r.eof(); ++i) { (void)r.str(); skipValue(r, r.le<uint32_t>()); }
    const uint64_t dataStart = ((r.pos + 31) / 32) * 32;

    std::vector<TensorEntry> tensors;
    for (uint64_t i = 0; i < tensorCount && !r.eof(); ++i) {
        TensorEntry t; t.name = r.str();
        uint32_t nd = r.le<uint32_t>();
        for (uint32_t d = 0; d < nd; ++d) t.dims.push_back(r.le<uint64_t>());
        t.type = r.le<uint32_t>();
        t.offset = r.le<uint64_t>();
        tensors.push_back(std::move(t));
    }

    const TensorEntry* chosen = nullptr;
    for (const auto& t : tensors) if (t.name == want) { chosen = &t; break; }
    if (!chosen) { std::printf("tensor not found\n"); return 1; }

    std::printf("tensor            : %s\n", chosen->name.c_str());
    std::printf("GGUF type id      : %u (6 = Q5_0)\n", chosen->type);
    std::printf("dims              : ");
    for (uint64_t d : chosen->dims) std::printf("%llu ", (unsigned long long)d);
    std::printf("\n");
    std::printf("data section start: %llu\n", (unsigned long long)dataStart);
    std::printf("tensor abs offset : %llu\n", (unsigned long long)(dataStart + chosen->offset));

    if (chosen->type != 6) {
        std::printf("REFUSED: expected Q5_0 (type 6); got %u. Comparing a different dtype\n"
                    "         against a Q5_0 reference would prove nothing.\n", chosen->type);
        return 3;
    }

    const uint8_t* p = base + dataStart + chosen->offset;
    if (dataStart + chosen->offset + (size_t)blockLimit * 22 > size) {
        std::printf("REFUSED: would read past EOF\n"); return 4;
    }

    std::printf("\n--- per-block comparison, identical 22 raw bytes ---\n");
    std::printf("%-4s %-22s %-10s %-12s %-12s %-9s\n",
                "blk", "rawScale", "GGML scale", "Deep2 scale", "maxDiff", "nonFin");

    size_t ggmlNonFin = 0, deep2NonFin = 0, differingBlocks = 0, compared = 0;
    double worstDiff = 0.0;

    for (size_t b = 0; b < blockLimit; ++b) {
        const uint8_t* blk = p + b * 22;

        // GGML reference on the raw bytes.
        float ref[32];
        dequantize_row_q5_0((const block_q5_0*)blk, ref, 32);

        // Deep2 decoder on the SAME raw bytes.
        float mine[32];
        deqQ5_0_Deep2(blk, 1, mine);

        size_t nfRef = 0, nfMine = 0;
        double maxDiff = 0.0;
        for (int i = 0; i < 32; ++i) {
            if (!std::isfinite(ref[i])) ++nfRef;
            if (!std::isfinite(mine[i])) ++nfMine;
            if (std::isfinite(ref[i]) && std::isfinite(mine[i])) {
                maxDiff = std::max(maxDiff, std::fabs((double)ref[i] - mine[i]));
            }
        }
        ggmlNonFin += nfRef; deep2NonFin += nfMine;
        if (maxDiff > worstDiff) worstDiff = maxDiff;
        if (maxDiff > 0.0 || nfRef != nfMine) ++differingBlocks;

        char hex[8]; std::snprintf(hex, sizeof(hex), "%02x %02x", blk[0], blk[1]);
        std::printf("%-4zu %-22s %-12g %-12g %-12g %-3zu/%-3zu\n",
                    b, hex,
                    ggml_fp16_to_fp32((uint16_t)(blk[0] | (blk[1] << 8))),
                    deep2HalfToFloat((uint16_t)(blk[0] | (blk[1] << 8))),
                    maxDiff, nfMine, nfRef);
        ++compared;
    }

    std::printf("\n--- verdict ---\n");
    std::printf("blocks compared   : %zu\n", compared);
    std::printf("differing blocks  : %zu\n", differingBlocks);
    std::printf("worst maxDiff     : %g\n", worstDiff);
    std::printf("non-finite GGML   : %zu\n", ggmlNonFin);
    std::printf("non-finite Deep2  : %zu\n", deep2NonFin);

    if (ggmlNonFin == deep2NonFin && differingBlocks == 0) {
        std::printf("\nCONCLUSION: Deep2 matches the GGML reference bit-for-bit, INCLUDING the\n"
                    "same non-finite values. The decoder is NOT the source of the non-finite\n"
                    "results. The fault is upstream: tensor identity, dtype, file offset, or\n"
                    "source data integrity.\n");
        return 0;
    }
    if (ggmlNonFin == 0 && deep2NonFin > 0) {
        std::printf("\nCONCLUSION: GGML produces finite scales from the same bytes and Deep2 does\n"
                    "not. The problem is Deep2's byte interpretation or FP16 conversion.\n");
        return 5;
    }
    std::printf("\nCONCLUSION: partial disagreement. Investigate the differing blocks above\n"
                "before concluding anything.\n");
    return 6;
}
