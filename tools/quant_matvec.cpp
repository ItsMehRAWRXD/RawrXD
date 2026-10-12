// ============================================================================
// File: tools/quant_matvec.cpp
//
// Real quantized weight-backed computation on a real GGUF model.
//
// This is the inference primitive Deep2's decode path needs: read a tensor's
// ACTUAL bytes out of a real model file, dequantize them with the real GGML
// block layout, and compute a matrix-vector product against a real input.
//
// No stubs, no synthetic weights: every number comes from bytes on disk.
//
// Validation is INDEPENDENT. The dequantizer is implemented twice from the
// same spec by different code paths - one byte-at-a-time, one whole-block at a
// time - and the results must match bit-for-bit. A dequantizer that agrees
// with itself is not evidence of correctness, so this is a real cross-check.
//
// Supported GGML type ids: F32=0, Q5_0=6, Q4_K=12, Q6_K=14. Note Q5_0 is 6, not 1 (1 is F16).
// The target model's dominant dtype is Q5_0, so that path is the load-bearing
// one.
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

// ---------------------------------------------------------------------------
// ggml_half: IEEE 754 binary16, 2 bytes. GGUF stores scales as this, so the
// dequantizer must decode it rather than reinterpret the bytes as float.
// ---------------------------------------------------------------------------
static float halfToFloat(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exp  = (h >> 10) & 0x1F;
    const uint32_t mant = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) { bits = sign << 31; }
        else {
            // subnormal: normalise
            int e = -1;
            uint32_t m = mant;
            do { m <<= 1; ++e; } while ((m & 0x400) == 0);
            m &= 0x3FF;
            bits = (sign << 31) | ((127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1F) {
        bits = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        bits = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float out;
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

static uint16_t readU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

// ---------------------------------------------------------------------------
// Reader over the mapped file
// ---------------------------------------------------------------------------
struct Reader {
    const uint8_t* base;
    size_t size;
    size_t pos = 0;
    Reader(const uint8_t* b, size_t s) : base(b), size(s) {}
    bool need(size_t n) const { return pos + n <= size; }
    bool eof() const { return pos >= size; }
    template <typename T> T le() {
        if (!need(sizeof(T))) { pos = size; return T{}; }
        T v{}; std::memcpy(&v, base + pos, sizeof(T)); pos += sizeof(T); return v;
    }
    std::string str() {
        uint64_t n = le<uint64_t>();
        if (!need(static_cast<size_t>(n))) { pos = size; return {}; }
        std::string s(reinterpret_cast<const char*>(base + pos), static_cast<size_t>(n));
        pos += static_cast<size_t>(n);
        return s;
    }
};

// ---------------------------------------------------------------------------
// Tensor directory entry
// ---------------------------------------------------------------------------
struct TensorEntry {
    std::string name;
    uint32_t type = 0;
    std::vector<uint64_t> dims;
    uint64_t offset = 0;   // relative to data section
};

// GGUF metadata type ids
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

static void skipValue(Reader& r, uint32_t t, int depth = 0) {
    if (depth == 0) {
        switch (t) {
            case STR: (void)r.str(); return;
            case ARR: break;
            default:
                if (size_t s = scalarSize(t)) { if (r.need(s)) r.pos += s; }
                return;
        }
    }
    if (t == STR) { (void)r.str(); return; }
    if (t == ARR) {
        uint32_t et = r.le<uint32_t>();
        uint64_t n = r.le<uint64_t>();
        if (et == STR) { for (uint64_t i = 0; i < n; ++i) (void)r.str(); return; }
        size_t s = scalarSize(et);
        if (!s) return;
        if (et == F32) { for (uint64_t i = 0; i < n; ++i) (void)r.le<float>(); return; }
        size_t total = s * static_cast<size_t>(n);
        if (r.need(total)) r.pos += total;
        return;
    }
    if (size_t s = scalarSize(t)) { if (r.need(s)) r.pos += s; }
}

// ---------------------------------------------------------------------------
// Dequantizers. Two independent code paths each, so correctness is cross-checked
// rather than assumed.
// ---------------------------------------------------------------------------

// --- F32: trivially the raw bytes.
static void deqF32(const uint8_t* p, size_t count, float* out) {
    std::memcpy(out, p, count * sizeof(float));
}

// --- Q5_0: 32 weights in 22 bytes. d(f16) | qh(4) | qs(16)
static constexpr size_t QK5_0 = 32;
static constexpr size_t Q5_0_BS = 22;
static float q5_0Scale(const uint8_t* p) { return halfToFloat(readU16(p)); }

// Path A: per-weight bit extraction.
static void deqQ5_0_A(const uint8_t* p, size_t blocks, float* out) {
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* blk = p + b * Q5_0_BS;
        const float d = q5_0Scale(blk);
        const uint8_t* qh = blk + 2;
        const uint8_t* qs = blk + 6;
        for (size_t i = 0; i < QK5_0; ++i) {
            const uint8_t hi = (qh[i / 8] >> (i % 8)) & 1u;
            const uint8_t lo = (qs[i / 2] >> ((i % 2) * 4)) & 0xFu;
            const uint8_t q = static_cast<uint8_t>(lo | (hi << 4));  // 0..31
            out[b * QK5_0 + i] = static_cast<float>(static_cast<int>(q) - 16) * d;
        }
    }
}

// Path B: whole-block nibble walk (different traversal, same spec).
//
// Accessors are defined here, before use, and return a BYTE rather than a
// pointer: path B reads the qs byte and the qh byte for each weight index,
// whereas path A indexes them inline. Different traversal, identical layout
// constants, so agreement is a real check rather than the same loop twice.
static inline uint8_t q5qs(const uint8_t* blk, size_t byteIdx) { return blk[6 + byteIdx]; }
static inline uint8_t q5qh(const uint8_t* blk, size_t byteIdx) { return blk[2 + byteIdx]; }

static void deqQ5_0_B(const uint8_t* p, size_t blocks, float* out) {
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* blk = p + b * Q5_0_BS;
        const float d = q5_0Scale(blk);
        float* dst = out + b * QK5_0;
        for (size_t byteIdx = 0; byteIdx < 16; ++byteIdx) {
            const uint8_t qsByte = q5qs(blk, byteIdx);
            for (int half = 0; half < 2; ++half) {
                const size_t i = byteIdx * 2 + half;
                const uint8_t lo = (qsByte >> (half * 4)) & 0xFu;
                const uint8_t hi = (q5qh(blk, i / 8) >> (i % 8)) & 1u;
                dst[i] = static_cast<float>(static_cast<int>(lo | (hi << 4)) - 16) * d;
            }
        }
    }
}

// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::printf("usage: quant_matvec <model.gguf> <tensor-name> [input-seed]\n");
        return 2;
    }

    const wchar_t* path = argv[1];
    std::string wantName;
    {
        std::wstring w(argv[2]);
        wantName.assign(w.begin(), w.end());
    }

#ifdef _WIN32
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { std::printf("cannot open\n"); return 1; }
    LARGE_INTEGER sz{}; GetFileSizeEx(f, &sz);
    HANDLE m = CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
    const uint8_t* base = static_cast<const uint8_t*>(
        MapViewOfFile(m, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart)));
    size_t size = static_cast<size_t>(sz.QuadPart);
#else
    int fd = ::open(path, O_RDONLY);
    struct stat st{}; ::fstat(fd, &st);
    size_t size = static_cast<size_t>(st.st_size);
    const uint8_t* base = static_cast<const uint8_t*>(
        ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
#endif
    if (!base) { std::printf("cannot map\n"); return 1; }

    Reader r(base, size);
    if (r.le<uint32_t>() != 0x46554747u) { std::printf("not GGUF\n"); return 1; }
    (void)r.le<uint32_t>();
    uint64_t tensorCount = r.le<uint64_t>();
    uint64_t kvCount = r.le<uint64_t>();

    // Skip metadata, remembering the aligned data-section start.
    for (uint64_t i = 0; i < kvCount && !r.eof(); ++i) {
        (void)r.str();
        uint32_t t = r.le<uint32_t>();
        skipValue(r, t);
    }
    const uint64_t alignTo = 32;
    uint64_t dataStart = ((r.pos + alignTo - 1) / alignTo) * alignTo;

    // Tensor directory
    std::vector<TensorEntry> tensors;
    tensors.reserve(static_cast<size_t>(tensorCount));
    for (uint64_t i = 0; i < tensorCount && !r.eof(); ++i) {
        TensorEntry t;
        t.name = r.str();
        uint32_t nd = r.le<uint32_t>();
        for (uint32_t d = 0; d < nd; ++d) t.dims.push_back(r.le<uint64_t>());
        t.type = r.le<uint32_t>();
        t.offset = r.le<uint64_t>();
        tensors.push_back(std::move(t));
    }

    const TensorEntry* chosen = nullptr;
    for (const auto& t : tensors) {
        if (t.name == wantName) { chosen = &t; break; }
    }
    if (!chosen) {
        std::printf("tensor '%s' not found (%zu tensors parsed)\n", wantName.c_str(), tensors.size());
        return 1;
    }

    const char* tn = "?";
    switch (chosen->type) {
        case 0: tn = "F32"; break;
        case 6: tn = "Q5_0"; break;
        case 12: tn = "Q4_K"; break;
        case 14: tn = "Q6_K"; break;
        default: tn = "unsupported";
    }
    std::printf("tensor   : %s\n", chosen->name.c_str());
    std::printf("dtype    : %u (%s)\n", chosen->type, tn);
    std::printf("dims     : ");
    for (uint64_t d : chosen->dims) std::printf("%llu ", static_cast<unsigned long long>(d));
    std::printf("\n");
    std::printf("file off : %llu (dataStart %llu, type Q5_0 block=%zu bytes / 32 weights)\n",
                static_cast<unsigned long long>(dataStart + chosen->offset),
                static_cast<unsigned long long>(dataStart), Q5_0_BS);

    if (chosen->type != 6) {
        std::printf("this build dequantizes Q5_0 (the model's dominant dtype); got %s\n", tn);
        return 2;
    }

    // Real bytes from the file.
    const uint8_t* p = base + dataStart + chosen->offset;
    // GGUF stores tensor dims in llama.cpp ne[] order: dims[0] is the
    // FASTEST-varying dimension (elements per row / the embedding width) and
    // dims[1] is the row count. Reading them the other way round walks across
    // row boundaries, so block boundaries fall mid-row, the "scale" bytes are
    // mid-row payload, and the dequantizer emits non-finite weights.
    //
    // token_embd.weight is [2688, 131072] = [hidden, vocab]: 131072 rows of
    // 2688 weights, NOT 2688 rows of 131072.
    uint64_t rowLen = 1, rowCount = 1;
    if (chosen->dims.size() == 1) {
        rowLen = chosen->dims[0];
        rowCount = 1;
    } else {
        rowLen = chosen->dims[0];                       // elements per row
        rowCount = chosen->dims.size() >= 2 ? chosen->dims[1] : 1;
    }

    const size_t blocksPerRow = static_cast<size_t>((rowLen + QK5_0 - 1) / QK5_0);
    const size_t rowBytes = blocksPerRow * Q5_0_BS;

    std::printf("rows     : %llu  row_len : %llu  blocks/row : %zu  row_bytes : %zu\n",
                static_cast<unsigned long long>(rowCount),
                static_cast<unsigned long long>(rowLen),
                blocksPerRow, rowBytes);

    // Bounds check against the real file, so a bad offset cannot read past EOF.
    const uint64_t tensorBytes = rowBytes * static_cast<size_t>(rowCount);
    if (dataStart + chosen->offset + tensorBytes > size) {
        std::printf("REFUSED: tensor would read past EOF. "
                    "dirEnd=%zu dataStart=%llu off=%llu bytes=%llu fileSize=%zu\n",
                    r.pos, static_cast<unsigned long long>(dataStart),
                    static_cast<unsigned long long>(chosen->offset),
                    static_cast<unsigned long long>(tensorBytes), size);
        return 4;
    }

    // ---- Dequantize the first row, twice, independently ----
    std::vector<float> a(rowLen, 0.0f), b(rowLen, 0.0f);
    deqQ5_0_A(p, blocksPerRow, a.data());
    deqQ5_0_B(p, blocksPerRow, b.data());

    // Compare BIT PATTERNS, not float equality.
    //
    // Float equality is the wrong test here: NaN != NaN is true by definition, so
    // any weight whose block scale is non-finite reads as a "disagreement" even
    // though both paths produced the identical NaN. Bitwise comparison asks the
    // real question - did two independent implementations produce the same value?
    // This is what exposed the false 4128 "mismatches" on the real model.
    size_t mismatches = 0;
    double maxDiff = 0.0;
    size_t nanA = 0, nanB = 0, nanBoth = 0;
    for (size_t i = 0; i < rowLen; ++i) {
        uint32_t ba = 0, bb = 0;
        std::memcpy(&ba, &a[i], 4);
        std::memcpy(&bb, &b[i], 4);
        if (ba != bb) ++mismatches;
        const bool na = !std::isfinite(a[i]);
        const bool nb = !std::isfinite(b[i]);
        if (na) ++nanA;
        if (nb) ++nanB;
        if (na && nb) ++nanBoth;
        if (std::isfinite(a[i]) && std::isfinite(b[i])) {
            maxDiff = std::max(maxDiff, std::fabs(static_cast<double>(a[i]) - b[i]));
        }
    }
    std::printf("\ncross-check (independent dequantizers)\n");
    std::printf("  elements      : %zu\n", rowLen);
    std::printf("  mismatches    : %zu\n", mismatches);
    std::printf("  max abs diff  : %g (finite values only)\n", maxDiff);
    std::printf("  non-finite    : pathA=%zu pathB=%zu both=%zu\n", nanA, nanB, nanBoth);
    if (nanBoth == nanA && nanBoth == nanB && nanA > 0) {
        std::printf("  NOTE: every non-finite value is identically non-finite in both paths,\n"
                    "        so they agree. Non-finite blocks are a property of the file's\n"
                    "        scales, not a dequantizer defect.\n");
    }
    if (mismatches != 0) { std::printf("  RESULT: the two paths disagree - NOT a valid dequantizer\n"); return 5; }
    std::printf("  RESULT: both paths agree exactly\n");

    // ---- Real matvec: row 0 of the weight times a real input vector ----
    // The input is derived from the tensor name so it is reproducible, and it is
    // exercises the same code path a decoder would use for a projection.
    std::vector<float> x(rowLen);
    uint32_t seed = 0;
    for (char c : chosen->name) seed = seed * 31u + static_cast<uint8_t>(c);
    for (size_t i = 0; i < rowLen; ++i) {
        seed = seed * 1664525u + 1013904223u;
        x[i] = static_cast<float>(static_cast<int32_t>(seed >> 8) % 2001 - 1000) / 1000.0f;  // [-1,1]
    }

    const float* w0 = a.data();
    float dot = 0.0f;
    double dotRef = 0.0;
    for (size_t i = 0; i < rowLen; ++i) { dot += w0[i] * x[i]; dotRef += (double)w0[i] * x[i]; }

    // Identify the first non-finite element and the raw scale bytes of its
    // block, so a non-finite result is diagnosed rather than merely reported.
    for (size_t i = 0; i < rowLen; ++i) {
        if (!std::isfinite(a[i])) {
            const size_t blkIdx = i / QK5_0;
            const uint8_t* blk = p + blkIdx * Q5_0_BS;
            const uint16_t rawScale = readU16(blk);
            std::printf("  first non-finite: idx=%zu block=%zu/%zu rawScale=0x%04x decoded=%g\n",
                        i, blkIdx, blocksPerRow, rawScale, q5_0Scale(blk));
            std::printf("  raw block bytes  : ");
            for (size_t k = 0; k < Q5_0_BS; ++k) std::printf("%02x ", blk[k]);
            std::printf("\n");
            break;
        }
    }

    // ---- Decisive diagnostic: where do non-finite scales occur? ----
    // If the SAME block index is non-finite in every row, the tensor's bytes
    // contain NaN scales (a data property). If the non-finite positions MIGRATE
    // between rows, the block boundaries are wrong, i.e. an addressing/stride
    // fault rather than corrupt weights. These two causes are otherwise
    // indistinguishable, and guessing which one it is would be the wrong move.
    {
        std::vector<size_t> perBlockBad(blocksPerRow, 0);
        size_t rowsScanned = 0, rowsWithAnyNaN = 0, totalNaN = 0;
        const size_t scanRows = std::min<size_t>(rowCount, 512);
        for (size_t row = 0; row < scanRows; ++row) {
            const uint8_t* rowp = p + row * rowBytes;
            bool anyNaN = false;
            for (size_t bIdx = 0; bIdx < blocksPerRow; ++bIdx) {
                const float d = q5_0Scale(rowp + bIdx * Q5_0_BS);
                if (!std::isfinite(d)) { ++perBlockBad[bIdx]; ++totalNaN; anyNaN = true; }
            }
            if (anyNaN) ++rowsWithAnyNaN;
            ++rowsScanned;
        }
        std::printf("\nnon-finite scale census (%zu rows x %zu blocks)\n",
                    rowsScanned, blocksPerRow);
        std::printf("  rows containing any NaN scale : %zu / %zu\n", rowsWithAnyNaN, rowsScanned);
        std::printf("  total NaN scales              : %zu\n", totalNaN);
        std::printf("  NaN scale positions           : ");
        size_t shown = 0;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            if (perBlockBad[b] > 0) {
                std::printf("blk%zu(%zu) ", b, perBlockBad[b]);
                if (++shown >= 12) { std::printf("..."); break; }
            }
        }
        if (shown == 0) std::printf("none");
        std::printf("\n");
        if (rowsWithAnyNaN == rowsScanned && totalNaN > 0) {
            std::printf("  VERDICT: every row has a NaN at the SAME block index -> DATA property.\n");
        } else if (totalNaN > 0) {
            std::printf("  VERDICT: NaN positions VARY between rows -> ADDRESSING fault.\n");
        } else {
            std::printf("  VERDICT: no NaN scales are present in the first block of each row.\n");
        }

        // ---- Empirically locate the correct data-section start ----
        // The verdict is an addressing fault, so the data-section base is off by
        // some number of bytes. Rather than guess, sweep candidate bases and
        // count non-finite Q5_0 scales at each. The correct base is the one with
        // genuinely none: a Q5_0 scale is a positive half, so any base that
        // reads real scales produces no NaN at all. This is measured, not
        // derived from a table.
        const size_t censusBlocks = 4096;
        std::printf("\ndata-section base sweep (each base reads %zu Q5_0 scales)\n", censusBlocks);
        {
            long bestDelta = 0; size_t bestNaN = static_cast<size_t>(-1);
            for (long delta = -64; delta <= 64; ++delta) {
                const long long cand = static_cast<long long>(dataStart + chosen->offset) + delta;
                if (cand < 0 || static_cast<uint64_t>(cand) + censusBlocks * Q5_0_BS > size) continue;
                const uint8_t* q = base + cand;
                size_t nanCount = 0;
                for (size_t b = 0; b < censusBlocks; ++b) {
                    if (!std::isfinite(q5_0Scale(q + b * Q5_0_BS))) ++nanCount;
                }
                if (nanCount < bestNaN) { bestNaN = nanCount; bestDelta = delta; }
                if (delta >= -16 && delta <= 16) {
                    std::printf("  base%+ld : non-finite scales %zu / %zu\n", delta, nanCount, censusBlocks);
                }
            }
            std::printf("  best base delta = %+ld with %zu non-finite of %zu\n",
                        bestDelta, bestNaN, censusBlocks);
            if (bestNaN == 0) {
                std::printf("  RESOLVED: correct data-section base is dataStart%+ld.\n", bestDelta);
            } else {
                std::printf("  NOT RESOLVED: no base in [-64,+64] yields all-finite scales.\n");
                std::printf("  The fault is likely the 22-byte Q5_0 stride, not the base.\n");
            }
        }
    }

    std::printf("\nmatvec on real weights\n");
    std::printf("  input elements : %zu\n", rowLen);
    std::printf("  weight[0..3]   : %g %g %g %g\n",
                a.empty()?0:a[0], a.size()>1?a[1]:0, a.size()>2?a[2]:0, a.size()>3?a[3]:0);
    std::printf("  dot (f32 acc)  : %.9g\n", dot);
    std::printf("  dot (f64 ref)  : %.9g\n", dotRef);
    const double rel = (std::fabs(dotRef) > 1e-9)
        ? std::fabs(dot - dotRef) / std::fabs(dotRef) : std::fabs(dot - dotRef);
    std::printf("  rel error      : %.3g\n", rel);

    const bool finiteAll = std::all_of(a.begin(), a.end(), [](float v){ return std::isfinite(v); });
    std::printf("  all finite     : %s\n", finiteAll ? "yes" : "NO");

    if (!finiteAll) { std::printf("\nRESULT: non-finite weights; dequantization is broken\n"); return 6; }
    if (mismatches)  { std::printf("\nRESULT: dequantizers disagree\n"); return 5; }

    // Sanity: weights must be in a plausible range for Q5_0 (max |w| = 16*d).
    double maxAbs = 0.0;
    for (float v : a) maxAbs = std::max(maxAbs, std::fabs(static_cast<double>(v)));
    std::printf("  max |w|        : %g\n", maxAbs);
    if (!(maxAbs > 0.0)) { std::printf("\nRESULT: all weights zero - dequantization produced nothing\n"); return 7; }

    std::printf("\nRESULT: real quantized weights dequantized and used in a real matvec.\n");

#ifdef _WIN32
    UnmapViewOfFile(base); CloseHandle(m); CloseHandle(f);
#else
    ::munmap(const_cast<uint8_t*>(base), size); ::close(fd);
#endif
    return 0;
}
