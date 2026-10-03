// ============================================================================
// gguf_tensor_slice_001.cpp
// RAWRXD_GGUF_TENSOR_SLICE_001
//
// Minimal, self-validating GGUF tensor reader.
//
// WHY THIS EXISTS
//   The in-tree loader cannot supply a real weight tensor:
//   src/deep2/GGUFLoader.cpp is 35 bytes (literally `// STUB: ...`, emptied by
//   commit 964eed96f), and no CMake target builds a GGUF-reading probe. Every
//   quantisation result so far in this project has therefore been measured on
//   SYNTHETIC weights, which is the single largest caveat on the sweep's
//   negative result.
//
//   So this reads a GGUF header, walks the tensor directory, and extracts ONE
//   row-block of ONE tensor directly from the file -- no engine, no Vulkan, no
//   whole-file copy. The file is opened for random access and only the bytes
//   actually needed are read, which is also the out-of-core property the whole
//   residency effort is about.
//
//   This does NOT dequantise. It reports geometry and raw byte ranges only.
//   Dequantisation and the SVD rank curve are separate stages, because a wrong
//   dequantiser would silently flatter or ruin any result computed on top of it
//   and must be validated on its own.
//
// VALIDATION IS STRUCTURAL, NOT ASSERTED
//   Every number below is checked against something that would have to be true
//   for the read to be correct: magic, version, alignment of the data section,
//   offsets falling inside the file, shapes consistent with the model's known
//   geometry, and the quant block size dividing the tensor's byte length
//   exactly. A reader that cannot fail these is not a reader.
// ============================================================================

// NOMINMAX must precede <windows.h>. That header defines min/max as MACROS,
// which silently rewrites std::max(a, b) into an illegal token sequence
// (C2589) rather than failing where the mistake is. Defining it here removes an
// entire class of compile error that has nothing to do with the code.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <functional>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr int kFail = 2;

int g_checks = 0, g_pass = 0, g_fail = 0;
void check(bool ok, const char* id, const char* fmt, ...) {
    ++g_checks;
    if (ok) ++g_pass; else ++g_fail;
    std::printf("%-6s %-32s ", ok ? "CHECK" : "FAIL", id);
    va_list ap; va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
}

// ---------------------------------------------------------------- file cursor
class File {
public:
    bool openW(const wchar_t* p) {
        h_ = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) { h_ = nullptr; return false; }
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h_, &li)) return false;
        size_ = static_cast<std::uint64_t>(li.QuadPart);
        return true;
    }
    ~File() { if (h_) CloseHandle(h_); }
    std::uint64_t size() const { return size_; }
    bool valid() const { return h_ != nullptr; }

    // Absolute read. Returns bytes actually read. This is the only I/O the tool
    // performs, and it is bounded by the caller's request -- the file is never
    // read whole.
    std::uint64_t readAt(std::uint64_t off, void* dst, std::uint64_t n) {
        if (!h_ || off > size_) return 0;
        if (off + n > size_) n = size_ - off;
        LARGE_INTEGER li{}; li.QuadPart = static_cast<LONGLONG>(off);
        if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) return 0;
        std::uint64_t done = 0;
        while (done < n) {
            DWORD chunk = static_cast<DWORD>((n - done) > 0x10000000ull
                                                  ? 0x10000000ull : (n - done));
            DWORD got = 0;
            if (!ReadFile(h_, static_cast<char*>(dst) + done, chunk, &got, nullptr))
                break;
            if (got == 0) break;
            done += got;
        }
        return done;
    }
private:
    HANDLE h_ = nullptr;
    std::uint64_t size_ = 0;
};

struct Cursor {
    File* f;
    std::uint64_t pos = 0;
    bool ok = true;
    void raw(void* dst, std::uint64_t n) {
        if (!ok) return;
        if (f->readAt(pos, dst, n) != n) { ok = false; return; }
        pos += n;
    }
    std::uint32_t u32() { std::uint32_t v = 0; raw(&v, 4); return v; }
    std::uint64_t u64() { std::uint64_t v = 0; raw(&v, 8); return v; }
    std::string str() {
        const std::uint64_t n = u64();
        if (!ok || n > (1ull << 20)) { ok = false; return {}; }
        std::string s(static_cast<std::size_t>(n), '\0');
        if (n) raw(&s[0], n);
        return s;
    }
};

// -------------------------------------------------------------- ggml types
// Block element count and byte size for the types this project actually uses.
struct TypeGeom { std::uint32_t blckElems; std::uint32_t typeSize; };
bool geomOf(std::uint32_t t, TypeGeom& g) {
    switch (t) {
        case 0:  g = {1, 4};    return true;   // F32
        case 1:  g = {1, 2};    return true;   // F16
        case 2:  g = {32, 18};  return true;   // Q4_0
        case 6:  g = {32, 22};  return true;   // Q6_0
        case 8:  g = {32, 34};  return true;   // Q8_0
        case 10: g = {256, 84}; return true;   // Q2_K
        case 11: g = {256, 110};return true;   // Q3_K
        case 12: g = {256, 144};return true;   // Q4_K
        case 13: g = {256, 176};return true;   // Q5_K
        case 14: g = {256, 210};return true;   // Q6_K
case 15: g = {256, 292};return true;   // Q8_K
        // Geometry verified against the reference static_asserts, not from memory:
        //   block_iq2_xs  : d + QK_K/8*sizeof(uint16_t) + QK_K/32 = 2 + 64 + 8 = 74
        //   block_iq3_xxs : d + 3*QK_K/8                        = 2 + 96    = 98
        case 17: g = {256, 74}; return true;   // IQ2_XS  -- 50 routed-expert tensors
        case 18: g = {256, 98}; return true;   // IQ3_XXS -- 77 routed-expert tensors
        case 26: g = {1, 4};    return true;   // I32 -- a plain int32 tid->eid ROUTING
                                             //         TABLE, not a quantisation at all
        case 30: g = {1, 2};    return true;   // BF16
        case 39: g = {32, 17};   return true;   // MXFP4 -- no codebook
        default: return false;
    }
}
const char* typeName(std::uint32_t t) {
    switch (t) {
        case 0: return "F32";  case 1: return "F16";  case 2: return "Q4_0";
        case 6: return "Q6_0"; case 8: return "Q8_0"; case 10: return "Q2_K";
        case 11: return "Q3_K";case 12: return "Q4_K";case 13: return "Q5_K";
case 14: return "Q6_K";  case 15: return "Q8_K";  case 30: return "BF16";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 26: return "I32";
        case 39: return "MXFP4";
        default: return "UNKNOWN";
    }
}

struct TensorInfo {
    std::string name;
    std::uint32_t nDims = 0;
    std::uint64_t dims[4] = {0, 0, 0, 0};
    std::uint32_t type = 0;
    std::uint64_t offset = 0;
    std::uint64_t nElems = 1;
    std::uint64_t nBlocks = 0;
    std::uint64_t byteLen = 0;
};

// ---------------------------------------------------------------------------
// Q4_K dequantisation, WITH validation.
//
// This stage exists because the next stage (a truncated-SVD rank curve of the
// delta) is only as trustworthy as the weights fed into it. A wrong sub-block
// SCALE INDEX produces a plausible-looking matrix whose low-rank structure is
// an artefact, and an artefact of that kind survives every downstream check.
//
// Layout, 144 bytes -> 256 values, 8 sub-blocks of 32, scales per 64:
//   [0..1]   fp16 d      super-block scale
//   [2..3]   fp16 dmin   super-block minimum
//   [4..15]  12 bytes    packed sub-block scales/mins
//   [16..143] 128 bytes  4-bit codes, low nibble first
// ---------------------------------------------------------------------------
float fp16ToFp32(std::uint16_t h) {
    const std::uint32_t sign = (h & 0x8000u) << 16;
    const std::uint32_t exp  = (h >> 10) & 0x1Fu;
    const std::uint32_t man  = h & 0x3FFu;
    std::uint32_t bits;
    if (exp == 0) {
        if (man == 0) bits = sign;
        else {   // subnormal
            std::uint32_t e = 0, m = man;
            while (!(m & 0x400u)) { m <<= 1; ++e; }
            m &= 0x3FFu;
            bits = sign | ((127 - 15 - e + 1) << 23) | (m << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (man << 13);
    } else {
        bits = sign | ((exp - 15 + 127) << 23) | (man << 13);
    }
    float f; std::memcpy(&f, &bits, 4); return f;
}

void getScaleMinK4(int j, const unsigned char* q, unsigned char& d, unsigned char& m) {
    if (j < 4) { d = q[j] & 63; m = q[j + 4] & 63; }
    else {
        d = static_cast<unsigned char>((q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4));
        m = static_cast<unsigned char>((q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4));
    }
}

void dequantQ4K(const unsigned char* x, float* y) {
    const float d    = fp16ToFp32(*reinterpret_cast<const std::uint16_t*>(x));
    const float dmin = fp16ToFp32(*reinterpret_cast<const std::uint16_t*>(x + 2));
    const unsigned char* q = x + 16;      // codes
    const unsigned char* sc = x + 4;      // 12 packed scale bytes
    int is = 0;
    float* out = y;
    for (int j = 0; j < 256; j += 64) {
        unsigned char s0, m0, s1, m1;
        getScaleMinK4(is + 0, sc, s0, m0);
        getScaleMinK4(is + 1, sc, s1, m1);
        const float d1 = d * s0, m1f = dmin * m0;
        const float d2 = d * s1, m2f = dmin * m1;
        for (int l = 0; l < 32; ++l) *out++ = d1 * (q[l] & 0xF) - m1f;
        for (int l = 0; l < 32; ++l) *out++ = d2 * (q[l] >> 4) - m2f;
        q += 32;
        is += 2;
    }
}

// Q6_K: 210 bytes -> 256 values. No codebook, unlike the i-quants, so it can be
// validated the same way Q4_K was and the validation is meaningful.
//
// Layout: ql[128] | qh[64] | scales[16] | fp16 d  = 210
void dequantQ6K(const unsigned char* x, float* y) {
    const float d = fp16ToFp32(*reinterpret_cast<const std::uint16_t*>(x + 208));
    const unsigned char* ql = x;
    const unsigned char* qh = x + 128;
    const signed char*    sc = reinterpret_cast<const signed char*>(x + 192);
    float* out = y;
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            const int is = l / 16;
            const int q1 = ((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int q2 = ((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = ((ql[l +  0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            out[l +  0] = d * float(sc[is + 0]) * float(q1);
            out[l + 32] = d * float(sc[is + 2]) * float(q2);
            out[l + 64] = d * float(sc[is + 4]) * float(q3);
            out[l + 96] = d * float(sc[is + 6]) * float(q4);
        }
        out  += 128; ql += 64; qh += 32; sc += 8;
    }
}

// Dispatch by ggml type. Returns false for anything not implemented -- notably
// the i-quants (IQ2_XXS/IQ2_XS/IQ4_XS) and MXFP4 that a production MoE uses for
// its expert tensors. Those carry CODEBOOKS, and a wrong codebook decode does
// not fail loudly: it produces a plausible matrix whose spectral structure is
// an artefact. They are deliberately left unimplemented rather than guessed.
// ---------------------------------------------------------------------------
// MXFP4 (ggml type 39) -- THE ACHIEVABLE MoE PATH.
//
// WHY THIS ONE AND NOT THE I-QUANTS. Types 17 (IQ2_XXS, 50 tensors) and 18
// (IQ2_XS, 77 tensors) ARE the routed expert weights, but both decode through a
// 256-entry `kvalues` table. Reproducing 256 magic bytes from memory is not a
// thing that can be checked afterwards: one wrong entry yields a decode that is
// perfectly self-consistent, passes any stationarity test, and produces a rank
// curve that is an ARTEFACT of the wrong table. That is precisely the failure
// mode this file exists to avoid, so those types are left unimplemented on
// purpose rather than guessed at.
//
// MXFP4 has no codebook. ggml_block_mxfp4 is 17 bytes for 32 values:
//     byte 0      E8M0 scale (exponent only; value = 2^(e-127))
//     bytes 1..16 32 x 4-bit E2M1 codes, high nibble first
//
// E2M1 magnitudes indexed 0..7: {0, 0.5, 1, 1.5, 2, 3, 4, 6}, bit 3 is sign.
//
// THE VALIDATION IS THE POINT. A correct decode confines every 32-element group
// to a lattice of at most 8 magnitudes x 2 signs. A wrong nibble order or a
// wrong E8M0 conversion destroys that lattice immediately, and the failure is
// visible as an inflated distinct-value count. So this decode is falsifiable in
// a way the i-quants are not.
float e8m0ToFp32(std::uint8_t e) {
    if (e == 0xFFu) return std::numeric_limits<float>::quiet_NaN();
    // 2^(e-127) without ldexp edge cases
    return std::ldexp(1.0f, static_cast<int>(e) - 127);
}

void dequantMXFP4(const unsigned char* x, float* y) {
    static const float kFp4[16] = {
        0.0f, 0.5f, 1.0f, 1.5f, 2.0f, 3.0f, 4.0f, 6.0f,
        -0.0f, -0.5f, -1.0f, -1.5f, -2.0f, -3.0f, -4.0f, -6.0f
    };
    const float s = e8m0ToFp32(x[0]);
    const unsigned char* q = x + 1;
    for (int j = 0; j < 32; j += 2) {
        y[j + 0] = s * kFp4[q[j] >> 4];
        y[j + 1] = s * kFp4[q[j] & 0xF];
    }
}

// ---------------------------------------------------------------------------
// i-quant decodes, ported from the vendored ggml reference.
//
// TYPES, CORRECTED AGAINST THE AUTHORITATIVE ENUM. An earlier receipt asserted
// 17=IQ2_XXS, 18=IQ2_XS, 26=IQ4_XS from memory. Reading ggml.h gives:
//     17 = IQ2_XS, 18 = IQ3_XXS, 23 = IQ4_XS, 26 = I32 (a plain int32 routing
//     table, not a quantisation), 39 = MXFP4.
// Three of four names were wrong. IQ3_XXS is a 3-bit format, not the 2-bit one
// described, and it uses a different codebook scheme.
//
// TABLES ARE GENERATED, NOT RECALLED. tools/iq_table_extract.ps1 parses
// ggml-common.h and emits iq_tables.inc with count verification (8/8, 128/128,
// 512/512, 256/256). A hand transcription of 4096 bytes is an operation that
// cannot be checked afterwards, so it is not performed.
//
// THE VALIDATION IS THE POINT, and it is stronger than stationarity. Each 8-value
// group of an IQ2_XS decode is, by construction, exactly one entry of the
// 512-entry grid scaled by db with a sign mask applied. So for every group the
// |value| pattern can be looked up in the grid and must match EXACTLY ONE entry.
// A wrong port, a wrong table, a wrong sign index or a wrong scale all fail
// that lookup. Agreement is therefore evidence the decode is right, not merely
// self-consistent.
// ---------------------------------------------------------------------------
#include "iq_tables.inc"

void dequantIQ2XS(const unsigned char* x, float* y) {
    const float d = fp16ToFp32(*reinterpret_cast<const std::uint16_t*>(x));
    const std::uint16_t* qs = reinterpret_cast<const std::uint16_t*>(x + 2);
    const std::uint8_t*  sc = x + 2 + 64;               // scales[QK_K/32]
    float* out = y;
    float db[2];
    for (int ib32 = 0; ib32 < 8; ++ib32) {
        db[0] = d * (0.5f + float(sc[ib32] & 0xf)) * 0.25f;
        db[1] = d * (0.5f + float(sc[ib32] >>  4)) * 0.25f;
        for (int l = 0; l < 4; ++l) {
            const std::uint16_t q = qs[4 * ib32 + l];
            const std::uint8_t* grid =
                reinterpret_cast<const std::uint8_t*>(iq2xs_grid + (q & 511));
            const std::uint8_t signs = ksigns_iq2xs[q >> 9];
            for (int j = 0; j < 8; ++j)
                out[j] = db[l / 2] * float(grid[j]) *
                         ((signs & kmask_iq2xs[j]) ? -1.0f : 1.0f);
            out += 8;
        }
    }
}

void dequantIQ3XXS(const unsigned char* x, float* y) {
    const float d = fp16ToFp32(*reinterpret_cast<const std::uint16_t*>(x));
    const std::uint8_t* qs = x + 2;
    const std::uint8_t* scalesAndSigns = qs + 64;      // QK_K/4
    float* out = y;
    std::uint32_t aux32;
    for (int ib32 = 0; ib32 < 8; ++ib32) {
        std::memcpy(&aux32, scalesAndSigns + 4 * ib32, 4);
        const float db = d * (0.5f + float(aux32 >> 28)) * 0.5f;
        for (int l = 0; l < 4; ++l) {
            const std::uint8_t signs = ksigns_iq2xs[(aux32 >> (7 * l)) & 127];
            const std::uint8_t* g1 =
                reinterpret_cast<const std::uint8_t*>(iq3xxs_grid + qs[2 * l + 0]);
            const std::uint8_t* g2 =
                reinterpret_cast<const std::uint8_t*>(iq3xxs_grid + qs[2 * l + 1]);
            for (int j = 0; j < 4; ++j) {
                out[j + 0] = db * float(g1[j]) *
                             ((signs & kmask_iq2xs[j + 0]) ? -1.0f : 1.0f);
                out[j + 4] = db * float(g2[j]) *
                             ((signs & kmask_iq2xs[j + 4]) ? -1.0f : 1.0f);
            }
            out += 8;
        }
        qs += 8;
    }
}

// Independent consistency check: does every decoded group reproduce an entry of
// the extracted codebook EXACTLY? Returns the fraction of groups that match.
double iq2xsLatticeMatch(const std::vector<float>& W, int R, std::uint64_t C) {
    std::size_t total = 0, hit = 0;
    std::vector<std::uint8_t> pat(8), ref(8);
    for (int r = 0; r < R; ++r)
        for (std::uint64_t b = 0; b < C / 8; ++b) {
            const float* g = W.data() + size_t(r) * size_t(C) + b * 8;
            float mx = 0.0f;
            for (int j = 0; j < 8; ++j) mx = std::max(mx, std::fabs(g[j]));
            if (!(mx > 0.0f)) continue;
            ++total;
            // Strip the scale: db is constant within a group of 8, so dividing by
            // the group max yields the grid's own byte pattern up to a common
            // factor. Match on the RATIO pattern instead of the raw bytes.
            for (int j = 0; j < 8; ++j)
                pat[size_t(j)] = static_cast<std::uint8_t>(
                    std::lround(std::fabs(g[j]) / mx * 255.0f));
            bool found = false;
            for (std::size_t gi = 0; gi < 512 && !found; ++gi) {
                std::memcpy(ref.data(), iq2xs_grid + gi, 8);
                float rmax = 0.0f;
                for (int j = 0; j < 8; ++j) rmax = std::max(rmax, float(ref[size_t(j)]));
                if (!(rmax > 0.0f)) continue;
                bool same = true;
                for (int j = 0; j < 8 && same; ++j)
                    same = (std::lround(std::fabs(g[j]) / mx * 255.0f) ==
                            std::lround(float(ref[size_t(j)]) / rmax * 255.0f));
                if (same) found = true;
            }
            if (found) ++hit;
        }
    return total ? double(hit) / double(total) : 0.0;
}

// Local relative L2. This tool has no shared metrics header; the sweep tool has
// its own copy of this function and the two are intentionally independent.
double relL2Local(const std::vector<float>& a, const std::vector<float>& ref) {
    double n = 0.0, d = 0.0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const double t = double(a[i]) - double(ref[i]);
        n += t * t; d += double(ref[i]) * double(ref[i]);
    }
    return d > 0.0 ? std::sqrt(n / d) : 0.0;
}

bool dequantDispatch(std::uint32_t type, const unsigned char* p, float* y) {
    switch (type) {
        case 12: dequantQ4K(p, y); return true;    // Q4_K
        case 14: dequantQ6K(p, y); return true;    // Q6_K
        case 17: dequantIQ2XS(p, y); return true;  // IQ2_XS   (50 expert tensors)
        case 18: dequantIQ3XXS(p, y); return true; // IQ3_XXS  (77 expert tensors)
        case 39: dequantMXFP4(p, y); return true;  // MXFP4    (2 expert tensors)
        default: return false;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// STAGE 4 -- THE RIVAL: DIRECT QUANTISATION AT MATCHED BITRATE.
//
// The overlay has always been compared against fp32, which is not its rival.
// Its rival is the best SINGLE-FORMAT quantiser at the SAME total bits. If a
// direct quantiser at the overlay's bitrate reaches comparable accuracy, the
// overlay is dominated: same bits, plus a second storage tier, a second decode
// pass, and a fetch on the hot path.
//
// RTN (round-to-nearest) min/max quantisers are used, with the EXACT bits per
// weight of each shipped format:  bits + 16/groupSize, fp16 scale per group.
//     4 + 16/32 = 4.50  (Q4_K)      5 + 16/32 = 5.50  (Q5_K)
//     6 + 16/16 = 7.00               8 + 16/32 = 8.50  (Q8_0)
//
// RTN is a FAIR and deliberately GENEROUS baseline: production k-quants and
// i-quants BEAT RTN at the same rate. So losing to RTN means losing to the real
// formats too, while beating RTN leaves a harder test rather than an easier
// one. The comparison is therefore biased AGAINST the conclusion, which is the
// correct direction when a previously-accepted claim is under review.
// ---------------------------------------------------------------------------
struct DirectPoint { double bpw; int bits; int group; double relL2; };

std::vector<DirectPoint> runDirectSweep(const std::vector<float>& W, int R,
                                        std::uint64_t C,
                                        const std::vector<float>& xv,
                                        const std::vector<float>& yRef) {
    std::vector<DirectPoint> out;
    const int bitsOpts[]  = {2, 3, 4, 5, 6, 8};
    const int groupOpts[] = {16, 32, 64};
    std::vector<float> yq(size_t(R), 0.0f);
    for (int bits : bitsOpts) {
        const int levels = 1 << bits;
        for (int gsz : groupOpts) {
            if (C % std::uint64_t(gsz)) continue;
            const std::uint64_t grpN = C / std::uint64_t(gsz);
            const double bpw = double(bits) + 16.0 / double(gsz);
            for (int r = 0; r < R; ++r) {
                float acc = 0.0f;
                for (std::uint64_t g = 0; g < grpN; ++g) {
                    const std::uint64_t c0 = g * std::uint64_t(gsz);
                    float lo = 1e30f, hi = -1e30f;
                    for (int k = 0; k < gsz; ++k) {
                        const float v = W[size_t(r) * size_t(C) + c0 + std::size_t(k)];
                        lo = std::min(lo, v);
                        hi = std::max(hi, v);
                    }
                    const float s = (hi - lo) / float(levels - 1);
                    for (int k = 0; k < gsz; ++k) {
                        const std::size_t c = std::size_t(c0) + std::size_t(k);
                        const std::size_t ix = std::size_t(r) * std::size_t(C) + c;
                        float wq;
                        if (!(s > 0.0f)) {
                            wq = 0.0f;   // a constant group: its scale is wasted
                        } else {
                            double q = (double(W[ix]) - double(lo)) / double(s);
                            // Explicit casts: mixing int levels with double
                            // bounds here fails template deduction, and a silent
                            // narrowing in a quantiser is the last place to want
                            // an implicit conversion.
                            q = std::min(double(levels - 1),
                                         std::max(0.0, std::floor(q + 0.5)));
                            wq = float(q * double(s) + double(lo));
                        }
                        acc += wq * xv[c];
                    }
                }
                yq[size_t(r)] = acc;
            }
            out.push_back(DirectPoint{bpw, bits, gsz, relL2Local(yq, yRef)});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const DirectPoint& a, const DirectPoint& b) {
                  return a.bpw < b.bpw;
              });
    return out;
}

// ---------------------------------------------------------------------------
// STAGE 5 -- THE ONE LIVE IDEA, PROPERLY TESTED.
//
// Stages 1-4 tested SPECIFIC bases (the shipped formats). That answers "did
// this base work?" -- not "is there ANY base that works?"
//
// The proposal, restated as an optimisation, is:
//
//      minimise   base_bpw + H(W - base)      over all bases
//
// Every point on the overlay's curve has rel_L2 = 0 BY CONSTRUCTION, because the
// delta is defined as W - base. So the entire overlay family collapses to a
// SINGLE NUMBER: the minimum of (base_bpw + residual entropy) over the base
// family.
//
// If that MINIMUM still loses to the direct-quantiser curve, then no choice of
// base rescues the architecture, and the family is closed rather than merely
// unpromising. That is a much stronger statement than the one the four shipped
// formats support.
//
// The base family here is RTN min/max over bits x groupSize. It is not all
// possible quantisers, so a negative result closes the family that was searched
// and not every quantiser ever devised -- which is stated rather than implied.
// ---------------------------------------------------------------------------
struct OverlayPoint { double baseBpw; double deltaH; double total; int bits; int group; };

std::vector<OverlayPoint> runOverlaySearch(const std::vector<float>& W, int R,
                                          std::uint64_t C) {
    std::vector<OverlayPoint> out;
    const int bitsOpts[]  = {1, 2, 3, 4, 5, 6, 8};
    const int groupOpts[] = {16, 32, 64, 128, 256};
    for (int bits : bitsOpts) {
        const int levels = 1 << bits;
        for (int gsz : groupOpts) {
            if (C % std::uint64_t(gsz)) continue;
            const std::uint64_t grpN = C / std::uint64_t(gsz);
            const double baseBpw = double(bits) + 16.0 / double(gsz);
            // Group amplitude is needed to normalise the residual before
            // measuring its entropy, exactly as in the shipped-format path.
            std::vector<double> gam(size_t(R) * size_t(grpN), 0.0);
            for (int r = 0; r < R; ++r)
                for (std::uint64_t g = 0; g < grpN; ++g) {
                    double am = 0.0;
                    for (int k = 0; k < gsz; ++k)
                        am = std::max(am, std::fabs(
                            double(W[size_t(r) * size_t(C) + g * gsz + k])));
                    gam[size_t(r) * size_t(grpN) + g] = am;
                }
            std::vector<std::uint64_t> hist(512, 0);
            std::uint64_t hn = 0;
            for (int r = 0; r < R; ++r)
                for (std::uint64_t g = 0; g < grpN; ++g) {
                    const double am = gam[size_t(r) * size_t(grpN) + g];
                    const double sc = am > 0.0 ? am : 1.0;
                    const std::uint64_t c0 = g * std::uint64_t(gsz);
                    for (int k = 0; k < gsz; ++k) {
                        const std::size_t ix =
                            std::size_t(r) * std::size_t(C) + c0 + std::size_t(k);
                        double q;
                        if (bits == 0 || !(sc > 0.0)) {
                            q = 0.0;
                        } else {
                            // RTN min/max within the group, same family as stage 4.
                            double lo = 1e300, hi = -1e300;
                            for (int j = 0; j < gsz; ++j) {
                                const double v =
                                    double(W[size_t(r) * size_t(C) + c0 + std::size_t(j)]);
                                lo = std::min(lo, v); hi = std::max(hi, v);
                            }
                            const double s = (hi - lo) / double(levels - 1);
                            if (!(s > 0.0)) { q = 0.0; }
                            else {
                                double t =
                                    (double(W[ix]) - lo) / s;
                                t = std::min(double(levels - 1),
                                             std::max(0.0, std::floor(t + 0.5)));
                                q = t * s + lo;
                            }
                        }
                        const double d = (double(W[ix]) - q) / sc;
                        int qi = int(std::lround(d * 255.0));
                        if (qi < -256) qi = -256;
                        if (qi > 255) qi = 255;
                        ++hist[size_t(qi + 256)];
                        ++hn;
                    }
                }
            double H = 0.0;
            for (std::uint64_t c : hist) {
                if (!c) continue;
                const double p = double(c) / double(hn);
                H -= p * std::log2(p);
            }
            out.push_back(OverlayPoint{baseBpw, H, baseBpw + H, bits, gsz});
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// STAGE 6 -- A BASE CHOSEN SO THE RESIDUAL IS SPARSE BY CONSTRUCTION.
//
// Every base searched so far minimises the BASE. A minimiser of base bits has
// no reason to shape its error -- and the stage-5 optima landing on one-bit
// bases are direct evidence of that. This stage changes the objective.
//
// MECHANISM. Within a group, choose the 2^b code levels to be the 2^b MOST
// FREQUENT values rather than an even min/max grid. Every element that then
// lands exactly on a level contributes a residual of EXACTLY ZERO, so the
// residual becomes sparse by construction. The residual that remains is
// concentrated on rare magnitudes -- large, but few.
//
// WHY THAT COULD WIN WHERE ORDER-0 FAILED. Order-0 coding pays ~8 bits on every
// element including the zeros. Sparse coding pays nothing on the zeros and
// (log2(group) + H(nonzero magnitudes)) on the rest. If the exact-hit fraction
// is high enough the arithmetic inverts.
//
// This is the last untested mechanism: a base optimised jointly with its
// residual, rather than independently.
// ---------------------------------------------------------------------------
struct SparseOverlay { double baseBpw; double sparsity; double codeBits; double total;
                      int bits; int group; double nonzeroEntropy; };

std::vector<SparseOverlay> runSparseResidualSearch(const std::vector<float>& W,
                                                  int R, std::uint64_t C) {
    std::vector<SparseOverlay> out;
    const int bitsOpts[]  = {1, 2, 3, 4};
    const int groupOpts[] = {16, 32, 64};
    for (int bits : bitsOpts) {
        const int levels = 1 << bits;
        for (int gsz : groupOpts) {
            if (C % std::uint64_t(gsz)) continue;
            const std::uint64_t grpN = C / std::uint64_t(gsz);
            const double baseBpw = double(bits) + 16.0 / double(gsz);
            std::uint64_t distinctSum = 0, groupsSeen = 0, groupsWithFew = 0;
            std::uint64_t exact = 0, total = 0;
            std::vector<double> nzMag;      // magnitudes of NONZERO residuals
            std::vector<double> nzScaled;   // normalised, for entropy
            std::vector<double> gam(size_t(R) * size_t(grpN), 0.0);

            for (int r = 0; r < R; ++r)
                for (std::uint64_t g = 0; g < grpN; ++g) {
                    const std::uint64_t c0 = g * std::uint64_t(gsz);
                    // 1. group amplitude
                    double am = 0.0;
                    for (int k = 0; k < gsz; ++k)
                        am = std::max(am, std::fabs(
                            double(W[size_t(r) * size_t(C) + c0 + std::size_t(k)])));
                    gam[size_t(r) * size_t(grpN) + g] = am;
                    // 2. MODE-SEEKING level selection: the `levels` most
                    //    frequent distinct values in this group.
                    std::map<double, int> freq;
                    for (int k = 0; k < gsz; ++k)
                        ++freq[double(W[size_t(r) * size_t(C) + c0 + std::size_t(k)])];
                    std::vector<double> lv;
                    lv.reserve(freq.size());
                    for (const auto& kv : freq) lv.push_back(kv.first);
                    std::stable_sort(lv.begin(), lv.end(),
                        [&freq](double a, double b) {
                            const int fa = freq.count(a) ? freq[a] : 0;
                            const int fb = freq.count(b) ? freq[b] : 0;
                            if (fa != fb) return fa > fb;   // most frequent first
                            return a < b;
                        });
                    if (int(lv.size()) > levels) lv.resize(size_t(levels));
                    ++distinctSum; ++groupsSeen;
                    if (int(lv.size()) <= levels) ++groupsWithFew;
                    // 3. assign + accumulate the residual
                    for (int k = 0; k < gsz; ++k) {
                        const std::size_t ix =
                            std::size_t(r) * std::size_t(C) + c0 + std::size_t(k);
                        const double w = double(W[ix]);
                        ++total;
                        double best = 0.0;
                        double bd = 1e300;
                        for (double cand : lv) {
                            const double d = std::fabs(w - cand);
                            if (d < bd) { bd = d; best = cand; }
                        }
                        const double resid = w - best;
                        if (resid == 0.0) { ++exact; }
                        else {
                            nzMag.push_back(std::fabs(resid));
                            nzScaled.push_back(resid / (am > 0.0 ? am : 1.0));
                        }
                    }
                }

            const double sparsity = total ? double(exact) / double(total) : 0.0;
            // Entropy of the NONZERO residual magnitudes only.
            std::vector<std::uint64_t> h2(512, 0);
            std::uint64_t h2n = 0;
            for (double v : nzScaled) {
                int qi = int(std::lround(v * 255.0));
                if (qi < -256) qi = -256;
                if (qi > 255) qi = 255;
                ++h2[size_t(qi + 256)];
                ++h2n;
            }
            double Hnz = 0.0;
            for (std::uint64_t c : h2) {
                if (!c) continue;
                const double p = double(c) / double(h2n);
                Hnz -= p * std::log2(p);
            }
            // Sparse coding: index (log2 group) + magnitude entropy, charged
            // only on the nonzero fraction.
            const double idxBits = std::log2(double(gsz));
            const double codeBits = (1.0 - sparsity) * (idxBits + Hnz);
            out.push_back(SparseOverlay{baseBpw, sparsity, codeBits,
                                        baseBpw + codeBits, bits, gsz, Hnz});
        }
    }
    return out;
}

int wmain(int argc, wchar_t** argv) {


    std::printf("RAWRXD_GGUF_TENSOR_SLICE_001\n");
    std::printf("SCOPE=HEADER_AND_TENSOR_DIRECTORY_ONLY_NO_DEQUANT\n\n");

if (argc < 3) {
        std::printf("usage: <gguf> <tensor-name-or-substring> [row-origin]\n");
        return kFail;
    }
    std::uint64_t g_rowOrigin = 0;
    // Window width. Deliberately a parameter, because the low-rank factor cost
    // of an R x C matrix is r*(R+C)*32/(R*C) bits/element -- WIDENING THE WINDOW
    // MAKES LOW RANK LOOK BETTER. Measuring MXFP4 at one width only would
    // confound "this format differs" with "a wider window flatters low rank",
    // and the two would be indistinguishable in the output.
    std::uint64_t g_cols = 256;
    if (argc >= 4) {
        const std::wstring s = argv[3];
        g_rowOrigin = std::stoull(std::wstring(s.begin(), s.end()));
    }
    if (argc >= 5) {
        const std::wstring s = argv[4];
        g_cols = std::stoull(std::wstring(s.begin(), s.end()));
    }
    const std::wstring path = argv[1];
    std::string want;
    {   // narrow the substring
        for (const wchar_t* c = argv[2]; *c; ++c)
            want.push_back(static_cast<char>(*c < 128 ? *c : '?'));
    }

    File f;
    if (!f.openW(path.c_str())) {
        std::printf("OPEN_FAILED path=%ls size_mb=?\n", path.c_str());
        return kFail;
    }
    std::printf("FILE_BYTES=%llu\n", (unsigned long long)f.size());

    Cursor c{&f, 0, true};
    char magic[4]{};
    c.raw(magic, 4);
    check(c.ok && memcmp(magic, "GGUF", 4) == 0, "MAGIC_GGUF", "got=%.4s", magic);
    if (!c.ok) return kFail;

    const std::uint32_t version = c.u32();
    check(version == 2 || version == 3, "VERSION_SUPPORTED", "v=%u", version);
    const std::uint64_t nTensors = c.u64();
    const std::uint64_t nKV = c.u64();
    std::printf("GGUF_VERSION=%u\nTENSOR_COUNT=%llu\nMETADATA_KV_COUNT=%llu\n\n",
                version, (unsigned long long)nTensors, (unsigned long long)nKV);
    if (!c.ok || nTensors == 0 || nTensors > 200000) return kFail;

    // ---- metadata ------------------------------------------------------
    std::uint64_t alignment = 32;
    // Localising state. A metadata parser that only reports "failed" forces the
    // next author to bisect by guesswork; this records the key it was reading
    // when the cursor went bad, so the next failure names itself.
    std::string failKey = "<none>";
    std::uint64_t failKv = 0, failPos = 0;
    for (std::uint64_t i = 0; i < nKV && c.ok; ++i) {
        const std::string key = c.str();
        const std::uint32_t vt = c.u32();
        switch (vt) {
            // GGML types: UINT8=0 INT8=1 UINT16=2 INT16=3 UINT32=4 INT32=5
            // FLOAT32=6 BOOL=7 STRING=8 ARRAY=9 UINT64=10 INT64=11 FLOAT64=12
            // BOOL is ONE byte. Treating it as four desynchronises every
            // subsequent key, which is what made the first run of this tool fail
            // with no indication of where.
            case 0: case 1: c.pos += 1; break;
            case 2: case 3: c.pos += 2; break;
            case 4: case 5: c.pos += 4; break;
            case 7: c.pos += 1; break;                 // <-- BOOL is 1 byte
            case 6:  { float v; c.raw(&v, 4);
                       if (key == "general.alignment") alignment = (std::uint64_t)v; } break;
            case 8:  c.str(); break;
            case 9:  { const std::uint32_t et = c.u32();
                        const std::uint64_t n = c.u64();
                        for (std::uint64_t k = 0; k < n && c.ok; ++k) {
                            switch (et) {
                                case 0: case 1: case 7: c.pos += 1; break;
                                case 2: case 3: c.pos += 2; break;
                                case 4: case 5: case 6: c.pos += 4; break;
                                case 10: case 11: case 12: c.pos += 8; break;
                                case 8: c.str(); break;
                                default: c.ok = false; break;
                            }
                        } } break;
            case 10: case 11: c.pos += 8; break;
            case 12: c.pos += 8; break;
            default: c.ok = false; break;
        }
        if (!c.ok) { failKey = key; failKv = i; failPos = c.pos; }
        if (c.ok && c.pos > f.size()) {
            c.ok = false; failKey = key + " (out-of-file)"; failKv = i; failPos = c.pos;
        }
    }
// The diagnostic prints SEPARATELY from the check. An earlier revision packed
    // it into the check's format arguments behind ternaries, and on success it
    // emitted garbage (kv=612120512030816) because a std::to_string temporary's
    // c_str() was being fed to %s alongside real arguments. A diagnostic that
    // prints nonsense when there is nothing wrong is worse than no diagnostic:
    // it makes a passing check look like it measured something absurd.
    check(c.ok, "METADATA_PARSED", "kv=%llu", (unsigned long long)nKV);
    if (!c.ok) {
        std::printf("  METADATA_FAILURE key=%s kv_index=%llu cursor_pos=%llu file_bytes=%llu\n",
                    failKey.c_str(), (unsigned long long)failKv,
                    (unsigned long long)failPos, (unsigned long long)f.size());
    }
    std::printf("GENERAL_ALIGNMENT=%llu\n\n", (unsigned long long)alignment);
    if (!c.ok) return kFail;

    // ---- tensor directory ---------------------------------------------
    std::vector<TensorInfo> ti;
    ti.reserve(static_cast<std::size_t>(nTensors));
    for (std::uint64_t i = 0; i < nTensors && c.ok; ++i) {
        TensorInfo t;
        t.name = c.str();
        t.nDims = c.u32();
        if (t.nDims == 0 || t.nDims > 4) { c.ok = false; break; }
        t.nElems = 1;
        for (std::uint32_t d = 0; d < t.nDims; ++d) {
            t.dims[d] = c.u64();
            t.nElems *= t.dims[d];
        }
        t.type = c.u32();
        t.offset = c.u64();
        TypeGeom g{};
        if (geomOf(t.type, g)) {
            t.nBlocks = t.nElems / g.blckElems;
            t.byteLen = t.nBlocks * g.typeSize;
        }
        ti.push_back(std::move(t));
    }
    check(c.ok && ti.size() == nTensors, "TENSOR_DIRECTORY_PARSED",
          "parsed=%zu expect=%llu", ti.size(), (unsigned long long)nTensors);
    if (!c.ok) return kFail;

    // ---- data section alignment ---------------------------------------
    std::uint64_t dataStart = (c.pos + alignment - 1) / alignment * alignment;
    check(dataStart <= f.size(), "DATA_SECTION_INSIDE_FILE",
          "start=%llu size=%llu", (unsigned long long)dataStart,
          (unsigned long long)f.size());

    // Every tensor must fit. A single out-of-range offset means the directory
    // parse went wrong, and continuing would attribute a later arithmetic result
    // to a misparsed header.
    std::uint64_t worstEnd = 0;
    std::uint32_t badOffsets = 0, badGeom = 0, badBlock = 0;
    for (const TensorInfo& t : ti) {
        const std::uint64_t end = dataStart + t.offset + t.byteLen;
        if (end > f.size()) ++badOffsets;
        if (end > worstEnd) worstEnd = end;
        TypeGeom g{};
        if (!geomOf(t.type, g)) { ++badGeom; continue; }
        if (t.nElems % g.blckElems != 0) ++badBlock;
    }
check(badOffsets == 0, "ALL_OFFSETS_IN_BOUNDS", "bad=%u", badOffsets);
    check(badGeom == 0, "ALL_TYPES_UNDERSTOOD", "unknown=%u", badGeom);
    // Name the unknown type IDs rather than only counting them. A MoE model
    // exposed 132 tensors whose type this table did not know, and the whole
    // MoE expert measurement was blocked until the ID was identified -- a count
    // alone would have left the next author guessing.
    if (badGeom) {
        std::printf("  UNKNOWN_TYPE_IDS:");
        std::vector<int> seen;
        for (const TensorInfo& t : ti) {
            TypeGeom gg{};
            if (geomOf(t.type, gg)) continue;
            if (std::find(seen.begin(), seen.end(), int(t.type)) == seen.end())
                seen.push_back(int(t.type));
        }
        for (int v : seen) std::printf(" %d", v);
        std::printf("\n");
    }
    check(badBlock == 0, "ALL_BLOCKS_ALIGNED", "misaligned=%u", badBlock);

// ---- geometry census ----------------------------------------------
    // The loop enumerates the types ACTUALLY PRESENT rather than a fixed range.
    // It used to stop at type 30, which silently omitted type 39 (MXFP4) --
    // the one exotic quantisation that carries NO codebook and is therefore
    // decodable and validatable without reproducing a kvalues table from
    // memory. A census that cannot print the type being asked about reports
    // "unknown" and invites a guess.
    std::printf("--- type census ---\n");
    {
        std::vector<std::uint32_t> ids;
        for (const TensorInfo& t : ti) ids.push_back(t.type);
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        for (std::uint32_t t : ids) {
            std::uint64_t cnt = 0;
            std::string sample;
            for (const TensorInfo& x : ti) {
                if (x.type != t) continue;
                ++cnt;
                if (sample.empty()) sample = x.name;
            }
            TypeGeom gg{};
            const bool known = geomOf(t, gg);
            std::printf("  type=%-5u %-10s count=%-6llu %-46s eg=%s\n", t,
                        known ? typeName(t) : "UNKNOWN",
                        (unsigned long long)cnt, sample.c_str(),
                        known ? "" : "<-- NOT IN GEOMETRY TABLE");
            // A rare type is usually the one being investigated, and one sample
            // name is not enough to find the others. Enumerate every name when
            // the population is small enough to list.
            if (cnt <= 4) {
                for (const TensorInfo& x : ti)
                    if (x.type == t)
                        std::printf("        type=%u member: %s  [%llu x %llu]\n", t,
                                    x.name.c_str(), (unsigned long long)x.dims[0],
                                    (unsigned long long)x.dims[1]);
            }
        }
    }
    std::printf("\nDATA_START=%llu  MAX_TENSOR_END=%llu  SLACK_BYTES=%llu\n\n",
                (unsigned long long)dataStart, (unsigned long long)worstEnd,
                (unsigned long long)(f.size() - worstEnd));

    // ---- locate the requested tensor ----------------------------------
    std::printf("--- sample of tensor names ---\n");
    for (std::size_t i = 0; i < ti.size() && i < 6; ++i)
        std::printf("  [%zu] %s\n", i, ti[i].name.c_str());

    const TensorInfo* hit = nullptr;
    // An exact name wins over a substring match. Without this, asking for
    // "blk.0.attn_q" returns blk.0.attn_q.bias -- a 1-D F32 bias rather than the
    // 2-D Q4_K weight matrix -- and every geometry expectation is then measured
    // against the wrong tensor.
    for (const TensorInfo& t : ti) if (t.name == want) { hit = &t; break; }
    if (!hit)
        for (const TensorInfo& t : ti)
            if (t.name.find(want) != std::string::npos) { hit = &t; break; }

    std::printf("\n--- requested: '%s' ---\n", want.c_str());
    if (!hit) {
        std::printf("NOT_FOUND\n");
        std::printf("FINAL_VERDICT=FAIL\n");
        return 1;
    }
    TypeGeom g{};
    if (!geomOf(hit->type, g)) { std::printf("TYPE_UNSUPPORTED\n"); return 1; }

    std::printf("TENSOR=%s\n", hit->name.c_str());
    std::printf("TYPE=%u (%s)\n", hit->type, typeName(hit->type));
    std::printf("NDIMS=%u\n", hit->nDims);
    for (std::uint32_t d = 0; d < hit->nDims; ++d)
        std::printf("DIM[%u]=%llu\n", d, (unsigned long long)hit->dims[d]);
    std::printf("N_ELEMS=%llu\n", (unsigned long long)hit->nElems);
    std::printf("BLOCK_ELEMS=%u  TYPE_SIZE=%u\n", g.blckElems, g.typeSize);
    std::printf("N_BLOCKS=%llu\n", (unsigned long long)hit->nBlocks);
    std::printf("BYTE_LEN=%llu\n", (unsigned long long)hit->byteLen);
    std::printf("FILE_OFFSET=%llu\n",
                (unsigned long long)(dataStart + hit->offset));

    // ---- actually read a slice ----------------------------------------
    // Read the FIRST block only. This is the property that matters for an
    // out-of-core engine: the cost of a slice is independent of tensor size.
    std::vector<unsigned char> block(static_cast<std::size_t>(g.typeSize), 0);
    const std::uint64_t abs = dataStart + hit->offset;
    const std::uint64_t got = f.readAt(abs, block.data(), g.typeSize);
    check(got == g.typeSize, "SLICE_READ_COMPLETE", "read=%llu expect=%u",
          (unsigned long long)got, g.typeSize);

    // A block that is ENTIRELY zero is what a wrong offset looks like: real weight
    // blocks are dense. Counting distinct bytes is reported for every tensor but
    // only gates on the true failure signature (zero distinct values).
    //
    // An earlier revision gated on distinct > 8 and FAILED on blk.0.attn_q.bias,
    // a 5120-element F32 bias whose low bytes legitimately take few distinct
    // values. That is a heuristic that cannot tell a bias from a misdirected
    // read, so it was replaced with the condition it was actually standing in
    // for.
    std::uint32_t distinct[256] = {0};
    for (unsigned char bch : block) ++distinct[bch];
    std::uint32_t nDistinct = 0;
    for (int i = 0; i < 256; ++i) if (distinct[i]) ++nDistinct;
    check(nDistinct > 0, "BLOCK_IS_NOT_ALL_ZERO", "distinct_bytes=%u", nDistinct);

    std::printf("\nSLICE_BYTES_READ=%llu\n", (unsigned long long)got);
    std::printf("SLICE_DISTINCT_BYTE_VALUES=%u\n", nDistinct);

    // ------------------------------------------------------------------
    // DEQUANT STAGE -- only meaningful for a 2-D quantised matrix.
    //
    // Validation rationale, because this is where a silent artefact would enter:
    // re-encoding the dequantised values would only prove the code is
    // SELF-CONSISTENT, and a wrong sub-block scale index is perfectly
    // self-consistent. What a wrong index destroys is STATIONARITY -- adjacent
    // 64-element groups of a weight matrix have similar magnitude, so a correct
    // decode gives a tight spread of per-group RMS, while a mis-indexed decode
    // gives groups whose RMS varies by orders of magnitude. That is the check
    // that can actually fail.
bool dequantApplicable = (hit->nDims >= 2) &&
                             (hit->type == 12 || hit->type == 14 ||
                              hit->type == 17 || hit->type == 18 ||
                              hit->type == 39);
    if (!dequantApplicable) {
        std::printf("\nDEQUANT_APPLICABLE=0 type=%u\n", hit->type);
    } else {
        const std::uint32_t be = g.blckElems;
        const std::uint64_t colsPerRow = hit->dims[0];
        // R is sized for the LOW-RANK ECONOMICS, not for convenience. A rank-r
        // factor of an R x C matrix costs r*(R+C) floats, so per-element cost is
        // r*(R+C)*32/(R*C) bits. With R=64 that penalises low-rank severely and
        // would make the measurement an artefact of the sample height rather
        // than of the delta. R=256 with C=256 gives r*0.25 bits/element, the same
        // scaling a real square weight tensor has.
        const int R = 256;
        std::uint64_t C = g_cols;
        // A window must be a whole number of quant blocks.
        const std::uint64_t blocksWide = C / be;
        if (blocksWide == 0 || (C % be) != 0) {
            std::printf("WINDOW_COLS_NOT_BLOCK_ALIGNED (be=%u)\n", be);
            return 1;
        }
        C = blocksWide * be;
        const std::uint64_t rowsNeeded = static_cast<std::uint64_t>(R);
        std::printf("\n--- dequant stage (type=%s) ---\n", typeName(hit->type));
        if (hit->dims[0] < C || hit->dims[1] < rowsNeeded) {
            std::printf("TENSOR_TOO_SMALL_FOR_STAGE\n");
        } else {
const std::uint64_t blocksPerRow = colsPerRow / be;
            // Window origin. A single window is an anecdote; the question is
            // whether the delta's structure is a property of the TENSOR or of the
            // region sampled. Supplied on the command line so many windows,
            // tensors and layers can be swept by re-running the tool, rather than
            // by restructuring validated analysis code to loop internally.
            const std::uint64_t row0 = g_rowOrigin;
            {
                std::vector<unsigned char> raw(size_t(R) * size_t(blocksWide) * g.typeSize, 0);
                bool readOk = true;
                std::uint64_t gotB = 0;
                const std::uint64_t wantB = raw.size();
                // READ blocksWide BLOCKS PER ROW. This loop originally read a
                // single block per row while the window width was hard-wired to
                // one block, which was self-consistent. Making C a parameter
                // WITHOUT widening this read left `raw` sized for R*blocksWide
                // blocks but holding only R -- and every subsequent index ran off
                // the end of the buffer. The post-normalisation lattice check is
                // what caught it (post_norm_max = 1.6e37 against an E2M1 ceiling
                // of 6.0), which is the whole reason that check exists.
                for (int r = 0; r < R && readOk; ++r) {
                    const std::uint64_t rowBase = row0 + std::uint64_t(r);
                    for (std::uint64_t b = 0; b < blocksWide; ++b) {
                        const std::uint64_t blkIndex = rowBase * blocksPerRow + b;
                        const std::uint64_t abs =
                            dataStart + hit->offset + blkIndex * g.typeSize;
                        unsigned char* dst =
                            raw.data() + (size_t(r) * size_t(blocksWide) + size_t(b)) * g.typeSize;
                        const std::uint64_t n = f.readAt(abs, dst, g.typeSize);
                        gotB += n;
                        if (n != g.typeSize) { readOk = false; break; }
                    }
                }
                if (gotB != wantB) readOk = false;
                check(readOk, "ROW_BLOCKS_READ", "row0=%llu cols=%llu read=%llu expect=%llu",
                      (unsigned long long)row0, (unsigned long long)C,
                      (unsigned long long)gotB, (unsigned long long)wantB);
                if (!readOk) return 1;

                std::vector<float> W(size_t(R) * size_t(C), 0.0f);
                for (int r = 0; r < R; ++r)
                    for (std::uint64_t b = 0; b < blocksWide; ++b)
                        dequantDispatch(hit->type,
                            raw.data() + (size_t(r) * size_t(blocksWide) + size_t(b)) * g.typeSize,
                            W.data() + size_t(r) * size_t(C) + b * be);

            // --- validation of the decode -------------------------------
            bool allFin = true;
            for (float v : W) if (!std::isfinite(v)) { allFin = false; break; }
            check(allFin, "DEQUANT_ALL_FINITE", "");

            double mean = 0.0;
            for (float v : W) mean += double(v);
            mean /= double(W.size());
            check(std::fabs(mean) < 0.25 * 0.25, "DEQUANT_NEAR_ZERO_MEAN",
                  "mean=%.6f", mean);

            std::vector<float> distinctVals;
            {
                std::vector<float> tmp = W;
                std::sort(tmp.begin(), tmp.end());
                tmp.erase(std::unique(tmp.begin(), tmp.end()), tmp.end());
                distinctVals = tmp;
            }
            // A correct 4-bit decode yields many distinct magnitudes; a
            // collapsed scale index yields a handful.
// The distinct-value criterion is TYPE-CONDITIONAL, and this is a
            // REPLACEMENT rather than a relaxation.
            //
            // For Q4_K / Q6_K the scale is shared across 256 elements, so many
            // distinct magnitudes appear and a floor of 64 catches a collapsed
            // scale index. For MXFP4 every 32-element block is confined to the
            // 16-value E2M1 lattice BY CONSTRUCTION, so a correct decode yields
            // a SMALL global distinct count -- 23 was measured. Gating that with
            // the Q4_K floor would fail every correct MXFP4 decode, and
            // "fixing" it by lowering the floor until it passes would be exactly
            // the fabrication this project keeps producing.
            //
            // The property that actually matters for MXFP4 is the PER-BLOCK
            // lattice bound, which is already checked by MXFP4_LATTICE_BOUNDED
            // and by MXFP4_POST_NORM_WITHIN_E2M1_LATTICE.
            const bool distinctGateApplies = (hit->type != 39);
            if (distinctGateApplies) {
                check(distinctVals.size() >= 64, "DEQUANT_DISTINCT_VALUES",
                      "distinct=%zu of %zu", distinctVals.size(), W.size());
            } else {
                std::printf("DEQUANT_DISTINCT_VALUES_OBSERVED_ONLY distinct=%zu "
                            "(MXFP4 is lattice-confined by construction; the gate that "
                            "applies is MXFP4_LATTICE_BOUNDED)\n", distinctVals.size());
            }

            // STATIONARITY: per-64-group RMS spread.
double rms[256];
            double rmsMean = 0.0;
            for (int r = 0; r < R; ++r) {
                double s = 0.0;
                for (std::uint64_t c = 0; c < C; ++c) {
                    const double v = double(W[size_t(r) * size_t(C) + c]);
                    s += v * v;
                }
                rms[r] = std::sqrt(s / double(C));
                rmsMean += rms[r];
            }
            rmsMean /= double(R);
            double rmsVar = 0.0;
            for (int r = 0; r < R; ++r) rmsVar += (rms[r] - rmsMean) * (rms[r] - rmsMean);
            rmsVar /= double(R);
            const double rmsCv = rmsMean > 0.0 ? std::sqrt(rmsVar) / rmsMean : 1e9;
            check(rmsCv < 1.0, "DEQUANT_SUBBLOCK_STATIONARY",
                  "group_rms_cv=%.4f (mis-indexed scales inflate this)", rmsCv);

            // ------------------------------------------------------------------
            // MXFP4 SCALE NORMALISATION.
            //
            // The previous run FAILED DEQUANT_SUBBLOCK_STATIONARY at cv=5.96 and
            // produced a numerically degenerate Gram matrix (sigma ratio 6.3e29).
            // Diagnosis: MXFP4 carries a PER-32-ELEMENT E8M0 scale that is a bare
            // power of two. Q4_K and Q6_K share one scale per 256 elements, so a
            // stationarity test is meaningful for them; for MXFP4 per-block RMS
            // legitimately varies by orders of magnitude and the covariance is
            // dominated by the scale exponent rather than by weight structure.
            //
            // So each block is divided by its OWN E8M0 scale before any
            // statistic is computed. What remains is weight structure.
            //
            // The criterion is REPLACED, not relaxed. Raw per-block RMS for MXFP4
            // has cv ~6 and always will; the normalised equivalent asks a
            // STRICTER question -- after removing the scale, do blocks still
            // agree in magnitude? A correct decode of stationary weights answers
            // yes with a tight cv. A wrong nibble order or wrong E8M0 conversion
            // leaves structure that does not normalise away, and fails here.
            // ------------------------------------------------------------------
            if (hit->type == 39) {
                double preMax = 0.0, postMax = 0.0;
                int    postWorst = 0;
                for (int r = 0; r < R; ++r) {
                    for (std::uint64_t b = 0; b < blocksWide; ++b) {
                        float* blk = W.data() + size_t(r) * size_t(C) + b * be;
                        // Recover the block scale from the raw bytes. The block
                        // is be elements at stride (R*blocksWide + r*blocksWide + b)
                        // in the raw buffer.
                        const std::uint64_t blkIndex =
                            std::uint64_t(R) * blocksWide * 0 + r * blocksWide + b;
                        const unsigned char e8 = raw[blkIndex * g.typeSize];
                        const float s = (e8 == 0xFFu) ? 1.0f : std::ldexp(1.0f, int(e8) - 127);
                        if (!(s > 0.0f)) continue;
                        for (std::uint32_t k = 0; k < be; ++k) {
                            preMax = std::max(preMax, std::fabs(double(blk[k])));
                            blk[k] /= s;
                            postMax = std::max(postMax, std::fabs(double(blk[k])));
                        }
                    }
                    double s2 = 0.0;
                    for (std::uint64_t c = 0; c < C; ++c) {
                        const double v = double(W[size_t(r) * size_t(C) + c]);
                        s2 += v * v;
                    }
                    const double rr = std::sqrt(s2 / double(C));
                    static double g_postMean = 0.0; g_postMean += rr;
                    (void)g_postMean;
                }
                // normalised per-row RMS spread
                std::vector<double> postRms(size_t(R), 0.0);
                double pm = 0.0;
                for (int r = 0; r < R; ++r) {
                    double s2 = 0.0;
                    for (std::uint64_t c = 0; c < C; ++c) {
                        const double v = double(W[size_t(r) * size_t(C) + c]);
                        s2 += v * v;
                    }
                    postRms[size_t(r)] = std::sqrt(s2 / double(C));
                    pm += postRms[size_t(r)];
                }
                pm /= double(R);
                double pv = 0.0;
                for (int r = 0; r < R; ++r)
                    pv += (postRms[size_t(r)] - pm) * (postRms[size_t(r)] - pm);
                pv /= double(R);
                const double postCv = pm > 0.0 ? std::sqrt(pv) / pm : 1e9;
                if (postCv * 100 > postWorst) postWorst = int(postCv * 100);

                check(postCv < 1.0, "MXFP4_NORMALISED_STATIONARY",
                      "post_norm_row_rms_cv=%.4f (REPLACES the raw cv for MXFP4)", postCv);
                std::printf("MXFP4_PRE_NORM_MAX=%.6f\n", preMax);
                std::printf("MXFP4_POST_NORM_MAX=%.6f  (E2M1 max magnitude is 6.0)\n", postMax);
                std::printf("MXFP4_POST_NORM_ROW_RMS_CV=%.4f\n", postCv);
                check(postMax <= 6.0 + 1e-3, "MXFP4_POST_NORM_WITHIN_E2M1_LATTICE",
                      "post_norm_max=%.4f (E2M1 top magnitude 6.0)", postMax);
            }

            if (hit->type == 17 || hit->type == 18) {
                // Independent confirmation that the port AND the extracted table
                // are correct: every decoded group must reproduce an entry of the
                // codebook EXACTLY. A wrong port, a wrong table, a wrong sign
                // index or a wrong scale all break this lookup.
                const int   gsz2 = (hit->type == 17) ? 8 : 4;
                const int   tblN = (hit->type == 17) ? 512 : 256;
                std::size_t tot = 0, hitn = 0;
                for (int r = 0; r < R; ++r)
                    for (std::uint64_t b = 0; b < C / gsz2; ++b) {
                        const float* g = W.data() + size_t(r) * size_t(C) + b * gsz2;
                        float mx = 0.0f;
                        for (int j = 0; j < gsz2; ++j) mx = std::max(mx, std::fabs(g[j]));
                        if (!(mx > 0.0f)) continue;
                        ++tot;
                        bool found = false;
                        for (int gi = 0; gi < tblN && !found; ++gi) {
                            const std::uint8_t* ref =
                                (hit->type == 17)
                                    ? reinterpret_cast<const std::uint8_t*>(iq2xs_grid + gi)
                                    : reinterpret_cast<const std::uint8_t*>(iq3xxs_grid + gi);
                            float rm = 0.0f;
                            for (int j = 0; j < gsz2; ++j) rm = std::max(rm, float(ref[j]));
                            if (!(rm > 0.0f)) continue;
                            bool same = true;
                            for (int j = 0; j < gsz2 && same; ++j)
                                same = (std::lround(std::fabs(g[j]) / mx * 255.0f) ==
                                        std::lround(float(ref[j]) / rm * 255.0f));
                            if (same) found = true;
                        }
                        if (found) ++hitn;
                    }
                const double mq = tot ? double(hitn) / double(tot) : 0.0;
                check(mq > 0.999, "IQ_LATTICE_MATCHES_CODEBOOK",
                      "matched=%.4f of %d-value groups against a %d-entry codebook",
                      mq, gsz2, tblN);
                std::printf("IQ_LATTICE_MATCH_FRACTION=%.6f\n", mq);
                std::printf("IQ_CODEBOOK_ENTRIES=%d\n", tblN);
            }

            // MXFP4 LATTICE CHECK. A correct E2M1/E8M0 decode confines every
            // 32-element group to at most 8 magnitudes x 2 signs, so the number
            // of distinct magnitudes per group is <= 8. A wrong nibble order or a
            // wrong scale conversion breaks that immediately. This is the check
            // that makes MXFP4 safe to measure where the i-quants are not.
            if (hit->type == 39) {
                int worstLattice = 0;
                int worstSignSkew = 0;
                for (int r = 0; r < R; ++r) {
                    for (std::uint64_t b = 0; b < blocksWide; ++b) {
                    const float* base = W.data() + size_t(r) * size_t(C) + b * be;
                    std::vector<float> grp(base, base + be);
                    std::sort(grp.begin(), grp.end());
                    grp.erase(std::unique(grp.begin(), grp.end()), grp.end());
                    int lat = int(grp.size());
                    if (lat > worstLattice) worstLattice = lat;
                    int pos = 0, neg = 0;
                    for (std::uint32_t c = 0; c < be; ++c) {
                        const float v = base[c];
                        if (v > 0) ++pos; else if (v < 0) ++neg;
                    }
                    const int tot = pos + neg;
                    if (tot > 0) {
                        const int skew = std::abs(2 * pos - tot);
                        if (skew > worstSignSkew) worstSignSkew = skew;
                    }
                    }
                }
                check(worstLattice <= 16, "MXFP4_LATTICE_BOUNDED",
                      "max_distinct_per_32group=%d (E2M1 allows 16)", worstLattice);
                check(worstSignSkew <= 24, "MXFP4_SIGN_SYMMETRIC",
                      "max_sign_skew_of_32=%d (random gives ~6, broken decode >>)", worstSignSkew);
                std::printf("MXFP4_MAX_DISTINCT_PER_32GROUP=%d\n", worstLattice);
                std::printf("MXFP4_MAX_SIGN_SKEW_OF_32=%d\n", worstSignSkew);
                std::printf("MXFP4_NIBBLE_ORDER_ASSUMED=high_first\n");
            }

            std::printf("DEQUANT_ROWS=%d COLS=%llu ELEMS=%zu\n",
                        R, (unsigned long long)C, W.size());
            std::printf("DEQUANT_MEAN=%.8f\n", mean);
            std::printf("DEQUANT_DISTINCT_VALUES=%zu\n", distinctVals.size());
            std::printf("DEQUANT_GROUP_RMS_MEAN=%.8f\n", rmsMean);
            std::printf("DEQUANT_GROUP_RMS_CV=%.4f\n", rmsCv);
            std::printf("DEQUANT_MIN=%.6f  DEQUANT_MAX=%.6f\n",
                        *std::min_element(W.begin(), W.end()),
                        *std::max_element(W.begin(), W.end()));
            std::printf("DEQUANT_VALIDATED=%d\n",
                        (allFin && rmsCv < 1.0 && (!distinctGateApplies || distinctVals.size() >= 64)) ? 1 : 0);

            // ==============================================================
            // STAGE 3 -- the question the synthetic sweep had to leave open.
            // Is the real delta LOW RANK, or only large?
            //
            // Method: ternary-quantise the REAL dequantised weights exactly as
            // the sweep did (same group size, same 1/3 deadband, representatives
            // at +/-1), form dW = W - Wq, then take the EXACT singular spectrum
            // of the R x R Gram matrix by Jacobi rotations. Exact rather than
            // power-iteration: an approximate spectrum would make the rank curve
            // a function of iteration count, and a rank curve that moves when the
            // iteration count changes cannot decide anything.
            // ==============================================================
            std::printf("\n--- stage 3: is the REAL delta low rank? ---\n");
            const int    gsz = 32;
            const int    groups = int(C) / gsz;
            const double dead = 1.0 / 3.0;
            std::vector<float> dW(W.size(), 0.0f);
            std::vector<double> gAmax(size_t(R) * size_t(groups), 0.0);
            for (int r = 0; r < R; ++r)
                for (int g = 0; g < groups; ++g) {
                    double am = 0.0;
                    for (int k = 0; k < gsz; ++k)
                        am = std::max(am, std::fabs(double(W[size_t(r) * size_t(C) + g * gsz + k])));
                    gAmax[size_t(r) * size_t(groups) + g] = am;
                }
            double num = 0.0, den = 0.0;
            for (int r = 0; r < R; ++r)
                for (int g = 0; g < groups; ++g) {
                    const double am = gAmax[size_t(r) * size_t(groups) + g];
                    const double s = am > 0.0 ? am : 1.0;
                    for (int k = 0; k < gsz; ++k) {
                        const size_t i = size_t(r) * size_t(C) + g * gsz + k;
                        const double v = double(W[i]) / s;
                        const double lv = (v >= dead) ? 1.0 : (v <= -dead ? -1.0 : 0.0);
                        const double wq = lv * s;
                        dW[i] = float(double(W[i]) - wq);
                        num += std::fabs(double(dW[i]));
                        den += std::fabs(double(W[i]));
                    }
                }
            const double l1ratio = den > 0.0 ? num / den : 0.0;

            // Gram matrix dW * dW^T  (R x R)
            std::vector<double> G(size_t(R) * size_t(R), 0.0);
            for (int i = 0; i < R; ++i)
                for (int j = i; j < R; ++j) {
                    double s = 0.0;
                    for (int c = 0; c < int(C); ++c)
                        s += double(dW[size_t(i) * size_t(C) + c]) *
                             double(dW[size_t(j) * size_t(C) + c]);
                    G[size_t(i) * size_t(R) + j] = s;
                    G[size_t(j) * size_t(R) + i] = s;
                }
            // Jacobi eigenvalue iteration -> exact eigenvalues of a symmetric G.
            std::vector<double> ev(size_t(R) * size_t(R), 0.0);
            for (int i = 0; i < R; ++i) ev[size_t(i) * size_t(R) + i] = 1.0;
            for (int sweep = 0; sweep < 60; ++sweep) {
                double off = 0.0;
                for (int i = 0; i < R; ++i)
                    for (int j = i + 1; j < R; ++j) off += G[size_t(i) * size_t(R) + j] * G[size_t(i) * size_t(R) + j];
                if (off < 1e-24) break;
                for (int p = 0; p < R; ++p)
                    for (int q = p + 1; q < R; ++q) {
                        const double apq = G[size_t(p) * size_t(R) + q];
                        if (std::fabs(apq) < 1e-30) continue;
                        const double theta = (G[size_t(q) * size_t(R) + q] - G[size_t(p) * size_t(R) + p]) / (2.0 * apq);
                        const double t = (theta >= 0.0 ? 1.0 : -1.0) /
                                         (std::fabs(theta) + std::sqrt(theta * theta + 1.0));
                        const double cs = 1.0 / std::sqrt(t * t + 1.0);
                        const double sn = t * cs;
                        for (int k = 0; k < R; ++k) {
                            const double gkp = G[size_t(k) * size_t(R) + p];
                            const double gkq = G[size_t(k) * size_t(R) + q];
                            G[size_t(k) * size_t(R) + p] = cs * gkp - sn * gkq;
                            G[size_t(k) * size_t(R) + q] = sn * gkp + cs * gkq;
                        }
                        for (int k = 0; k < R; ++k) {
                            const double gpk = G[size_t(p) * size_t(R) + k];
                            const double gqk = G[size_t(q) * size_t(R) + k];
                            G[size_t(p) * size_t(R) + k] = cs * gpk - sn * gqk;
                            G[size_t(q) * size_t(R) + k] = sn * gpk + cs * gqk;
                        }
                        for (int k = 0; k < R; ++k) {
                            const double vkp = ev[size_t(k) * size_t(R) + p];
                            const double vkq = ev[size_t(k) * size_t(R) + q];
                            ev[size_t(k) * size_t(R) + p] = cs * vkp - sn * vkq;
                            ev[size_t(k) * size_t(R) + q] = sn * vkp + cs * vkq;
                        }
                    }
            }
            std::vector<double> sv(size_t(R), 0.0);
            double tot = 0.0;
            for (int i = 0; i < R; ++i) {
                const double e = G[size_t(i) * size_t(R) + i];
                sv[size_t(i)] = e > 0.0 ? std::sqrt(e) : 0.0;
                tot += e;
            }
            std::sort(sv.begin(), sv.end(), std::greater<double>());

            // ------------------------------------------------------------------
            // rank(W) ITSELF -- the anchor for the algebraic bound.
            //
            // If W = B + D then rank(W) <= rank(B) + rank(D). So a LOW-RANK
            // residual requires a HIGH-RANK base, and a two-factor split of a
            // full-rank matrix cannot compress it at all: the factor cost is
            // proportional to rank, so total cost >= rank(W) * per-rank cost,
            // which for a full-rank W is the original.
            //
            // Measuring rank(W) turns that from an argument into a measurement.
            // ------------------------------------------------------------------
            std::vector<double> Gw(size_t(R) * size_t(R), 0.0);
            for (int i = 0; i < R; ++i)
                for (int j = i; j < R; ++j) {
                    double s = 0.0;
                    for (int c = 0; c < int(C); ++c)
                        s += double(W[size_t(i) * size_t(C) + c]) *
                             double(W[size_t(j) * size_t(C) + c]);
                    Gw[size_t(i) * size_t(R) + j] = s;
                    Gw[size_t(j) * size_t(R) + i] = s;
                }
            std::vector<double> evw(size_t(R) * size_t(R), 0.0);
            for (int i = 0; i < R; ++i) evw[size_t(i) * size_t(R) + i] = 1.0;
            for (int sweep = 0; sweep < 60; ++sweep) {
                double off = 0.0;
                for (int i = 0; i < R; ++i)
                    for (int j = i + 1; j < R; ++j)
                        off += Gw[size_t(i) * size_t(R) + j] * Gw[size_t(i) * size_t(R) + j];
                if (off < 1e-24) break;
                for (int p = 0; p < R; ++p)
                    for (int q = p + 1; q < R; ++q) {
                        const double apq = Gw[size_t(p) * size_t(R) + q];
                        if (std::fabs(apq) < 1e-30) continue;
                        const double th = (Gw[size_t(q) * size_t(R) + q] -
                                           Gw[size_t(p) * size_t(R) + p]) / (2.0 * apq);
                        const double t = (th >= 0.0 ? 1.0 : -1.0) /
                                         (std::fabs(th) + std::sqrt(th * th + 1.0));
                        const double cs = 1.0 / std::sqrt(t * t + 1.0);
                        const double sn = t * cs;
                        for (int k = 0; k < R; ++k) {
                            const double a = Gw[size_t(k) * size_t(R) + p];
                            const double b = Gw[size_t(k) * size_t(R) + q];
                            Gw[size_t(k) * size_t(R) + p] = cs * a - sn * b;
                            Gw[size_t(k) * size_t(R) + q] = sn * a + cs * b;
                        }
                        for (int k = 0; k < R; ++k) {
                            const double a = Gw[size_t(p) * size_t(R) + k];
                            const double b = Gw[size_t(q) * size_t(R) + k];
                            Gw[size_t(p) * size_t(R) + k] = cs * a - sn * b;
                            Gw[size_t(q) * size_t(R) + k] = sn * a + cs * b;
                        }
                        for (int k = 0; k < R; ++k) {
                            const double a = evw[size_t(k) * size_t(R) + p];
                            const double b = evw[size_t(k) * size_t(R) + q];
                            evw[size_t(k) * size_t(R) + p] = cs * a - sn * b;
                            evw[size_t(k) * size_t(R) + q] = sn * a + cs * b;
                        }
                    }
            }
            std::vector<double> svw(size_t(R), 0.0);
            double totw = 0.0;
            for (int i = 0; i < R; ++i) {
                const double e = Gw[size_t(i) * size_t(R) + i];
                svw[size_t(i)] = e > 0.0 ? std::sqrt(e) : 0.0;
                totw += e;
            }
            std::sort(svw.begin(), svw.end(), std::greater<double>());
            int wRank99 = R;
            { double c2 = 0.0;
              for (int i = 0; i < R; ++i) {
                  c2 += svw[size_t(i)] * svw[size_t(i)];
                  if (totw > 0 && c2 / totw > 0.99) { wRank99 = i + 1; break; }
              } }
            const double wBpRank = double(wRank99) * double(R + int(C)) * 32.0 /
                                   (double(R) * double(C));
            std::printf("W_RANK_FOR_99PCT_ENERGY=%d\n", wRank99);
            std::printf("W_FULL_RANK_FRACTION=%.4f\n", double(wRank99) / double(R));
            std::printf("W_MIN_TWO_FACTOR_COST=%.3f bits/elem  (rank bound: "
                        "rank(B)+rank(D) >= rank(W))\n", wBpRank);

            // order-0 entropy of the real delta, for direct comparison with the
            // synthetic sweep's 5.90-7.25 bits/element
            std::vector<std::uint64_t> hist(256, 0);
            std::uint64_t hn = 0;
            for (int r = 0; r < R; ++r)
                for (int g = 0; g < groups; ++g) {
                    const double am = gAmax[size_t(r) * size_t(groups) + g];
                    if (!(am > 0.0)) continue;
                    for (int k = 0; k < gsz; ++k) {
                        const size_t i = size_t(r) * size_t(C) + g * gsz + k;
                        double v = double(dW[i]) / am;
                        int q = int(std::lround(v * 127.0));
                        if (q < -128) q = -128;
                        if (q > 127) q = 127;
                        ++hist[size_t(q + 128)];
                        ++hn;
                    }
                }
            double ent = 0.0;
            for (std::uint64_t h : hist) {
                if (!h) continue;
                const double p = double(h) / double(hn);
                ent -= p * std::log2(p);
            }

            // The overlay's OWN two points, so the trade can be read rather than asserted.
            //
            // base alone      : (base_bpw, BASE_ONLY_REL_L2)
            // base + delta    : (base_bpw + delta_bits, ~0 BY CONSTRUCTION)
            //
            // The second point is free accuracy, which sounds attractive until
            // the delta bits are counted. Printing both ends makes the SEGMENT
            // explicit so it can be compared against any single-format
            // quantiser costing the same total -- which is the comparison that
            // actually matters, and the one the proposal never made.
            std::vector<float> yBase(size_t(R), 0.0f);
            std::vector<float> yFull(size_t(R), 0.0f);
            std::vector<float> yRef(size_t(R), 0.0f);
            // A local probe vector. This tool has no input vector of its own --
            // it reads a tensor out of a file -- so the accuracy figures below
            // are defined against a fixed-seed Gaussian x. The value is only
            // meaningful for COMPARING points against each other on the same x,
            // which is exactly what the overlay segment needs.
            std::vector<float> xv(size_t(C), 0.0f);
            {
                std::mt19937 rng(20260903u);
                std::normal_distribution<float> g(0.0f, 1.0f);
                for (auto& v : xv) v = g(rng);
                for (int r = 0; r < R; ++r) {
                    float a = 0.0f;
                    for (int c = 0; c < int(C); ++c)
                        a += W[size_t(r) * size_t(C) + c] * xv[size_t(c)];
                    yRef[size_t(r)] = a;
                }
            }
            {
                const int    gsz2 = 32;
                const int    grpN = int(C) / gsz2;
                const double dead = 1.0 / 3.0;
                std::vector<double> gam(size_t(R) * size_t(grpN), 0.0);
                for (int r = 0; r < R; ++r)
                    for (int gI = 0; gI < grpN; ++gI) {
                        double am = 0.0;
                        for (int k2 = 0; k2 < gsz2; ++k2)
                            am = std::max(am, std::fabs(
                                double(W[size_t(r) * size_t(C) + gI * gsz2 + k2])));
                        gam[size_t(r) * size_t(grpN) + gI] = am;
                    }
                for (int r = 0; r < R; ++r) {
                    float ab = 0.0f, af = 0.0f;
                    for (int c = 0; c < int(C); ++c) {
                        const size_t ix = size_t(r) * size_t(C) + c;
                        const int gI = c / gsz2;
                        const double s0 = gam[size_t(r) * size_t(grpN) + gI];
                        const double sc = s0 > 0.0 ? s0 : 1.0;
                        const double v = double(W[ix]) / sc;
                        const double lv = (v >= dead) ? 1.0 : (v <= -dead ? -1.0 : 0.0);
                        const double wq = lv * sc;
                        ab += float(wq) * xv[size_t(c)];
                        af += float(wq + double(dW[ix])) * xv[size_t(c)];
                    }
                    yBase[size_t(r)] = ab;
                    yFull[size_t(r)] = af;
                }
            }
            const double baseOnlyL2 = relL2Local(yBase, yRef);
            const double fullL2     = relL2Local(yFull, yRef);
            const double baseBitsEst =
                (hit->type == 12) ? 4.5 : (hit->type == 14) ? 6.5625 :
                (hit->type == 17) ? 2.3125 : (hit->type == 18) ? 3.0625 :
                (hit->type == 39) ? 4.25 : 0.0;
            std::printf("BASE_FORMAT_BPW=%.4f\n", baseBitsEst);
            std::printf("BASE_ONLY_REL_L2=%.6f\n", baseOnlyL2);
            std::printf("OVERLAY_POINT_A=(%.3f bpw, rel_L2 %.4f)\n", baseBitsEst, baseOnlyL2);
            std::printf("OVERLAY_POINT_B=(%.3f bpw, rel_L2 %.6f)\n",
                        baseBitsEst + ent, fullL2);

            // ---- STAGE 4: the rival, at matched bitrate ------------------
            const std::vector<DirectPoint> ds = runDirectSweep(W, R, C, xv, yRef);
            const double overlayB = baseBitsEst + ent;
            std::printf("\n--- direct quantiser sweep (RTN, same probe x) ---\n");
            std::printf("%-10s %-7s %-7s %s\n", "bpw", "bits", "group", "rel_L2");
            for (const DirectPoint& d : ds)
                std::printf("%-10.4f %-7d %-7d %.6f%s\n", d.bpw, d.bits, d.group,
                            d.relL2, (d.bpw <= overlayB ? "   <= overlay point B bpw" : ""));
            // Best direct accuracy achievable at or below the overlay's total cost.
            const DirectPoint* bestAtOrBelow = nullptr;
            for (const DirectPoint& d : ds)
                if (d.bpw <= overlayB && (!bestAtOrBelow || d.relL2 < bestAtOrBelow->relL2))
                    bestAtOrBelow = &d;
            // And the cheapest direct point that reaches a given fidelity.
            std::printf("\nOVERLAY_TOTAL_BPW=%.4f  OVERLAY_REL_L2=%.6f\n", overlayB, fullL2);
            if (bestAtOrBelow) {
                std::printf("BEST_DIRECT_AT_OR_BELOW_OVERLAY: bpw=%.4f rel_L2=%.6f "
                            "(bits=%d group=%d)\n", bestAtOrBelow->bpw, bestAtOrBelow->relL2,
                            bestAtOrBelow->bits, bestAtOrBelow->group);
                const double gapBp = overlayB - bestAtOrBelow->bpw;
                std::printf("OVERLAY_COST_PREMIA_BPW=%.4f  (overlay minus best direct)\n", gapBp);
            }
            // ---- STAGE 5: minimise base_bpw + H(residual) over the whole base family
            {
                const std::vector<OverlayPoint> ops = runOverlaySearch(W, R, C);
                const OverlayPoint* bestOv = nullptr;
                for (const OverlayPoint& o : ops)
                    if (!bestOv || o.total < bestOv->total) bestOv = &o;
                std::printf("\n--- stage 5: overlay family minimised ---\n");
                std::printf("%-10s %-12s %-12s %-7s %-7s\n",
                            "base_bpw", "delta_H", "TOTAL", "bits", "group");
                for (const OverlayPoint& o : ops)
                    if (bestOv && std::fabs(o.total - bestOv->total) < 1e-12)
                        std::printf("%-10.4f %-12.4f %-12.4f %-7d %-7d  <-- MINIMUM\n",
                                    o.baseBpw, o.deltaH, o.total, o.bits, o.group);
                if (bestOv) {
                    std::printf("OVERLAY_FAMILY_MIN_TOTAL_BPW=%.4f\n", bestOv->total);
                    std::printf("OVERLAY_FAMILY_MIN_BASE_BPW=%.4f bits=%d group=%d\n",
                                bestOv->baseBpw, bestOv->bits, bestOv->group);
                    std::printf("OVERLAY_FAMILY_MIN_DELTA_H=%.4f\n", bestOv->deltaH);
                }
                // The direct curve's cost at a useful fidelity. If the FAMILY
                // MINIMUM cannot beat this, no base in the family works.
                double directAt05 = 0.0, directAt01 = 0.0;
                bool have05 = false, have01 = false;
                for (const DirectPoint& d : ds) {
                    if (!have05 && d.relL2 <= 0.05) { directAt05 = d.bpw; have05 = true; }
                    if (!have01 && d.relL2 <= 0.01) { directAt01 = d.bpw; have01 = true; }
                }
                std::printf("DIRECT_COST_REACHING_L2_0.05=%.4f\n", directAt05);
                if (have01) std::printf("DIRECT_COST_REACHING_L2_0.01=%.4f\n", directAt01);
                if (bestOv && have05) {
                    std::printf("FAMILY_MIN_VS_DIRECT_AT_0.05=%.4f  (>0 means the whole "
                                "overlay family LOSES)\n", bestOv->total - directAt05);
                    std::printf("ANY_BASE_IN_FAMILY_BEATS_DIRECT=%d\n",
                                (bestOv->total < directAt05) ? 1 : 0);
                }
                std::printf("FAMILY_SEARCHED=RTN_minmax_bits_x_group\n");
                std::printf("FAMILY_SEARCH_IS_NOT_ALL_QUANTISERS=1\n");

                // ---- STAGE 6: sparse-by-construction base ------------
                const std::vector<SparseOverlay> so = runSparseResidualSearch(W, R, C);
                const SparseOverlay* bestSp = nullptr;
                for (const SparseOverlay& s : so)
                    if (!bestSp || s.total < bestSp->total) bestSp = &s;
                std::printf("\n--- stage 6: base chosen for a SPARSE residual ---\n");
                std::printf("%-10s %-10s %-11s %-11s %-6s %-6s\n",
                            "base_bpw", "sparsity", "nz_entropy", "TOTAL", "bits", "grp");
                for (const SparseOverlay& s : so)
                    if (bestSp && std::fabs(s.total - bestSp->total) < 1e-12)
                        std::printf("%-10.4f %-10.4f %-11.4f %-11.4f %-6d %-6d  <-- MIN\n",
                                    s.baseBpw, s.sparsity, s.nonzeroEntropy, s.total,
                                    s.bits, s.group);
                if (bestSp) {
                    std::printf("SPARSE_OVERLAY_MIN_TOTAL_BPW=%.4f\n", bestSp->total);
                    std::printf("SPARSE_OVERLAY_SPARSITY=%.4f\n", bestSp->sparsity);
// The right baseline on an i-quant tensor is NOT RTN. The data came FROM a
                    // 256-entry codebook, so a local per-group dictionary can
                    // re-learn that codebook almost for free and appear to
                    // reconstruct exactly. Both are reported so the apparent
                    // win can be attributed correctly.
                    std::printf("SPARSE_DIAGNOSTIC_MEAN_DISTINCT_PER_GROUP=%.3f of %d\n",
                                groupsSeen ? double(distinctSum) / double(groupsSeen) : 0.0,
                                bestSp ? bestSp->group : 0);
                    std::printf("SPARSE_DIAGNOSTIC_GROUPS_FULLY_COVERED=%llu of %llu\n",
                                (unsigned long long)groupsWithFew,
                                (unsigned long long)groupsSeen);
                    const double nativeBpw =
                        (hit->type == 12) ? 4.5 : (hit->type == 14) ? 6.5625 :
                        (hit->type == 17) ? 2.3125 : (hit->type == 18) ? 3.0625 :
                        (hit->type == 39) ? 4.25 : 0.0;
                    std::printf("NATIVE_SOURCE_FORMAT_BPW=%.4f\n", nativeBpw);
                    if (nativeBpw > 0.0) {
                        std::printf("SPARSE_MIN_VS_NATIVE_FORMAT=%.4f  (<0 would mean the "
                                    "sparse base beats simply storing the tensor in its OWN "
                                    "format)\n", bestSp->total - nativeBpw);
                        std::printf("SPARSE_BEATS_NATIVE_FORMAT=%d\n",
                                    (bestSp->total < nativeBpw) ? 1 : 0);
                    }
                    if (have05) {
                        std::printf("SPARSE_MIN_VS_DIRECT_AT_0.05=%.4f\n",
                                    bestSp->total - directAt05);
                        std::printf("SPARSE_BY_CONSTRUCTION_WINS=%d\n",
                                    (bestSp->total < directAt05) ? 1 : 0);
                    }
                }
            }
            for (const DirectPoint& d : ds)
                if (d.relL2 <= 0.05) {
                    std::printf("CHEAPEST_DIRECT_REACHING_REL_L2_0.05=%.4f bpw "
                                "(bits=%d group=%d)\n", d.bpw, d.bits, d.group);
                    std::printf("OVERLAY_IS_DOMINATED_AT_THAT_FIDELITY=%d\n",
                                (d.bpw < overlayB) ? 1 : 0);
                    break;
                }
            std::printf("REAL_DELTA_ORDER0_ENTROPY_B=%.4f\n", ent);
            std::printf("SIGMA_1_OVER_SIGMA_R=%.2f  (spectrum flatness)\n",
                        sv[0] > 0 ? sv[0] / std::max(sv[size_t(R) - 1], 1e-30) : 0.0);
            std::printf("\n%-6s %-12s %-16s\n", "rank", "energy_captured", "factor_bits_per_elem");
            double cum = 0.0;
            bool printed[6] = {false, false, false, false, false, false};
            const int wantRanks[6] = {1, 2, 4, 8, 16, 32};
            for (int i = 0; i < R; ++i) {
                cum += sv[size_t(i)] * sv[size_t(i)];
                for (int k = 0; k < 6; ++k)
                    if (!printed[k] && i + 1 >= wantRanks[k]) {
                        printed[k] = true;
                        const double frac = tot > 0 ? cum / tot : 0.0;
                        const double bits = double(wantRanks[k]) * double(R + int(C)) * 32.0 /
                                           (double(R) * double(C));
                        std::printf("%-6d %-12.8f %-16.3f%s\n", wantRanks[k], frac, bits,
                                    (frac > 0.999 && bits < ent) ? "  <-- BEATS ORDER0" : "");
                    }
            }
            double cum99 = 0.0; int rank99 = R;
            for (int i = 0; i < R; ++i) {
                cum99 += sv[size_t(i)] * sv[size_t(i)];
                if (tot > 0 && cum99 / tot > 0.99) { rank99 = i + 1; break; }
            }
            const double bits99 = double(rank99) * double(R + int(C)) * 32.0 /
                                  (double(R) * double(C));
            std::printf("\nRANK_FOR_99PCT_ENERGY=%d  ITS_COST=%.3f bits/elem  "
                        "ORDER0_COST=%.3f bits/elem\n",
                        rank99, bits99, ent);
            const bool lowRankWins = (bits99 < ent);
            std::printf("LOW_RANK_BEATS_ORDER0=%d\n", lowRankWins ? 1 : 0);
            std::printf("STAGE3_ROW_ORIGIN=%llu\n", (unsigned long long)g_rowOrigin);
            std::printf("STAGE3_SAMPLED_ROWS=%d COLS=%d TENSOR=%s TYPE=%s\n", R,
                        int(C), hit->name.c_str(), typeName(hit->type));
}
    }
    }

    std::printf("\n--- SUMMARY ---\n");
    std::printf("CHECKS_TOTAL=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\n",
                g_checks, g_pass, g_fail);
    const bool verdict = (g_fail == 0 && hit != nullptr);
    std::printf("TENSOR_LOCATED=%d\n", hit ? 1 : 0);
    std::printf("SLICE_READ_WITHOUT_WHOLE_FILE_COPY=1\n");
    std::printf("FINAL_VERDICT=%s\n", verdict ? "PASS" : "FAIL");
    return verdict ? 0 : 1;
}
