// ============================================================================
// quant_block_oracle.cpp — RAWRXD_QUANT_BLOCK_ORACLE_001
// ============================================================================
// Independent canonical block decode vs the production decode, elementwise, on
// REAL BLOCKS READ FROM A REAL MAPPED GGUF. Reports FIRST_DIFF_INDEX.
//
// WHY THIS SHAPE
//   A full generation is the most expensive possible way to find out that a
//   34-byte block is mis-decoded. This runs the cheapest possible discriminator
//   first: take one real packed block, decode it twice -- once from the format
//   specification written out here from scratch, once through the production
//   registry kernel the engine actually calls -- and compare.
//
//   The reference here is deliberately NOT the production code, NOT
//   ggml, and NOT another call into QuantKernelRegistry. It is the format
//   definition transcribed independently, so a shared defect cannot hide behind
//   a shared helper. If both sides were wrong in the same way the test would be
//   worthless, so the only thing these two implementations have in common is
//   the fp16->fp32 conversion, which is written against the IEEE-754 binary16
//   definition and is exact for every input including subnormals.
//
// WHAT IS ESTABLISHED AND WHAT IS NOT
//   PASS on a type  -> production decode of that type agrees with the format
//                      definition, bit for bit, on every block sampled.
//   FAIL on a type  -> the FIRST_DIFF_INDEX names the element, and the printed
//                      reference vs production values name the magnitude. That
//                      is a localized defect: no attention, no sampling, no
//                      runtime is involved.
//   A type absent from the model's tensor table is reported NO_BLOCKS_FOUND and
//   carries no verdict. It is not silently skipped and not silently passed.
//
// TYPES COVERED
//   Q8_0 (type 8)  block_q8_0  { fp16 d; int8 qs[32]; }                    34 B
//   Q4_0 (type 2)  block_q4_0  { fp16 d; fp16 m; uint8 qs[16]; }          18 B
//   Q5_0 (type 6)  block_q5_0  { fp16 d; fp16 m; uint8 qh[4]; uint8 qs[16]; } 22 B
//
// BUILD (standalone; not registered in CMakeLists.txt)
//   cl /nologo /std:c++20 /EHsc /O2 /I src /I src\deep2 /I <VULKAN_SDK>\Include
//      /c /Fo:quant_block_oracle.obj tools\quant_block_oracle.cpp
//   link /OUT:quant_block_oracle.exe quant_block_oracle.obj
//        InferenceEngine.lib rawrxd_remote64.lib vulkan-1.lib
//
// USAGE
//   quant_block_oracle.exe <model.gguf> [blocksPerType]
// ============================================================================

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// fp16 -> fp32, transcribed from the IEEE-754 binary16 definition.
// Not a reinterpretation of the host's conversion: an explicit branch per
// encoding class, so a host FPU quirk cannot decide whether the oracle agrees.
// ---------------------------------------------------------------------------
float half_to_float(std::uint16_t h) {
    const std::uint32_t sign = std::uint32_t(h >> 15) & 1u;
    const std::uint32_t exp  = std::uint32_t(h >> 10) & 0x1Fu;
    const std::uint32_t man  = std::uint32_t(h) & 0x3FFu;
    std::uint32_t bits;
    if (exp == 0u) {
        if (man == 0u) {
            bits = sign << 31;                       // +/- zero
        } else {
            // Subnormal: normalise by shifting until the implicit bit appears.
            int e = -1;
            std::uint32_t m = man;
            do { ++e; m <<= 1; } while ((m & 0x400u) == 0u);
            m &= 0x3FFu;
            bits = (sign << 31) |
                   (std::uint32_t(127 - 15 - e) << 23) |
                   (m << 13);
        }
    } else if (exp == 31u) {
        bits = (sign << 31) | 0x7F800000u | (man << 13);   // inf / NaN
    } else {
        bits = (sign << 31) |
               ((exp + 127u - 15u) << 23) |
               (man << 13);
    }
    float out;
    std::memcpy(&out, &bits, sizeof out);
    return out;
}

int half_bits_to_float_check(std::uint16_t h) {
    // Convenience for printing: signalled when the input was inf/NaN.
    const std::uint32_t exp = std::uint32_t(h >> 10) & 0x1Fu;
    return exp == 31u ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Canonical decoders. Each writes `out[0..count)` and is written only from the
// block layout, not from any production source.
// ---------------------------------------------------------------------------

// block_q8_0: fp16 d; int8 qs[32].  y[i] = qs[i] * d
void decode_q8_0(const std::uint8_t* blk, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 34;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* p = blk + b * kBytes;
        std::uint16_t d16;
        std::memcpy(&d16, p, 2);
        const float d = half_to_float(d16);
        for (std::size_t i = 0; i < kPer; ++i) {
            const float q = float(std::int8_t(p[2 + i]));   // sign-extending
            out[b * kPer + i] = q * d;
        }
    }
}

// block_q4_0: fp16 d; fp16 m; uint8 qs[16].  32 values, two per byte: for
// e = 0,2,4,... the low nibble is element e and the high nibble is element e+1.
//   y = (nibble - 8) * d + m
// NOTE ON ORDERING, learned the hard way: the reference below was first written
// with the Q4_2/Q4_3 ordering (byte j holding elements 16j..16j+15). That is a
// different format. ggml's block_q4_0 pairs CONSECUTIVE elements in one byte, so
// element e reads qs[e/2]. The first run of this oracle reported a mismatch
// that was half reference error and half production error, which is exactly the
// situation where a discriminator stops being informative.
void decode_q4_0(const std::uint8_t* blk, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 18;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* p = blk + b * kBytes;
        std::uint16_t d16, m16;
        std::memcpy(&d16, p, 2);
        std::memcpy(&m16, p + 2, 2);
        const float d = half_to_float(d16);
        const float m = half_to_float(m16);
        for (std::size_t e = 0; e < kPer; ++e) {
            const std::uint8_t byte = p[4 + e / 2];
            const int nib = (e % 2 == 0) ? int(byte & 0x0Fu) : int(byte >> 4);
            out[b * kPer + e] = float(nib - 8) * d + m;
        }
    }
}

// block_q5_0: fp16 d; fp16 m; uint8 qh[4]; uint8 qs[16].  The 5th bit of each
// value lives in qh: for the even element of a pair it is bit (e/4), for the odd
// element bit (e/4 + 1), and it becomes the 0x10 bit before the −16 bias.
//   y = ((nibble | highbit) - 16) * d + m
void decode_q5_0(const std::uint8_t* blk, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 22;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* p = blk + b * kBytes;
        std::uint16_t d16, m16;
        std::memcpy(&d16, p, 2);
        std::memcpy(&m16, p + 2, 2);
        const float d = half_to_float(d16);
        const float m = half_to_float(m16);
        const std::uint8_t* qh = p + 4;     // 4 bytes
        const std::uint8_t* qs = p + 8;     // 16 bytes
        for (std::size_t e = 0; e < kPer; ++e) {
            const std::uint8_t byte = qs[e / 2];
            const int nib = (e % 2 == 0) ? int(byte & 0x0Fu) : int(byte >> 4);
            const int bit = int(e / 4) + int(e % 2);
            const int high = int(((qh[e / 8] >> bit) & 1u) << 4);
            out[b * kPer + e] = float((nib | high) - 16) * d + m;
        }
    }
}

struct TypeSpec {
    int         ggmlType;
    const char* name;
    std::size_t blockBytes;
    std::size_t elemsPerBlock;
    void (*decode)(const std::uint8_t*, std::size_t, float*);
};

const TypeSpec kSpecs[] = {
    { 8, "Q8_0", 34, 32, decode_q8_0 },
    { 2, "Q4_0", 18, 32, decode_q4_0 },
    { 6, "Q5_0", 22, 32, decode_q5_0 },
};

int g_fail = 0;

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <model.gguf> [blocksPerType]\n", argv[0]);
        return 2;
    }
    const std::size_t want = (argc >= 3) ? std::strtoull(argv[2], nullptr, 10) : 4096;

    std::fprintf(stderr, "RAWRXD_QUANT_BLOCK_ORACLE_001\n");
    std::fprintf(stderr, "model=%s\nblocksPerType=%zu\n", argv[1], want);

    Deep2::GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "LOAD_FAIL=%s\n", loader.error().c_str());
        std::fprintf(stderr, "VERDICT=NO_VERDICT_MODEL_UNREADABLE\n");
        return 2;
    }

    // Registry invariant first: an uninitialised registry produces an empty
    // dequant table, which looks exactly like "no kernel for this type".
    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();

    std::printf("%-6s %-10s %-10s %-12s %-14s %-14s %s\n",
                "TYPE", "TENSORS", "BLOCKS", "BYTES_CMP",
                "MAX_ABS_DIFF", "FIRST_DIFF", "VERDICT");

    int verdicts = 0, noBlocks = 0;

    for (const TypeSpec& s : kSpecs) {
        // Find the largest tensor of this type so the sample comes from real
        // weight data rather than from a 20 KB norm vector.
        const Deep2::GGUFTensor* best = nullptr;
        std::size_t bestBytes = 0;
        std::size_t tensorCount = 0;
        for (const auto& n : loader.listTensors()) {
            const auto* t = loader.getTensor(n);
            if (!t || static_cast<int>(t->type) != s.ggmlType) continue;
            ++tensorCount;
            if (t->sizeBytes > bestBytes) { bestBytes = t->sizeBytes; best = t; }
        }
        if (!best || !best->data) {
            std::printf("%-6s %-10zu %-10s %-12s %-14s %-14s %s\n",
                        s.name, tensorCount, "-", "-", "-", "-", "NO_BLOCKS_FOUND");
            ++noBlocks;
            continue;
        }

        std::size_t be = 0, bb = 0;
        const bool geom = Deep2::GGUFLoader::queryTypeGeometry(
            static_cast<std::uint32_t>(s.ggmlType), be, bb);
        // The oracle asserts the geometry independently. If the registry's
        // block size disagrees with the format definition, that disagreement IS
        // the defect and it is reported before any element is compared.
        if (!geom || bb != s.blockBytes || be != s.elemsPerBlock) {
            std::printf("%-6s %-10zu %-10s %-12s %-14s %-14s %s\n",
                        s.name, tensorCount, "-", "-", "-", "-",
                        "GEOMETRY_MISMATCH");
            ++g_fail; ++verdicts;
            std::fprintf(stderr,
                "  registry geometry blockElems=%zu blockBytes=%zu ; "
                "format definition blockElems=%zu blockBytes=%zu\n",
                be, bb, s.elemsPerBlock, s.blockBytes);
            continue;
        }

        Deep2::DequantKernelFn dq = reg.GetDequant(s.ggmlType);
        if (!dq) {
            std::printf("%-6s %-10zu %-10s %-12s %-14s %-14s %s\n",
                        s.name, tensorCount, "-", "-", "-", "-",
                        "NO_DEQUANT_KERNEL");
            ++g_fail; ++verdicts;
            continue;
        }

        const std::size_t nBlocks = std::min<std::size_t>(want, best->sizeBytes / s.blockBytes);
        const std::size_t nElems  = nBlocks * s.elemsPerBlock;
        if (!nBlocks) {
            std::printf("%-6s %-10zu %-10zu %-12s %-14s %-14s %s\n",
                        s.name, tensorCount, nBlocks, "-", "-", "-", "NO_BLOCKS_FOUND");
            ++noBlocks;
            continue;
        }

        std::vector<float> ref(nElems, 0.0f);
        std::vector<float> got(nElems, 0.0f);

        s.decode(best->data, nBlocks, ref.data());
        dq(best->data, got.data(), nElems);

        long long firstDiff = -1;
        double maxAbs = 0.0;
        std::size_t mismatch = 0;
        for (std::size_t i = 0; i < nElems; ++i) {
            // Bit-exact first. A tolerance here would hide exactly the class of
            // defect this oracle exists to find, so equality means equality.
            if (std::memcmp(&ref[i], &got[i], sizeof(float)) != 0) {
                if (firstDiff < 0) firstDiff = (long long)i;
                ++mismatch;
                const double d = std::fabs(double(ref[i]) - double(got[i]));
                if (std::isfinite(d) && d > maxAbs) maxAbs = d;
            }
        }

        char dBuf[32], mBuf[32], bdBuf[32];
        if (firstDiff < 0) {
            std::snprintf(dBuf, sizeof dBuf, "-");
            std::snprintf(mBuf, sizeof mBuf, "0");
        } else {
            std::snprintf(dBuf, sizeof dBuf, "%lld", firstDiff);
            std::snprintf(mBuf, sizeof mBuf, "%zu", mismatch);
        }
        std::snprintf(bdBuf, sizeof bdBuf, "%zu", nBlocks * s.blockBytes);

        const bool ok = (firstDiff < 0);
        if (!ok) ++g_fail;
        ++verdicts;
        std::printf("%-6s %-10zu %-10zu %-12s %-14.9g %-14s %s  mismatched=%s\n",
                    s.name, tensorCount, nBlocks, bdBuf, maxAbs, dBuf,
                    ok ? "PARITY" : "MISMATCH", mBuf);

        if (!ok) {
            const std::size_t i = std::size_t(firstDiff);
            const std::size_t blk = i / s.elemsPerBlock;
            const std::size_t off = i % s.elemsPerBlock;
            const std::uint8_t* raw = best->data + blk * s.blockBytes;
            std::fprintf(stderr,
                "  FIRST_DIFF element=%zu  block=%zu offsetInBlock=%zu\n"
                "    reference = %.9g (bits 0x%08llx)\n"
                "    production= %.9g (bits 0x%08llx)\n"
                "    raw block bytes:",
                i, blk, off, double(ref[i]),
                (unsigned long long)*(std::uint32_t*)&ref[i],
                double(got[i]),
                (unsigned long long)*(std::uint32_t*)&got[i]);
            for (std::size_t b = 0; b < s.blockBytes; ++b)
                std::fprintf(stderr, " %02X", raw[b]);
            std::fprintf(stderr, "\n");
            // fp16 scale of the offending block, so a wrong d/m is immediately
            // distinguishable from a wrong unpacking.
            if (s.blockBytes >= 4) {
                std::uint16_t d16, m16;
                std::memcpy(&d16, raw, 2);
                std::memcpy(&m16, raw + 2, 2);
                std::fprintf(stderr,
                    "    block fp16 d=0x%04X (%s)  m=0x%04X (%s)\n",
                    d16, half_bits_to_float_check(d16) ? "inf/NaN" : "finite",
                    m16, half_bits_to_float_check(m16) ? "inf/NaN" : "finite");
            }
            std::fprintf(stderr, "    tensor=%s byteOffset=%zu\n",
                         loader.listTensors().empty() ? "?" : best->name.c_str(),
                         std::size_t(blk * s.blockBytes));
        }
    }

    std::fprintf(stderr, "\nTYPES_WITH_VERDICT=%d  TYPES_WITH_NO_BLOCKS=%d  FAILURES=%d\n",
                 verdicts, noBlocks, g_fail);
    if (verdicts == 0) {
        std::fprintf(stderr,
            "VERDICT=NO_VERDICT_NONE_OF_THE_TYPES_UNDER_TEST_APPEAR_IN_THIS_MODEL\n");
        return 2;
    }
    std::fprintf(stderr, "VERDICT=%s\n", g_fail == 0 ? "PARITY_ALL_UNDER_TEST" : "MISMATCH_FOUND");
    return g_fail == 0 ? 0 : 1;
}
