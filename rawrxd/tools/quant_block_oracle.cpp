// ============================================================================
// quant_block_oracle.cpp — RAWRXD_QUANT_BLOCK_ORACLE_002
// ============================================================================
// Independent canonical block decode vs the production decode, elementwise, on
// REAL BLOCKS READ FROM A REAL MAPPED GGUF. Reports FIRST_DIFF_INDEX.
//
// WHAT CHANGED FROM 001, AND WHY (measured, not stylistic)
//   001 tested Q8_0, Q4_0 and Q5_0 only. Built and run against the two files
//   the Q2_K-vs-Q4_K question is actually about, all three are absent and it
//   correctly reported NO_VERDICT on both:
//
//     quant_block_oracle.exe G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf
//     quant_block_oracle.exe F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf
//       Q8_0 0 tensors / Q4_0 0 tensors / Q5_0 0 tensors
//       VERDICT=NO_VERDICT_NONE_OF_THE_TYPES_UNDER_TEST_APPEAR_IN_THIS_MODEL
//
//   An instrument whose subject list is disjoint from its subject measures
//   nothing. 002 therefore enumerates the types FROM THE FILE and looks each
//   one up in tools/quant_format_reference.hpp, so a new model is covered
//   without editing a table here.
//
//   001's Q4_0 and Q5_0 references were also wrong, and wrong in a way that
//   manufactured a finding. It modelled both as `{d, m, qs[16]}`; upstream
//   block_q4_0 is `{d, qs[16]}` (18 B) and block_q5_0 is `{d, qh[4], qs[16]}`
//   (22 B), and both pair SPLIT (element j and element j+16 from byte j) with a
//   zero point. See the field-order and pairing notes in quant_format_reference.hpp.
//   A MISMATCH from the old reference is therefore not evidence about
//   production. It is retracted; 002 re-derives it from the specification.
//
// THE INSTRUMENT'S ONE HONEST LIMIT
//   A type present in the file with no canonical decoder is reported
//   NO_REFERENCE and counted. It is never skipped silently and never counted as
//   a pass. If NO_REFERENCE covers any bytes, the run says so in the verdict.
//
// BUILD (standalone; deliberately not registered in CMakeLists.txt — see the
// adoption note in the receipt)
//   cl /nologo /std:c++20 /EHsc /O2 /MT /I src /I src\deep2 /I tools /c /Fo:qbo.obj tools\quant_block_oracle.cpp
//   link /OUT:quant_block_oracle.exe qbo.obj InferenceEngine.lib rawrxd_remote64.lib vulkan-1.lib
//
// USAGE
//   quant_block_oracle.exe <model.gguf> [blocksPerType]
// ============================================================================

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include "quant_format_reference.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

struct TypeCensus {
    int         ggmlType = 0;
    std::size_t tensors  = 0;
    unsigned long long bytes = 0;
    const Deep2::GGUFTensor* largest = nullptr;
};

void printHeaderLine() {
    std::printf("%-8s %-8s %-9s %-12s %-8s %-11s %-13s %-12s %s\n",
                "TYPE", "TENSORS", "BYTES", "SAMPLED", "GEOMETRY",
                "MAX_ABS_DIFF", "FIRST_DIFF", "MISMATCHED", "VERDICT");
}

// Every fp16 word in the offending block, with its byte offset. A field-order
// inversion inside an otherwise-correct block size is invisible to a byte
// comparison and obvious here: the sane scale sits at some offset other than 0.
void probeFp16Offsets(const std::uint8_t* blk, std::size_t blockBytes) {
    std::fprintf(stderr, "    fp16 probe (offset: value):");
    for (std::size_t o = 0; o + 1 < blockBytes && o < 128; o += 2) {
        std::uint16_t h;
        std::memcpy(&h, blk + o, 2);
        const float v = rawrxd::qref::half_to_float(h);
        std::fprintf(stderr, " %zu:%.6g%s", o, double(v),
                     rawrxd::qref::half_is_nonfinite(h) ? "(nf)" : "");
    }
    std::fprintf(stderr, "\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <model.gguf> [blocksPerType]\n", argv[0]);
        return 2;
    }
    const std::size_t want = (argc >= 3) ? std::strtoull(argv[2], nullptr, 10) : 4096;

    std::fprintf(stderr, "RAWRXD_QUANT_BLOCK_ORACLE_002\n");
    std::fprintf(stderr, "model=%s\nblocksPerType=%zu\n", argv[1], want);
    std::fprintf(stderr,
        "reference=tools/quant_format_reference.hpp "
        "(ggml-common.h + ggml-quants.c, ggml-org/llama.cpp master, 2026-10-04)\n");
    std::fprintf(stderr,
        "tolerance=NONE  comparison=memcmp on the float bit pattern\n");

    Deep2::GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "LOAD_FAIL=%s\n", loader.error().c_str());
        std::fprintf(stderr, "VERDICT=NO_VERDICT_MODEL_UNREADABLE\n");
        return 2;
    }

    // Registry invariant first. Instance() is not a ready registry; omitting
    // Initialize() yields an empty dequant table, which is indistinguishable
    // from "this quant type is unsupported".
    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();

    // ---- census: the types are read off the tensor table, never the filename
    std::vector<TypeCensus> census;
    for (const auto& n : loader.listTensors()) {
        const auto* t = loader.getTensor(n);
        if (!t) continue;
        const int ty = static_cast<int>(t->type);
        TypeCensus* slot = nullptr;
        for (auto& c : census) if (c.ggmlType == ty) { slot = &c; break; }
        if (!slot) { census.push_back(TypeCensus{}); slot = &census.back(); slot->ggmlType = ty; }
        ++slot->tensors;
        slot->bytes += static_cast<unsigned long long>(t->sizeBytes);
        if (!slot->largest || t->sizeBytes > slot->largest->sizeBytes) slot->largest = t;
    }
    // Dominant type first: the order a reader needs is the order that decides
    // whether the decode is plausible at all.
    std::sort(census.begin(), census.end(),
              [](const TypeCensus& a, const TypeCensus& b) { return a.bytes > b.bytes; });

    unsigned long long totalBytes = 0;
    for (const auto& c : census) totalBytes += c.bytes;

    std::fprintf(stderr, "\n-- TYPE CENSUS (from the file's tensor table)\n");
    for (const auto& c : census) {
        const char* nm = rawrxd::qref::ggmlTypeName(c.ggmlType);
        const double pct = totalBytes ? (100.0 * double(c.bytes) / double(totalBytes)) : 0.0;
        std::fprintf(stderr, "   type=%-3d %-8s tensors=%-6zu bytes=%-14llu %7.4f%%\n",
                     c.ggmlType, nm ? nm : "UNKNOWN", c.tensors, c.bytes, pct);
    }
    std::fprintf(stderr, "   DISTINCT_TYPES=%zu TOTAL_TENSOR_BYTES=%llu\n\n",
                 census.size(), totalBytes);

    printHeaderLine();

    int judged = 0, parity = 0, mismatched = 0, noRef = 0, noKernel = 0,
        geomBad = 0, unjudgeableBytes = 0;

    for (const TypeCensus& c : census) {
        const char* nm = rawrxd::qref::ggmlTypeName(c.ggmlType);
        char nameBuf[16];
        if (!nm) { std::snprintf(nameBuf, sizeof nameBuf, "T%d", c.ggmlType); nm = nameBuf; }

        // ---- is there a canonical decoder for this type at all?
        const rawrxd::qref::ReferenceType* rt = rawrxd::qref::findReferenceType(c.ggmlType);
        if (!rt) {
            std::printf("%-8s %-8zu %-9llu %-12s %-8s %-11s %-13s %-12s %s\n",
                        nm, c.tensors, c.bytes, "-", "-", "-", "-", "-",
                        "NO_REFERENCE");
            ++noRef;
            unjudgeableBytes += c.bytes;
            continue;
        }
        if (!c.largest || !c.largest->data) {
            std::printf("%-8s %-8zu %-9llu %-12s %-8s %-11s %-13s %-12s %s\n",
                        nm, c.tensors, c.bytes, "-", "-", "-", "-", "-",
                        "NO_BLOCKS_FOUND");
            ++noRef;
            unjudgeableBytes += c.bytes;
            continue;
        }

        // ---- geometry is asserted by the oracle, not taken from the registry
        std::size_t regElems = 0, regBytes = 0;
        const bool geom = Deep2::GGUFLoader::queryTypeGeometry(
            static_cast<std::uint32_t>(c.ggmlType), regElems, regBytes);
        char geomBuf[32];
        if (!geom)          std::snprintf(geomBuf, sizeof geomBuf, "UNKNOWN");
        else if (regBytes != rt->blockBytes || regElems != rt->elemsPerBlock)
            std::snprintf(geomBuf, sizeof geomBuf, "MISMATCH");
        else                std::snprintf(geomBuf, sizeof geomBuf, "AGREE");
        if (std::strcmp(geomBuf, "AGREE") != 0) {
            std::printf("%-8s %-8zu %-9llu %-12s %-8s %-11s %-13s %-12s %s\n",
                        nm, c.tensors, c.bytes, "-", geomBuf, "-", "-", "-",
                        (geom ? "GEOMETRY_MISMATCH" : "REGISTRY_GEOMETRY_UNKNOWN"));
            ++geomBad;
            std::fprintf(stderr,
                "    registry says blockElems=%zu blockBytes=%zu ; format definition says "
                "blockElems=%zu blockBytes=%zu\n",
                regElems, regBytes, rt->elemsPerBlock, rt->blockBytes);
            continue;
        }

        Deep2::DequantKernelFn dq = reg.GetDequant(c.ggmlType);
        if (!dq) {
            std::printf("%-8s %-8zu %-9llu %-12s %-8s %-11s %-13s %-12s %s\n",
                        nm, c.tensors, c.bytes, "-", geomBuf, "-", "-", "-",
                        "NO_DEQUANT_KERNEL");
            ++noKernel;
            continue;
        }

        // Sample from the largest tensor of this type: real weight data, not a
        // 12 KB norm vector. Blocks, not elements, so the byte range compared is
        // a whole number of blocks on both sides.
        const std::size_t avail = c.largest->sizeBytes / rt->blockBytes;
        const std::size_t nBlocks = std::min<std::size_t>(want, avail);
        if (!nBlocks) {
            std::printf("%-8s %-8zu %-9llu %-12zu %-8s %-11s %-13s %-12s %s\n",
                        nm, c.tensors, c.bytes, nBlocks, geomBuf, "-", "-", "-",
                        "NO_BLOCKS_FOUND");
            ++noRef;
            unjudgeableBytes += c.bytes;
            continue;
        }
        const std::size_t nElems = nBlocks * rt->elemsPerBlock;

        std::vector<float> ref(nElems, 0.0f);
        std::vector<float> got(nElems, 0.0f);
        rt->decode(c.largest->data, nBlocks, ref.data());
        dq(c.largest->data, got.data(), nElems);

        long long firstDiff = -1;
        double maxAbs = 0.0, maxRefMag = 0.0, maxGotMag = 0.0;
        std::size_t mismatch = 0, nonFinite = 0;
        for (std::size_t i = 0; i < nElems; ++i) {
            maxRefMag = std::max(maxRefMag, std::fabs(double(ref[i])));
            maxGotMag = std::max(maxGotMag, std::fabs(double(got[i])));
            if (!std::isfinite(ref[i]) || !std::isfinite(got[i])) ++nonFinite;
            if (std::memcmp(&ref[i], &got[i], sizeof(float)) != 0) {
                if (firstDiff < 0) firstDiff = (long long)i;
                ++mismatch;
                const double d = std::fabs(double(ref[i]) - double(got[i]));
                if (std::isfinite(d) && d > maxAbs) maxAbs = d;
            }
        }

        char diffBuf[32], firstBuf[32], misBuf[32];
        if (firstDiff < 0) {
            std::snprintf(diffBuf,  sizeof diffBuf,  "0");
            std::snprintf(firstBuf, sizeof firstBuf, "-");
            std::snprintf(misBuf,   sizeof misBuf,   "0");
        } else {
            std::snprintf(diffBuf,  sizeof diffBuf,  "%.9g", maxAbs);
            std::snprintf(firstBuf, sizeof firstBuf, "%lld", firstDiff);
            std::snprintf(misBuf,   sizeof misBuf,   "%zu", mismatch);
        }
        const bool ok = (firstDiff < 0);
        ++judged;
        if (ok) ++parity; else ++mismatched;
        if (!ok) ++g_fail;

        std::printf("%-8s %-8zu %-9llu %-12zu %-8s %-11s %-13s %-12s %s\n",
                    nm, c.tensors, c.bytes, nBlocks, geomBuf, diffBuf, firstBuf,
                    misBuf, ok ? "PARITY" : "MISMATCH");

        if (!ok) {
            const std::size_t i  = std::size_t(firstDiff);
            const std::size_t bk = i / rt->elemsPerBlock;
            const std::size_t of = i % rt->elemsPerBlock;
            const std::uint8_t* raw = c.largest->data + bk * rt->blockBytes;
            std::fprintf(stderr,
                "  TYPE=%s TENSOR=%s\n"
                "    FIRST_DIFF element=%zu block=%zu offsetInBlock=%zu (of %zu)\n"
                "    reference = %.9g   (bits 0x%08llx)\n"
                "    production= %.9g   (bits 0x%08llx)\n"
                "    max|reference|=%.9g  max|production|=%.9g  nonFiniteElements=%zu\n"
                "    bytes_compared=%zu mismatched=%zu (%.4f%%)\n",
                nm, c.largest->name.c_str(), i, bk, of, rt->elemsPerBlock,
                double(ref[i]), (unsigned long long)*(std::uint32_t*)&ref[i],
                double(got[i]), (unsigned long long)*(std::uint32_t*)&got[i],
                maxRefMag, maxGotMag, nonFinite,
                nBlocks * rt->blockBytes, mismatch,
                nElems ? (100.0 * double(mismatch) / double(nElems)) : 0.0);
            probeFp16Offsets(raw, rt->blockBytes);
            // Numeric bisect of the failing element: print the inputs the two
            // decoders must have disagreed on. Without this, "reference !=
            // production at element 0" is a location, not a cause.
            {
                const std::size_t ne = std::min<std::size_t>(8, rt->elemsPerBlock);
                std::fprintf(stderr, "    first %zu elements  reference | production:", ne);
                for (std::size_t k = 0; k < ne; ++k)
                    std::fprintf(stderr, " %.6g|%.6g",
                                 double(ref[bk * rt->elemsPerBlock + k]),
                                 double(got[bk * rt->elemsPerBlock + k]));
                std::fprintf(stderr, "\n");
            }
            std::fprintf(stderr, "    first %zu raw bytes:", std::min<std::size_t>(rt->blockBytes, 192));
            for (std::size_t k = 0; k < std::min<std::size_t>(rt->blockBytes, 192); ++k)
                std::fprintf(stderr, " %02X", raw[k]);
            std::fprintf(stderr, "\n");
        }
    }

    // ---- verdict, computed from the counters above and nothing else
    const double unjudgedPct = totalBytes ? (100.0 * double(unjudgeableBytes) / double(totalBytes)) : 0.0;
    std::fprintf(stderr,
        "\nTYPES_PRESENT=%zu  TYPES_JUDGED=%d  PARITY=%d  MISMATCH=%d\n"
        "GEOMETRY_MISMATCH=%d  NO_DEQUANT_KERNEL=%d  NO_REFERENCE=%d\n"
        "UNJUDGED_TENSOR_BYTES=%llu (%.4f%% of %llu)\n"
        "TYPES_WITH_VERDICT=%d  FAILURES=%d\n",
        census.size(), judged, parity, mismatched,
        geomBad, noKernel, noRef,
        (unsigned long long)unjudgeableBytes, unjudgedPct,
        (unsigned long long)totalBytes,
        judged + geomBad + noKernel, g_fail);

    if (judged == 0) {
        std::fprintf(stderr,
            "VERDICT=NO_VERDICT_NO_TYPE_IN_THIS_FILE_HAS_A_CANONICAL_DECODER\n");
        return 2;
    }
    if (mismatched > 0) {
        std::fprintf(stderr, "VERDICT=MISMATCH_FOUND\n");
        return 1;
    }
    if (unjudgeableBytes > 0) {
        // Not a pass. "Every type I could judge agreed" and "the file is
        // correct" are different claims and only one of them was measured.
        std::fprintf(stderr,
            "VERDICT=PARTIAL_PARITY_WITH_UNJUDGED_BYTES\n"
            "NOTE=types carrying %.4f%% of this file's tensor bytes have no canonical\n"
            "     decoder in the reference, so they carry no verdict in either\n"
            "     direction. PARITY below covers %d of %zu types only.\n",
            unjudgedPct, judged, census.size());
        return 1;
    }
    std::fprintf(stderr, "VERDICT=PARITY_ALL_TYPES_IN_THIS_FILE\n");
    return 0;
}