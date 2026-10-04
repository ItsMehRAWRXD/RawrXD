// gpu_weight_block_parity_probe.cpp
//
// RAWRXD_GPU_WEIGHT_BLOCK_PARITY_001
//
// THE GATE
// ---------
// Receipt §11 established that the GPU projections are not elementwise equal
// to an offline W*x on an input both routes agree on bit-exactly:
//
//   blk.0.attn_q.weight     Q4_0  COSINE=0.4416
//   blk.0.attn_k.weight     Q4_0  COSINE=0.3009
//   blk.0.attn_v.weight     Q5_0  COSINE=0.3762
//   blk.0.attn_output.weight Q3_K COSINE=0.2198
//
// with a per-head block-norm multiset differing by ~51% on attn_q, which
// separates ARITHMETIC from PERMUTATION. Two causes remained open:
//
//   WEIGHT_DECODE   the packed->float decode is wrong
//   GEMV            the decode is right and the matvec/accumulation is wrong
//
// WHY NO GPU INSTRUMENTATION IS NEEDED TO SEPARATE THEM
// -----------------------------------------------------
// The GPU forward route does not decode quant weights in a shader. It calls the
// production registry dequantizer on the HOST and hands the result to Vulkan:
//
//   src/deep2/Deep2Engine_GpuForward.cpp:266
//       auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
//   src/deep2/Deep2Engine_GpuForward.cpp:267
//       return e.PreparedWeights().Acquire(src, (PreparedDequantFn)deq);
//
// So the weight tile the GPU multiplies by is produced by
// QuantKernelRegistry::GetDequant(). Comparing that against an INDEPENDENT
// canonical decoder therefore answers the weight-decode question exactly, with
// no dump of GPU memory required and no risk of comparing misaligned bytes --
// the failure mode that produced the bogus RMSE=3.8e14 reading in §11.
//
// The reference side is tools/quant_format_reference.hpp, transcribed from
// llama.cpp with provenance recorded in that header. It is never compiled into
// a shipping binary.
//
// HONESTY CONSTRAINTS
// -------------------
//  * The two sides are DIFFERENT implementations. Using the registry decoder on
//    both sides would be an instrument agreeing with itself, which is the exact
//    class of error this repository has now produced twice.
//  * Reference dispatch is by QuantTypeName(), the authoritative mapping, not
//    by a guessed numeric enum.
//  * Element count and block geometry are cross-checked before comparing, so a
//    geometry mismatch is reported rather than compared elementwise anyway.
//  * No expected value is written as a literal. The verdict is computed from
//    the counted differences.

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"
#include "quant_format_reference.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace ref = rawrxd::qref;

namespace {

struct Format {
    const char* name;
    size_t blockElements;
    void (*decode)(const uint8_t*, size_t, float*);
};

// Dispatch by NAME because QuantTypeName() is the authoritative type mapping.
// A guessed numeric enum is exactly the kind of assumption that produced the
// earlier false readings.
const Format* formatFor(const std::string& name) {
    static const Format kFormats[] = {
        { "Q4_0", 32,  &ref::decode_q4_0 },
        { "Q5_0", 32,  &ref::decode_q5_0 },
        { "Q8_0", 32,  &ref::decode_q8_0 },
        { "Q2_K", 256, &ref::decode_q2_K },
        { "Q3_K", 256, &ref::decode_q3_K },
        { "Q4_K", 256, &ref::decode_q4_K },
        { "Q5_K", 256, &ref::decode_q5_K },
        { "Q6_K", 256, &ref::decode_q6_K },
    };
    for (const Format& f : kFormats) {
        if (name == f.name) return &f;
    }
    return nullptr;
}

uint64_t fnv1a(const void* data, size_t bytes) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < bytes; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: gpu_weight_block_parity_probe MODEL.gguf "
                             "[tensor ...]\n");
        return 64;
    }
    const char* modelPath = argv[1];

    // The four projections receipt §11 found elementwise-divergent. Defaulting
    // to exactly those keeps the probe tied to the open question rather than to
    // a convenient sample.
    std::vector<std::string> tensors;
    for (int i = 2; i < argc; ++i) tensors.emplace_back(argv[i]);
    if (tensors.empty()) {
        tensors = { "blk.0.attn_q.weight", "blk.0.attn_k.weight",
                    "blk.0.attn_v.weight", "blk.0.attn_output.weight" };
    }

    std::fprintf(stderr, "GATE=GPU_WEIGHT_BLOCK_PARITY\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);
    std::fprintf(stderr, "PRODUCTION_DECODER=QuantKernelRegistry::GetDequant\n");
    std::fprintf(stderr, "REFERENCE_DECODER=quant_format_reference.hpp(llama.cpp)\n");

    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "FAIL=load %s\n", loader.error().c_str());
        return 1;
    }

    int tensorsChecked = 0, decodePass = 0, decodeFail = 0, skipped = 0;
    uint64_t totalElements = 0, totalDiffs = 0;

    for (const std::string& name : tensors) {
        auto* t = loader.getTensor(name);
        if (!t || !t->data) {
            std::fprintf(stderr, "SKIP name=%s reason=absent\n", name.c_str());
            ++skipped;
            continue;
        }
        const std::string typeName = Deep2::QuantTypeName(static_cast<uint32_t>(t->type));
        const size_t n = static_cast<size_t>(t->numElements());

        const Format* fmt = formatFor(typeName);
        if (!fmt) {
            std::fprintf(stderr, "SKIP name=%s type=%s reason=no_reference_decoder\n",
                         name.c_str(), typeName.c_str());
            ++skipped;
            continue;
        }
        if (n % fmt->blockElements != 0) {
            std::fprintf(stderr,
                "SKIP name=%s type=%s reason=ELEMENT_COUNT_NOT_BLOCK_MULTIPLE "
                "n=%zu block=%zu\n", name.c_str(), typeName.c_str(),
                n, fmt->blockElements);
            ++skipped;
            continue;
        }
        const size_t nBlocks = n / fmt->blockElements;

        // --- production side: the exact kernel the GPU forward path uses ---
        auto prod = Deep2::QuantKernelRegistry::Instance().GetDequant(static_cast<int>(t->type));
        if (!prod) {
            std::fprintf(stderr, "SKIP name=%s type=%s reason=no_production_kernel\n",
                         name.c_str(), typeName.c_str());
            ++skipped;
            continue;
        }
        std::vector<float> a(n, 0.0f), b(n, 0.0f);
        prod(t->data, a.data(), n);

        // --- reference side: independent canonical decode ---
        fmt->decode(t->data, nBlocks, b.data());

        // --- elementwise comparison ---
        size_t firstDiff = SIZE_MAX, diffs = 0;
        double dot = 0.0, na = 0.0, nb = 0.0, maxAbs = 0.0, sumSq = 0.0;
        size_t nonFiniteA = 0, nonFiniteB = 0;
        for (size_t i = 0; i < n; ++i) {
            if (!std::isfinite(a[i])) ++nonFiniteA;
            if (!std::isfinite(b[i])) ++nonFiniteB;
            if (a[i] != b[i]) {
                if (firstDiff == SIZE_MAX) firstDiff = i;
                ++diffs;
            }
            dot += static_cast<double>(a[i]) * b[i];
            na  += static_cast<double>(a[i]) * a[i];
            nb  += static_cast<double>(b[i]) * b[i];
            const double d = std::fabs(static_cast<double>(a[i]) - b[i]);
            if (d > maxAbs) maxAbs = d;
            sumSq += d * d;
        }
        const double cosine = (na > 0.0 && nb > 0.0) ? dot / std::sqrt(na * nb) : 0.0;
        const double rmse = std::sqrt(sumSq / static_cast<double>(n ? n : 1));

        const uint64_t hashA = fnv1a(a.data(), n * sizeof(float));
        const uint64_t hashB = fnv1a(b.data(), n * sizeof(float));

        const bool pass = (diffs == 0) && (nonFiniteA == 0) && (nonFiniteB == 0);
        if (pass) ++decodePass; else ++decodeFail;
        ++tensorsChecked;
        totalElements += n;
        totalDiffs += diffs;

        std::fprintf(stderr,
            "TENSOR name=%s type=%s elements=%zu blocks=%zu\n"
            "  PROD_HASH=%016llx REF_HASH=%016llx HASH_MATCH=%d\n"
            "  DIFF_COUNT=%zu FIRST_DIFF_INDEX=%s MAX_ABS=%.6g RMSE=%.6g COSINE=%.9g\n"
            "  NONFINITE_PROD=%zu NONFINITE_REF=%zu VERDICT=%s\n",
            name.c_str(), typeName.c_str(), n, nBlocks,
            (unsigned long long)hashA, (unsigned long long)hashB,
            hashA == hashB ? 1 : 0,
            diffs,
            firstDiff == SIZE_MAX ? "NONE" : std::to_string(firstDiff).c_str(),
            maxAbs, rmse, cosine,
            nonFiniteA, nonFiniteB, pass ? "PASS" : "FAIL");

        if (!pass && firstDiff != SIZE_MAX) {
            // Smallest provenance tuple that localises the defect: which
            // element, its block, its offset inside that block, and both
            // decoded values. Everything else (scale, payload) is derivable
            // from the block index and offset, so printing the block bytes
            // would be noise.
            const size_t blk = firstDiff / fmt->blockElements;
            const size_t off = firstDiff % fmt->blockElements;
            std::fprintf(stderr,
                "  FIRST_BAD element=%zu block=%zu offset_in_block=%zu "
                "prod=%.9g ref=%.9g delta=%.9g\n",
                firstDiff, blk, off,
                static_cast<double>(a[firstDiff]), static_cast<double>(b[firstDiff]),
                static_cast<double>(a[firstDiff]) - static_cast<double>(b[firstDiff]));
        }
    }

    std::printf("=== RAWRXD_GPU_WEIGHT_BLOCK_PARITY_001 ===\n");
    std::printf("TENSORS_CHECKED=%d\n", tensorsChecked);
    std::printf("TENSORS_SKIPPED=%d\n", skipped);
    std::printf("DECODE_PASS=%d\n", decodePass);
    std::printf("DECODE_FAIL=%d\n", decodeFail);
    std::printf("ELEMENTS_COMPARED=%llu\n", (unsigned long long)totalElements);
    std::printf("TOTAL_DIFFS=%llu\n", (unsigned long long)totalDiffs);
    std::printf("GPU_FORWARD_USES_REGISTRY_DECODER=1\n");
    std::printf("WEIGHT_DECODE=%s\n",
                decodeFail == 0 ? "CLEARED" : "CONVICTED");
    std::printf("VERDICT=%s\n", (decodeFail == 0 && tensorsChecked > 0) ? "PASS" : "FAIL");
    return (decodeFail == 0 && tensorsChecked > 0) ? 0 : 1;
}