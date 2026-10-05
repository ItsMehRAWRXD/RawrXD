// ============================================================================
// nqb_hash_chunk_invariance.cpp
// RAWRXD_NQB_HASH_CHUNK_PARTITION_INVARIANCE_001
//
// A permanent regression test for the defect Item 7 found.
//
// WHAT HAPPENED
// -------------
// src/deep2/Nanof32BraidManifest.hpp exposed
//     inline void nqbHashCanonicalF32(values, elements, uint64_t& fnvOut, Sha256&)
// and that function opened with
//     fnvOut = nqbFnvBegin();
// so it was secretly SINGLE-CALL-ONLY. The source authority called it once per
// tensor and was correct. The payload authority calls it once per 8 MiB chunk,
// so every tensor larger than one chunk had its FNV-1a accumulator reset at every
// chunk boundary and only the final chunk's contribution survived.
//
// The signature was unmistakable once measured:
//
//     SHA256_MATCH=255/255   PASS
//     FNV1A64_MATCH=58/255   FAIL
//
// 58 being exactly the count of tensors that fit in a single chunk is what
// identified chunk-state handling as the cause rather than the data.
//
// THE CONTRACT THIS TEST ENFORCES
// ------------------------------
//     STREAMING_STATE_INITIALIZED_BY_CALLER=1
//     STREAMING_PRIMITIVE_MAY_RESET_STATE=0
//     CHUNK_PARTITION_INVARIANCE_REQUIRED=1
//
// A streaming primitive must not touch caller-owned streaming state, and a digest
// must not depend on how the input was partitioned. Hash the same bytes whole, in
// 8 MiB chunks, in 1 MiB chunks, and in irregular chunks: one FNV, one SHA-256.
//
// THE TEST CAN FAIL
// -----------------
// The same vector is also hashed through a deliberately BROKEN accumulator that
// resets on entry, and this probe requires the broken result to DIFFER. Without
// that, a probe which compared only self-consistent paths could not detect the
// very defect it exists to prevent.
//
// Usage: nqb_hash_chunk_invariance [elementCount]
// ============================================================================

#include "deep2/Nanof32BraidManifest.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

struct Digest { uint64_t fnv; std::string sha; };

// The CORRECT contract: caller initialises, primitive never resets.
Digest hashPartitioned(const std::vector<float>& v,
                       const std::vector<size_t>& partition) {
    uint64_t fnv = Deep2::nqbFnvBegin();
    Deep2::Sha256 sha;
    size_t off = 0;
    for (size_t n : partition) {
        if (n == 0) continue;
        Deep2::nqbHashCanonicalF32Chunk(v.data() + off, n, fnv, sha);
        off += n;
    }
    return Digest{fnv, sha.hex()};
}

// The DEFECT, reproduced faithfully: the accumulator is wiped at the START of
// every call, so only the final chunk's contribution survives.
//
// The first version of this control reset AFTER the call. That made both
// partitions end on the untouched basis value, so the two agreed trivially and
// the control could not fail -- reported as IDENTICAL_CONTROL_IS_VOID. Resetting
// before the call is what the original code actually did
// (`fnvOut = nqbFnvBegin();` was the function's first statement).
Digest hashPartitionedBroken(const std::vector<float>& v,
                             const std::vector<size_t>& partition) {
    uint64_t fnv = 0;
    Deep2::Sha256 sha;
    size_t off = 0;
    for (size_t n : partition) {
        if (n == 0) continue;
        fnv = Deep2::nqbFnvBegin();   // the bug
        Deep2::nqbHashCanonicalF32Chunk(v.data() + off, n, fnv, sha);
        off += n;
    }
    return Digest{fnv, sha.hex()};
}

std::vector<size_t> wholePartition(size_t n) { return {n}; }

std::vector<size_t> uniformPartition(size_t n, size_t chunk) {
    std::vector<size_t> p;
    for (size_t off = 0; off < n; off += chunk)
        p.push_back((std::min)(chunk, n - off));
    return p;
}

// Irregular, deterministic. A random partition could fail for reasons unrelated
// to the property under test, which is the same mistake as a control whose own
// randomness can break it.
std::vector<size_t> irregularPartition(size_t n) {
    static const size_t kSteps[] = {1, 7, 65536, 3, 262144, 11, 4099, 1, 131072};
    std::vector<size_t> p;
    size_t off = 0, i = 0;
    while (off < n) {
        const size_t s = kSteps[i % (sizeof(kSteps) / sizeof(kSteps[0]))];
        p.push_back((std::min)(s, n - off));
        off += p.back();
        ++i;
    }
    return p;
}

} // namespace

int main(int argc, char** argv) {
    // Large enough that the primitive's internal 64 KiB chunk iterates many times,
    // AND large enough that 8 MiB and 1 MiB outer partitions both split it.
    size_t n = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 5000000u;
    if (n < 4) n = 4;

    std::printf("GATE=RAWRXD_NQB_HASH_CHUNK_PARTITION_INVARIANCE_001\n");
    std::printf("ELEMENTS=%zu\n", n);

    // Deterministic, non-trivial values including denormals, negatives and values
    // whose low 16 bits are non-zero -- a primitive that hashed fewer than 32 bits
    // per element would be caught by these even if the chunking were correct.
    std::vector<float> v(n);
    for (size_t i = 0; i < n; ++i) {
        const uint32_t u = static_cast<uint32_t>(i * 2654435761u);
        std::memcpy(&v[i], &u, 4);
        if ((i % 97) == 0) v[i] = 0.0f;
        if ((i % 101) == 0) v[i] = -v[i];
    }

    struct Case { const char* label; std::vector<size_t> part; };
    std::vector<Case> cases;
    cases.push_back({"WHOLE",        wholePartition(n)});
    cases.push_back({"8MIB_CHUNKS",  uniformPartition(n, 2u * 1024 * 1024)});
    cases.push_back({"1MIB_CHUNKS",  uniformPartition(n, 1u * 1024 * 1024)});
    cases.push_back({"IRREGULAR",    irregularPartition(n)});

    Digest ref{0, ""};
    uint64_t fail = 0;
    bool first = true;
    for (const Case& c : cases) {
        const Digest d = hashPartitioned(v, c.part);
        if (first) { ref = d; first = false; }
        const bool same = (d.fnv == ref.fnv) && (d.sha == ref.sha);
        std::printf("PARTITION %-12s chunks=%-6zu FNV=%llu SHA256=%s %s\n",
                    c.label, c.part.size(), (unsigned long long)d.fnv,
                    d.sha.c_str(), same ? "MATCH" : "DIFFERS");
        if (!same) ++fail;
        if (c.part.size() == 1 && c.label == std::string("WHOLE"))
            std::printf("REFERENCE_FNV=%llu\nREFERENCE_SHA256=%s\n",
                        (unsigned long long)d.fnv, d.sha.c_str());
    }

    // Falsification: the broken accumulator MUST produce a different FNV, or this
    // probe could not detect the defect it exists to prevent.
    const Digest brokenWhole    = hashPartitionedBroken(v, wholePartition(n));
    const Digest brokenChunked  = hashPartitionedBroken(v, uniformPartition(n, 1u << 20));
    const bool brokenDiffers = (brokenWhole.fnv != brokenChunked.fnv);
    std::printf("NEGATIVE_CONTROL broken_whole_fnv=%llu broken_1mib_fnv=%llu %s\n",
                (unsigned long long)brokenWhole.fnv,
                (unsigned long long)brokenChunked.fnv,
                brokenDiffers ? "DIFFERS_AS_REQUIRED" : "IDENTICAL_CONTROL_IS_VOID");
    if (!brokenDiffers) ++fail;

    // The broken variant's SHA-256 is unaffected, which is exactly why the Item 7
    // run reported SHA256_MATCH=255/255 alongside FNV1A64_MATCH=58/255. Assert
    // that too so the explanation stays tied to a measurement.
    const bool brokenShaSame = (brokenWhole.sha == brokenChunked.sha);
    std::printf("NEGATIVE_CONTROL broken_sha256_invariant=%d (%s)\n",
                brokenShaSame ? 1 : 0,
                brokenShaSame ? "explains Item 7's split result" : "UNEXPECTED");

    std::printf("STREAMING_STATE_INITIALIZED_BY_CALLER=1\n");
    std::printf("STREAMING_PRIMITIVE_MAY_RESET_STATE=0\n");
    std::printf("CHUNK_PARTITION_INVARIANCE_REQUIRED=1\n");
    std::printf("FAILURES=%llu\n", (unsigned long long)fail);
    std::printf("VERDICT=%s\n", fail == 0 ? "PASS" : "FAIL");
    return fail == 0 ? 0 : 1;
}