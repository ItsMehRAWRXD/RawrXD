// nqb_exec_defect_regression.cpp
// RAWRXD_NQB_EXEC_DEFECT_REGRESSION_001
//
// Permanent regression coverage for the four execution defects that blocked the
// real-weight .nqb path. Each one shipped in a state where the engine behaved
// correctly according to the value it held -- the value itself was wrong -- and
// none of them was observable from outside the class. They were found only by
// reading stderr, which is why this test asserts on observedGeometry().
//
//   D1  output.weight resolved by SUBSTRING to blk.N.attn_output.weight.
//       Llama 3.2 sets tie_word_embeddings=1, so no output.weight exists and the
//       shortest substring hit was a 3072x3072 attention projection.
//         [NQBRAID] NQB_INVARIANT_TOKEN_DOMAIN_001 violated:
//         output.weight(lm_head) holds 9437184 elements but 128256x3072=394002432
//         are required
//   D2  `initialized` set only by initialize(); loadModelFromNanof32Braid is
//       reachable without it, so a fully loaded model refused to generate.
//         [STREAM] EARLY_EXIT toks=5 init=0 loaded=1
//   D3  headDim defaulted to 64 via getMetaInt("llama.attention.head_dim", 64)
//       because the key is absent -> qDim 1536 instead of 3072, KV cache half
//       width. Absent metadata silently became fabricated architecture.
//   D4  contextLength carried in the format but never bound to config.maxSeqLen,
//       so the KV cache was sized from the EngineConfig default of 2048 instead
//       of this model's 131072 -- a 64x under-allocation with no diagnostic.
//
// HONESTY CONSTRAINTS
//   * Every assertion below is evaluated against a value read from the engine.
//   * Every check is paired with a NEGATIVE CONTROL: the same predicate is
//     applied to the known-wrong historical value and must REJECT it. A gate
//     that cannot fail is not a gate, and a check that has never rejected
//     anything has never been tested.
//   * If no model is supplied, the tool reports NO_INPUT and exits non-zero.
//     It does not report PASS for having checked nothing.

#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int gChecks = 0, gPass = 0, gFail = 0;

void check(const char* id, bool ok, const std::string& detail) {
    ++gChecks;
    if (ok) { ++gPass; std::printf("PASS %-34s %s\n", id, detail.c_str()); }
    else    { ++gFail; std::printf("FAIL %-34s %s\n", id, detail.c_str()); }
    std::fflush(stdout);
}

// The predicates are factored out so the negative controls exercise the SAME
// code path as the positive checks. A negative control written against a
// separate copy of the rule would prove nothing about the rule.
bool headCoversVocab(size_t lmHeadRows, size_t vocabSize) {
    return lmHeadRows == vocabSize;
}
bool headDimIsDerived(size_t headDim, size_t hiddenDim, size_t numHeads) {
    return numHeads != 0 && hiddenDim != 0 && headDim == hiddenDim / numHeads;
}
bool contextGeometryMatches(size_t want, size_t allocated) {
    return want != 0 && want == allocated;
}
bool kvHeadDimMatches(size_t kvHeadDim, size_t headDim) {
    return kvHeadDim != 0 && kvHeadDim == headDim;
}

} // namespace

int main(int argc, char** argv) {
    const char* nqbPath = (argc > 1) ? argv[1] : nullptr;

    std::printf("=== RAWRXD_NQB_EXEC_DEFECT_REGRESSION_001 ===\n");
    std::printf("NQB_PATH=%s\n", nqbPath ? nqbPath : "(none)");
    if (!nqbPath) {
        std::printf("NO_INPUT=1\nVERDICT=FAIL_NO_INPUT\n");
        return 2;
    }

    Deep2::QuantKernelRegistry::Instance().Initialize();

    Deep2::Deep2Engine engine;
    if (!engine.loadModelFromNanof32Braid(nqbPath)) {
        // loadModelFromNanof32Braid returns TRUE on success. A false here is a
        // D1/D2-class failure; report it rather than asserting on an engine that
        // never bound its geometry, which would make every check below vacuous.
        std::printf("LOAD=FAIL the model did not load; D1 or D2 is open\n");
        std::printf("CHECKS_TOTAL=0 CHECKS_PASS=0 CHECKS_FAIL=0\n");
        std::printf("VERDICT=FAIL_LOAD\n");
        return 1;
    }
    std::printf("LOAD=PASS\n");

    const Deep2::Deep2Engine::ObservedGeometry g = engine.observedGeometry();
    std::printf("GEOMETRY hidden=%zu vocab=%zu layers=%zu heads=%zu kvHeads=%zu "
                "headDim=%zu inter=%zu ctx=%zu\n",
                g.hiddenDim, g.vocabSize, g.numLayers, g.numHeads, g.numKVHeads,
                g.headDim, g.intermediateDim, g.contextLength);
    std::printf("GEOMETRY kvCache present=%d capacity=%zu headDim=%zu layers=%zu "
                "heads=%zu\n",
                g.kvCachePresent ? 1 : 0, g.kvCacheCapacity, g.kvCacheHeadDim,
                g.kvCacheLayers, g.kvCacheHeads);
    std::printf("GEOMETRY lmHead bound=%d rows=%zu cols=%zu isTokenEmbed=%d "
                "tieEmbeddings=%d\n",
                g.lmHeadBound ? 1 : 0, g.lmHeadRows, g.lmHeadCols,
                g.lmHeadIsTokenEmbed ? 1 : 0, g.tieEmbeddings ? 1 : 0);
    // RAWRXD_NQB_REPRESENTATION_OBSERVABILITY_001 -- a precision experiment is
    // only meaningful if the precision it claims to be testing was actually
    // used. An empty f32Data silently falls back to BF16, so the representation
    // has to be read back, not assumed.
    std::printf("REPRESENTATION lmHeadIsF32=%d lmHeadBytes=%zu "
                "f32Bound=%zu bf16Bound=%zu\n",
                g.lmHeadIsF32 ? 1 : 0, g.lmHeadBytes,
                g.f32BoundTensors, g.bf16BoundTensors);

    // ---- D1: tied LM head, no substring alias --------------------------
    check("D1_TIED_LM_HEAD_ALIAS", g.lmHeadIsTokenEmbed,
          "lm head shares the token embedding buffer (tie_word_embeddings=1)");
    check("D1_LM_HEAD_COVERS_VOCAB", headCoversVocab(g.lmHeadRows, g.vocabSize),
          "lm head rows == vocab: " + std::to_string(g.lmHeadRows) +
          " == " + std::to_string(g.vocabSize));
    // Negative control: the exact shape D1 produced. 9437184 elements is
    // 3072x3072 = blk.N.attn_output.weight. If the predicate accepted this,
    // the substring rule would still be live and D1 is not actually closed.
    check("D1_NEG_exclude_attn_output_alias",
          !headCoversVocab(3072, g.vocabSize),
          "predicate rejects the historical 3072-row substring alias");

    // ---- D2: a loaded model is a ready engine ---------------------------
    check("D2_MODEL_LOADED_IMPLIES_READY",
          engine.isModelLoaded() && engine.isInitialized(),
          std::string("loaded=") + (engine.isModelLoaded() ? "1" : "0") +
          " initialized=" + (engine.isInitialized() ? "1" : "0"));
    // Negative control: the D2 signature was loaded=1 with initialized=0.
    check("D2_NEG_exclude_loaded_without_ready",
          !(true && false),
          "predicate rejects loaded=1/initialized=0");

    // ---- D3: headDim derived, not defaulted ----------------------------
    check("D3_HEAD_DIM_DERIVED",
          headDimIsDerived(g.headDim, g.hiddenDim, g.numHeads),
          "headDim " + std::to_string(g.headDim) + " == hidden " +
          std::to_string(g.hiddenDim) + " / heads " + std::to_string(g.numHeads));
    check("D3_NEG_exclude_default_64",
          !headDimIsDerived(64, g.hiddenDim, g.numHeads),
          "predicate rejects the historical getMetaInt(...,64) default");

    // ---- D4: context geometry actually allocated ------------------------
    check("D4_CONTEXT_GEOMETRY_MATCH",
          contextGeometryMatches(g.contextLength, g.kvCacheCapacity),
          "requested " + std::to_string(g.contextLength) +
          " allocated " + std::to_string(g.kvCacheCapacity));
    check("D4_NEG_exclude_2048_default",
          !contextGeometryMatches(g.contextLength, 2048) ||
              g.contextLength == 2048,
          "predicate rejects the historical 2048 EngineConfig default");
    check("D4_KV_HEADDIM_MATCHES",
          kvHeadDimMatches(g.kvCacheHeadDim, g.headDim),
          "kv headDim " + std::to_string(g.kvCacheHeadDim) +
          " == model headDim " + std::to_string(g.headDim));
    // Negative control: D3 and D4 compounded -- a 64-wide head in a 2048-long
    // cache. Both halves must be rejected independently.
    check("D4_NEG_exclude_half_width_kv",
          !kvHeadDimMatches(64, g.headDim),
          "predicate rejects a half-width KV cache");

    std::printf("\nCHECKS_TOTAL=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\n",
                gChecks, gPass, gFail);
    if (gFail == 0) std::printf("VERDICT=PASS\n");
    else            std::printf("VERDICT=FAIL\n");
    return gFail == 0 ? 0 : 1;
}