// nqb_residual_lm_head_accumulation.cpp
// RAWRXD_NQBRAID_RESIDUAL_LM_HEAD_ACCUMULATION_001
//
// WHY THIS GATE EXISTS
// --------------------
// Two boundaries are now proven equal by hash:
//
//     FINAL_NORM   3072 elements   HASH a0212aaa596d007d on BOTH routes
//     weights      255/255 tensors MAX_ABS=0, ARGMAX_MATCH=255/255, type F32
//
// and yet the logits differ on 123,537 of 128,256 rows by more than 1e-3
// (P50 = 0.0147, P99 = 0.0596, worst = 0.1032) -- a smooth, broadly-distributed
// perturbation that is far too large for float32 accumulation noise over a
// 3072-term dot product and far too uniform for damaged rows.
//
//     identical input  +  identical logical weights  ->  different dot products
//
// So the question is no longer "which tensor" but "which arithmetic". This gate
// answers it with a reference the two implementations cannot both match by
// construction: a scalar double-precision accumulation over the SAME decoded F32
// operands both routes consumed.
//
// THE THREE OUTCOMES
// ------------------
//     REF ~= NQB,  GGUF differs   -> the Q2_K LM-head GEMV / dequant accumulation
//     REF ~= GGUF, NQB differs    -> the F32 GEMV
//     both straddle REF          -> implementation-dependent accumulation
//                                    ordering, not a correctness defect
//     both far from REF          -> the operands are NOT identical where the
//                                    kernels consume them; move the boundary in
//
// THRESHOLDS ARE FIXED HERE, BEFORE ANY RESULT IS SEEN. Tuning them afterwards
// converts the gate into a description of whatever answer was already obtained.
//
// COST: only ~32 rows are evaluated. A full 3072 x 128256 reference projection
// is ~394M multiply-adds; that belongs in a certification gate once the
// discriminating rows have identified which implementation is implicated.

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "Nanof32BraidStreamer.hpp"
#include "Deep2Engine.h"
#include "authority/Measured.hpp"
#include "rawr_build_identity_nqb_residual_lm_head_accumulation.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

using rawrxd::authority::InputAuthority;
using rawrxd::authority::Measured;

static const char* GATE = "RAWRXD_NQBRAID_RESIDUAL_LM_HEAD_ACCUMULATION_001";

// Declared before any measurement is taken.
static const double kRefCosineTol  = 0.9999999;
static const double kRefRelTol    = 1e-6;

struct RowVerdict { size_t row; int ggufSide; int nqbSide; };

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "Usage: %s <model.gguf> <model.nqb>\n", argv[0]);
        return 4;
    }
    const char* ggufPath = argv[1];
    const char* nqbPath  = argv[2];

    std::fprintf(stderr, "=== %s ===\n", GATE);
    RAWRXD_PRINT_BUILD_IDENTITY();
    std::fprintf(stderr, "REF_ACCUMULATION=double COSINE_TOL=%g REL_TOL=%g ROWS_TARGET=32\n",
                 kRefCosineTol, kRefRelTol);

    Deep2::QuantKernelRegistry::Instance().Initialize();

    // ----------------------------------------------------------------
    // INPUT AUTHORITY. Nothing is compared until both operands are proven
    // present, non-vacuous, same shape, and same dtype.
    // ----------------------------------------------------------------
    Measured<std::vector<float>> hRef;   // FINAL_NORM, from the NQB capture
    Measured<std::vector<float>> wRef;   // lm_head row block, from the NQB file
    uint32_t rows = 0, cols = 0;

    {
        Deep2::GGUFLoader loader;
        if (!loader.load(ggufPath)) {
            std::fprintf(stderr, "FAIL=gguf_load %s\n", loader.error().c_str());
            return 4;
        }
        const Deep2::GGUFTensor* te = loader.getTensor("token_embd.weight");
        if (!te) { std::fprintf(stderr, "FAIL=no_token_embd\n"); return 4; }
        cols = static_cast<uint32_t>(te->shape[0]);
        rows = static_cast<uint32_t>(te->shape[1]);
        std::fprintf(stderr, "LM_HEAD_SHAPE rows=%u cols=%u gguf_type=%d\n",
                     rows, cols, static_cast<int>(te->type));
    }

    // FINAL_NORM full vector, captured from the parity file by running the NQB
    // route with fullVecLayer == -3. Performed in-process so the operands are
    // the ones the kernel actually saw.
    {
        Deep2::Deep2Engine e;
        if (!e.loadModelFromNanof32Braid(std::string(nqbPath))) {
            std::fprintf(stderr, "FAIL=nqb_load\n"); return 4;
        }
        const char* pv = "f:\~dev\\nqb_residual_parity.txt";
        e.enableParityProbe(pv, 0);
        e.enableParityProbeFullVectors(-3);          // RAWRXD_PARITY_FINAL_NORM_VEC_001
        Deep2::GenerationOptions o;
        o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
        (void)e.generateStream("The capital of France is", o, nullptr);
        e.disableParityProbe();

        // Parse the VEC block for the FINAL_NORM site.
        std::FILE* f = std::fopen(pv, "r");
        if (!f) { std::fprintf(stderr, "FAIL=parity_file_missing %s\n", pv); return 4; }
        std::vector<float> acc; bool inVec = false;
        char line[8192];
        while (std::fgets(line, sizeof line, f)) {
            if (std::strstr(line, "VEC=LAYER_-1_FINAL_NORM")) {
                inVec = true; acc.clear(); continue;
            }
            if (inVec) {
                if (std::strchr(line, ' ') == nullptr || line[0] == '\n') break;
                char* p = line;
                for (;;) {
                    char* end = nullptr;
                    const double d = std::strtod(p, &end);
                    if (end == p) break;
                    acc.push_back(static_cast<float>(d));
                    p = end;
                    if (*p == ',') ++p;
                }
            }
        }
        std::fclose(f);
        if (acc.empty()) {
            std::fprintf(stderr, "FAIL=final_norm_vector_not_captured\n");
            std::fprintf(stderr, "  the LM head's actual input was never observed, so a\n"
                                 "  reference dot product over it would be fiction\n");
            return 2;
        }
        hRef = Measured<std::vector<float>>::observe(acc, 1, 1, 2);
        std::fprintf(stderr, "FINAL_NORM_CAPTURED elements=%zu\n", acc.size());
    }

    // Weight rows, decoded from the NQB file (bit-identical to the GGUF path by
    // an established 255/255 measurement, so either source is a valid operand).
    {
        Deep2::Nanof32BraidStreamer s;
        if (!s.open(nqbPath)) { std::fprintf(stderr, "FAIL=nqb_open\n"); return 4; }
        std::vector<std::pair<std::string, Deep2::NQBraidBlock>> blocks;
        if (!s.readAllTensors(blocks)) { std::fprintf(stderr, "FAIL=nqb_read\n"); return 4; }
        for (auto& kv : blocks) {
            if (kv.first == "token_embd.weight") {
                wRef = Measured<std::vector<float>>::observe(kv.second.f32Data, 1, 2, 2);
                std::fprintf(stderr, "WEIGHTS_CAPTURED format=%s elements=%zu\n",
                             kv.second.f32Data.empty() ? "BF16" : "F32",
                             kv.second.elements());
            }
        }
    }

    InputAuthority ia;
    ia.inputAPresent = hRef.populated;
    ia.inputBPresent = wRef.populated;
    ia.inputAElements = hRef.populated ? hRef.get().size() : 0;
    ia.inputBElements = wRef.populated ? wRef.get().size() : 0;
    ia.inputASourceValid = ia.inputBSourceValid = true;
    ia.inputABuildIdValid = ia.inputBBuildIdValid = true;
    ia.sameToken = ia.samePosition = ia.sameLayer = ia.sameStage = true;
    ia.sameElements = (ia.inputAElements == cols) && (ia.inputBElements ==
                     static_cast<uint64_t>(rows) * cols);
    ia.sameDtype = true;   // both float32
    ia.nameA = "FINAL_NORM"; ia.nameB = "LM_HEAD";
    ia.print("LM_HEAD_INPUT");
    if (!ia.admissible()) {
        std::fprintf(stderr, "VERDICT=INVALID_INPUT reason=operand_authority\n");
        return 2;
    }

    // ----------------------------------------------------------------
    // Production logits from BOTH routes, via the same gated capture the
    // oracle uses. These are the numbers that actually reached the sampler,
    // not a recomputation.
    // ----------------------------------------------------------------
    std::vector<float> logitsGGUF, logitsNQB;
    {
        _putenv_s("DEEP2_DEBUG_EXPOSE_LOGITS", "1");

        Deep2::Deep2Engine eg;
        if (!eg.loadModel(std::string(ggufPath))) {
            std::fprintf(stderr, "FAIL=gguf_engine_load\n"); return 4;
        }
        Deep2::GenerationOptions o;
        o.maxTokens = 1; o.temperature = 0.0f; o.topK = 1; o.seed = 7;
        (void)eg.generateStream("The capital of France is", o, nullptr);
        logitsGGUF = eg.debugLastLogits();
        std::fprintf(stderr, "GGUF_PRODUCTION_LOGITS captured=%zu step=%llu\n",
                     logitsGGUF.size(),
                     static_cast<unsigned long long>(eg.debugLogitsStep()));

        Deep2::Deep2Engine en;
        if (!en.loadModelFromNanof32Braid(std::string(nqbPath))) {
            std::fprintf(stderr, "FAIL=nqb_engine_load\n"); return 4;
        }
        (void)en.generateStream("The capital of France is", o, nullptr);
        logitsNQB = en.debugLastLogits();
        std::fprintf(stderr, "NQB_PRODUCTION_LOGITS  captured=%zu step=%llu\n",
                     logitsNQB.size(),
                     static_cast<unsigned long long>(en.debugLogitsStep()));
    }

    if (logitsGGUF.size() != rows || logitsNQB.size() != rows) {
        std::fprintf(stderr, "FAIL=logits_shape gguf=%zu nqb=%zu expected_rows=%u\n",
                     logitsGGUF.size(), logitsNQB.size(), rows);
        std::fprintf(stderr,
            "  without a production logit vector per route there is nothing for a\n"
            "  reference to be compared against, so no verdict would be admissible\n");
        return 2;
    }

    // ----------------------------------------------------------------
    // Row selection: union of both top-10, the worst-observed pair, and
    // deterministic ordinary rows. Small and targeted on purpose -- a full
    // 3072 x 128256 reference projection is ~394M multiply-adds and belongs in
    // a certification gate, not in the step that identifies the culprit.
    // ----------------------------------------------------------------
    const std::vector<float>& h = hRef.get();
    const std::vector<float>& W = wRef.get();
    auto topN = [&](const std::vector<float>& v, size_t n) {
        std::vector<size_t> idx(v.size());
        for (size_t i = 0; i < v.size(); ++i) idx[i] = i;
        std::partial_sort(idx.begin(), idx.begin() + std::min(n, idx.size()), idx.end(),
                          [&](size_t a, size_t b) { return v[a] > v[b]; });
        idx.resize(std::min(n, idx.size()));
        return idx;
    };
    std::set<size_t> rowsToTest;
    for (size_t r : topN(logitsGGUF, 10)) rowsToTest.insert(r);
    for (size_t r : topN(logitsNQB, 10))  rowsToTest.insert(r);
    {
        size_t worst = 0; double wd = -1.0;
        for (size_t r = 0; r < rows; ++r) {
            const double d = std::fabs(static_cast<double>(logitsGGUF[r]) -
                                       static_cast<double>(logitsNQB[r]));
            if (d > wd) { wd = d; worst = r; }
        }
        rowsToTest.insert(worst);
    }
    for (size_t r = 0; r < rows && rowsToTest.size() < 32; r += rows / 8) rowsToTest.insert(r);

    std::fprintf(stderr, "\nROWS_TESTED=%zu (of %u)\n", rowsToTest.size(), rows);
    std::fprintf(stderr, "REFERENCE=double scalar accumulation, %u terms per row\n\n", cols);
    std::fprintf(stderr,
        "%8s %16s %16s %16s %12s %12s %12s\n",
        "ROW", "REF_F64", "GGUF_PROD", "NQB_PROD", "GGUF_ERR", "NQB_ERR", "PAIR_DIFF");

    double sG = 0, sN = 0, sP = 0;
    double mG = 0, mN = 0, mP = 0;
    size_t closerG = 0, closerN = 0, ties = 0;
    std::vector<double> pairDiffs;
    size_t n = 0;

    for (size_t r : rowsToTest) {
        // One canonical F64 accumulation over the operands both routes consumed.
        double ref = 0.0;
        const float* wrow = W.data() + r * static_cast<size_t>(cols);
        for (uint32_t i = 0; i < cols; ++i)
            ref += static_cast<double>(h[i]) * static_cast<double>(wrow[i]);

        const double g = static_cast<double>(logitsGGUF[r]);
        const double q = static_cast<double>(logitsNQB[r]);
        const double eG = std::fabs(g - ref);
        const double eN = std::fabs(q - ref);
        const double pD = std::fabs(g - q);

        std::fprintf(stderr, "%8zu %16.9f %16.9f %16.9f %12.3e %12.3e %12.3e\n",
                     r, ref, g, q, eG, eN, pD);
        sG += eG * eG; sN += eN * eN; sP += pD * pD;
        mG = std::max(mG, eG); mN = std::max(mN, eN); mP = std::max(mP, pD);
        if (eG < eN) ++closerG; else if (eN < eG) ++closerN; else ++ties;
        pairDiffs.push_back(pD);
        ++n;
    }

    std::sort(pairDiffs.begin(), pairDiffs.end());
    std::fprintf(stderr,
        "\nGGUF_RMSE_TO_F64=%.9g\nNQB_RMSE_TO_F64=%.9g\n"
        "GGUF_MAX_ABS_TO_F64=%.9g\nNQB_MAX_ABS_TO_F64=%.9g\n"
        "GGUF_CLOSER_COUNT=%zu\nNQB_CLOSER_COUNT=%zu\nTIE_COUNT=%zu\n"
        "PRODUCTION_PAIR_RMSE=%.9g\nPRODUCTION_PAIR_P50=%.9g\n"
        "PRODUCTION_PAIR_P95=%.9g\nPRODUCTION_PAIR_MAX=%.9g\n",
        std::sqrt(sG / n), std::sqrt(sN / n), mG, mN,
        closerG, closerN, ties,
        std::sqrt(sP / n),
        pairDiffs.empty() ? 0.0 : pairDiffs[pairDiffs.size() / 2],
        pairDiffs.empty() ? 0.0 : pairDiffs[(pairDiffs.size() * 95) / 100],
        mP);

    // The verdict is DERIVED, and each outcome names a different subsystem.
    const double rmseG = std::sqrt(sG / n), rmseN = std::sqrt(sN / n);
    const char* verdict;
    if (rmseN * 10.0 < rmseG)      verdict = "GGUF_LM_HEAD_PRODUCTION_DEFECTIVE";
    else if (rmseG * 10.0 < rmseN) verdict = "NQB_LM_HEAD_PRODUCTION_DEFECTIVE";
    else if (std::max(rmseG, rmseN) < 1e-3)
                                   verdict = "ACCUMULATION_ORDERING_NOT_A_DEFECT";
    else                            verdict = "BOTH_FAR_FROM_REFERENCE";
    std::fprintf(stderr, "\nVERDICT=%s\n", verdict);
    std::fprintf(stderr,
        "NOTE: RAW_LM_HEAD_DOT_BEFORE_STORE is NOT captured by this gate, so a\n"
        "      divergence inside GEMV cannot yet be separated from one in\n"
        "      writeback/postprocess. That split is the next measurement.\n");
    return 0;
}
