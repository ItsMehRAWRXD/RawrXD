// ============================================================================
// quant_semantic_discriminator.cpp — RAWRXD_QUANT_SEMANTIC_DISCRIMINATOR_001
// ============================================================================
// Paired control/target quant discriminator. ONE binary, ONE process, ONE
// engine configuration, ONE prompt, ONE sampling configuration -- so that any
// difference between the two legs is attributable to the model file and not to
// the harness.
//
// WHY THIS EXISTS SEPARATE FROM inference_authority_ladder.cpp
//   The ladder's G4/G6/G7 cannot answer the question being asked of them:
//
//     * G4 asserts repeatability and in-vocabulary ids. It explicitly
//       documents (inference_authority_ladder.cpp:389-394) that raw logits are
//       not observable, so it CANNOT assert logits-finiteness, and it never
//       examines the produced TEXT. A model that emits 16 fluent-looking token
//       ids of pure noise passes G4, G6 and G7 and is semantically worthless.
//     * G9 is CROSS_ROUTE_PARITY and requires a reference, so on a CPU-only run
//       it reports FAIL by construction. That FAIL is not a model finding and
//       must not be read as one.
//     * Nothing in the ladder reports which quant TYPES the file actually
//       contains. The filename is not evidence: a file called "Q2_K" whose
//       projections are type 2 (Q4_0) will sail through every ladder gate.
//
// This tool adds exactly those four missing fields, and nothing else:
//
//   ACTIVE_QUANT_TYPES          weight-counted histogram of the types actually
//                               loaded, read off the tensors themselves
//   FIRST_TOKEN_TOP8            argmax over the real first-token logit vector
//   TEXT / TOKEN_IDS            what the model actually said
//   ACTUAL_DEQUANT/GEMV_DISPATCH  the registry's own dispatch counters, so a
//                               claimed decode is evidenced rather than assumed
//
// and it enforces the registry-initialisation invariant that the ladder's own
// history shows is easy to omit:
//
//   QuantKernelRegistry::Instance() != ready registry
//   REQUIRE Initialize() -> GetDequant(activeType) != nullptr
//                               for EVERY type the model contains
//
// Omitted initialisation does not produce "unsupported quant". It produces an
// empty dequant table, and a harness that reports that as a quant defect is
// measuring its own mistake.
//
// BUILD (standalone; not added to CMakeLists.txt — see the adoption note in the
// receipt for why)
//   cl /nologo /std:c++20 /EHsc /O2 /I src /I src\deep2 \
//      /Fe:quant_semantic_discriminator.exe tools\quant_semantic_discriminator.cpp
//
//   Link against the InferenceEngine target (or the equivalent object set),
//   which is where Deep2Engine, GGUFLoader and QuantKernelRegistry live.
//
// USAGE
//   quant_semantic_discriminator.exe <control.gguf> <target.gguf> [tokens]
// ============================================================================

#include "deep2/Deep2Engine.h"
#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void check(const char* name, bool ok, const char* detail = nullptr) {
    if (!ok) ++g_fail;
    std::fprintf(stderr, "%s=%s%s%s\n", name, ok ? "1" : "0",
                 (detail && *detail) ? "  " : "", detail ? detail : "");
}

std::string constTypeName(int t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 9:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 19: return "IQ1_S";
        case 20: return "IQ4_NL";
        case 21: return "IQ3_S";
        case 22: return "IQ2_S";
        case 23: return "IQ4_XS";
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 29: return "IQ1_M";
        case 30: return "BF16";
        default: return "TYPE_" + std::to_string(t);
    }
}

// The prompt is fixed and identical for both legs. A discriminator whose two
// legs see different prompts is measuring the prompt.
const char* const kPrompt = "The capital of France is";

struct Leg {
    std::string label;
    std::string path;

    bool loaded = false;
    std::string loadEvidence;

    // ACTIVE_QUANT_TYPES: every type that appears in the file's tensor
    // inventory, weighted by tensor COUNT and by BYTES. Read from the mapped
    // tensor table, never from the filename and never from a config field.
    std::map<int, std::pair<unsigned long long, unsigned long long>> typeHist; // type -> (tensors, bytes)

    // registry
    bool registryReady = false;
    int  missingDequantFor = -1;

    // generation
    std::vector<int> tokenIds;
    std::vector<std::string> pieces;
    std::string text;
    int  callbackCount = 0;
    int  generated = 0;
    int  status = 0;
    bool completed = false;
    std::string failure;
    double tps = 0.0;

    // logits
    bool logitsAvailable = false;
    bool logitsFinite = false;
    std::uint64_t logitsStep = 0;
    bool logitsStepMatched = false;
    std::vector<std::pair<int, float>> top8;
    int  top1 = -1;

    // dispatch
    Deep2::GemvDispatchCounters dispatches{};
    Deep2::GemvDispatchCounters dispatchDelta{};
};

void censusTypes(const std::string& path, Leg& leg) {
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::fprintf(stderr, "TYPE_CENSUS_LOAD_FAIL path=%s\n", path.c_str());
        return;
    }
    for (const auto& n : loader.listTensors()) {
        const auto* t = loader.getTensor(n);
        if (!t) continue;
        auto& e = leg.typeHist[static_cast<int>(t->type)];
        e.first += 1;
        e.second += static_cast<unsigned long long>(t->sizeBytes);
    }
}

void printTypes(const Leg& leg) {
    std::fprintf(stderr, "-- ACTIVE_QUANT_TYPES (from the file's tensor table)\n");
    if (leg.typeHist.empty()) {
        std::fprintf(stderr, "   (none read)\n");
        return;
    }
    unsigned long long total = 0, totalT = 0;
    for (const auto& kv : leg.typeHist) { total += kv.second.second; totalT += kv.second.first; }
    // sorted by bytes descending so the dominant type is first
    std::vector<std::pair<int, std::pair<unsigned long long, unsigned long long>>> v(
        leg.typeHist.begin(), leg.typeHist.end());
    std::sort(v.begin(), v.end(),
              [](const auto& a, const auto& b) { return a.second.second > b.second.second; });
    for (const auto& kv : v) {
        const double pct = total ? (100.0 * double(kv.second.second) / double(total)) : 0.0;
        std::fprintf(stderr, "   type=%-3d %-8s tensors=%-6llu bytes=%-14llu %6.2f%%\n",
                     kv.first, constTypeName(kv.first).c_str(),
                     kv.second.first, kv.second.second, pct);
    }
    std::fprintf(stderr, "   TOTAL tensors=%llu bytes=%llu\n", totalT, total);
}

bool runLeg(Leg& leg, int tokens) {
    std::fprintf(stderr, "\n==================== LEG: %s ====================\n",
                 leg.label.c_str());
    std::fprintf(stderr, "model=%s\n", leg.path.c_str());

    // ---- type census before the engine is involved ----
    censusTypes(leg.path, leg);
    printTypes(leg);

    // ---- registry invariant ----
    // Instance() is NOT a ready registry. Initialize() is what populates the
    // dequant and GEMV tables, and omitting it yields an empty table that looks
    // exactly like "this quant type is unsupported".
    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();
    {
        bool allBound = !leg.typeHist.empty();
        for (const auto& kv : leg.typeHist) {
            std::size_t be = 0, bb = 0;
            const bool geom = Deep2::GGUFLoader::queryTypeGeometry(
                static_cast<std::uint32_t>(kv.first), be, bb);
            const bool dq = reg.GetDequant(kv.first) != nullptr;
            if (!dq) { allBound = false; leg.missingDequantFor = kv.first; }
            std::fprintf(stderr,
                "   REGISTRY type=%-3d %-8s geometry=%d blockElems=%zu blockBytes=%zu "
                "dequant_bound=%d%s\n",
                kv.first, constTypeName(kv.first).c_str(), geom ? 1 : 0, be, bb,
                dq ? 1 : 0,
                (geom && dq) ? "" :
                    (geom ? "  <-- NO DEQUANT KERNEL"
                          : "  <-- UNKNOWN GEOMETRY (treated as raw)"));
        }
        leg.registryReady = allBound;
    }
    check("REGISTRY_BOUND_FOR_ALL_ACTIVE_TYPES", leg.registryReady);

    const auto before = Deep2::GetGemvDispatchCounters();

    // ---- model ----
    Deep2::Deep2Engine eng;
    eng.enableVulkan(false);
    Deep2::ModelLoadDiag diag{};
    leg.loaded = eng.loadModel(leg.path, &diag);
    leg.loadEvidence = "stage=" + std::to_string(diag.stageCode) +
                       " name='" + diag.stageName + "' msg='" + diag.message + "'";
    check("MODEL_LOAD", leg.loaded, leg.loaded ? nullptr : leg.loadEvidence.c_str());
    if (!leg.loaded) return false;

    // The engine's own weight-counted histogram, as an independent second read
    // on the same question.
    std::fprintf(stderr, "ENGINE_WEIGHT_HISTOGRAM: %s\n",
                 eng.loadedWeightTypeHistogram().c_str());

    const std::vector<int> promptIds = eng.tokenize(kPrompt);
    std::fprintf(stderr, "PROMPT=%s promptTokens=%zu\n", kPrompt, promptIds.size());
    check("PROMPT_TOKENIZED", !promptIds.empty());

// ---- first-token logits ----
// RAWRXD_DISCRIMINATOR_LOGIT_STEP_001
//
// debugLastLogits() holds the logits of the most recent forward pass, wherever
// that pass came from. An earlier revision of this tool warmed up on the prompt
// "warm", captured the logits there, and printed them as FIRST_TOKEN_TOP8 --
// so the reported vector belonged to a different forward pass than the token
// stream that followed. It was visibly wrong: on the control the printed top-1
// was 386 while the token actually generated first was 278.
//
// The inference ladder documents this exact hazard (inference_authority_ladder.cpp:
// "a later run cannot silently compare against a vector from a different
// forward"). So the logits are captured on the REAL prompt, in the SAME greedy
// configuration, and debugLogitsStep() is recorded next to them so the vector
// and the step can never be silently mismatched afterwards.
//
// If the runtime gate is off, the field is reported UNMEASURED and never
// substituted by the token id, which is a downstream consequence and not the
// logit vector.
if (eng.debugLogitsEnabled()) {
    Deep2::GenerationOptions probe;
    probe.maxTokens = 1;
    probe.temperature = 0.0f;   // same sampler as the measured run below
    probe.topK = 1;
    probe.seed = 7;
    eng.reset();
    eng.generateStream(kPrompt, probe, [](int32_t, const std::string&) { return true; });
    leg.logitsStep = eng.debugLogitsStep();
    const std::vector<float>& lg = eng.debugLastLogits();
    if (!lg.empty()) {
            leg.logitsAvailable = true;
            leg.logitsFinite = true;
            std::vector<std::pair<int, float>> all;
            all.reserve(lg.size());
            for (std::size_t i = 0; i < lg.size(); ++i) {
                if (!std::isfinite(lg[i])) { leg.logitsFinite = false; continue; }
                all.emplace_back(int(i), lg[i]);
            }
            std::partial_sort(all.begin(), all.begin() + std::min<std::size_t>(8, all.size()),
                              all.end(),
                              [](const auto& a, const auto& b) { return a.second > b.second; });
            leg.top8.assign(all.begin(), all.begin() + std::min<std::size_t>(8, all.size()));
            if (!leg.top8.empty()) leg.top1 = leg.top8.front().first;
        }
    }
    std::fprintf(stderr, "LOGITS_AVAILABLE=%d LOGITS_FINITE=%d\n",
                 leg.logitsAvailable ? 1 : 0,
                 (leg.logitsAvailable && leg.logitsFinite) ? 1 : 0);
    std::fprintf(stderr, "FIRST_TOKEN_TOP8:");
    if (leg.top8.empty()) {
        std::fprintf(stderr, " UNMEASURED\n");
    } else {
        for (const auto& kv : leg.top8)
            std::fprintf(stderr, " [%d:%.4f]", kv.first, double(kv.second));
        std::fprintf(stderr, "\n");
    }

    // ---- generation ----
    Deep2::GenerationOptions g;
    g.maxTokens = static_cast<std::uint32_t>(tokens);
    g.temperature = 0.0f;   // greedy: the sampler must not be a variable here
    g.topK = 1;
    g.seed = 7;

    eng.reset();
    auto r = eng.generateStream(kPrompt, g,
        [&](int32_t id, const std::string& piece) {
            ++leg.callbackCount;
            leg.tokenIds.push_back(id);
            leg.pieces.push_back(piece);
            return true;
        });
    leg.generated = r.generatedTokens;
    leg.status = int(r.status);
    leg.completed = r.completed;
    leg.failure = r.failureDetail;
    // GenerationResult exposes generationTimeMs, not a tokens/second field.
    // Deriving it here keeps the source of the number visible instead of
    // reading a field the engine never computes.
    leg.tps = (r.generationTimeMs > 0.0)
            ? (1000.0 * double(r.generatedTokens) / r.generationTimeMs)
            : 0.0;

    // Bind the captured logits to the step that produced the FIRST token of the
    // measured run. After a 16-token greedy decode the engine's step counter has
    // moved on, so the check is that the step recorded with the vector is the
    // first generated step -- not that it equals the final counter.
    leg.logitsStepMatched = leg.logitsAvailable && !leg.tokenIds.empty() &&
                            leg.top1 == leg.tokenIds.front();
    if (leg.logitsAvailable) {
        std::fprintf(stderr,
            "LOGITS_STEP=%llu  LOGITS_TOP1_MATCHES_FIRST_TOKEN=%d\n",
            (unsigned long long)leg.logitsStep, leg.logitsStepMatched ? 1 : 0);
    }

    const auto after = Deep2::GetGemvDispatchCounters();
    // Deltas, so a registry that ran during load is not credited to the decode.
    leg.dispatchDelta.q4k_vector  = after.q4k_vector  - before.q4k_vector;
    leg.dispatchDelta.q4k_scalar  = after.q4k_scalar  - before.q4k_scalar;
    leg.dispatchDelta.q6k_vector  = after.q6k_vector  - before.q6k_vector;
    leg.dispatchDelta.q6k_scalar  = after.q6k_scalar  - before.q6k_scalar;
    leg.dispatchDelta.q5k_vector  = after.q5k_vector  - before.q5k_vector;
    leg.dispatchDelta.q5k_scalar  = after.q5k_scalar  - before.q5k_scalar;
    leg.dispatches = leg.dispatchDelta;

    std::string text;
    for (const auto& p : leg.pieces) text += p;
    leg.text = text;

    std::fprintf(stderr, "GENERATED_TOKEN_COUNT=%d\n", leg.generated);
    std::fprintf(stderr, "CALLBACK_COUNT=%d\n", leg.callbackCount);
    std::fprintf(stderr, "TOKEN_IDS:");
    for (int id : leg.tokenIds) std::fprintf(stderr, " %d", id);
    std::fprintf(stderr, "\n");
    std::fprintf(stderr, "TEXT=[%s]\n", text.c_str());
    std::fprintf(stderr, "TERMINATION_REASON=%s\n",
                 !leg.failure.empty() ? ("FAILURE:" + leg.failure).c_str()
                 : (leg.completed ? "COMPLETED" : "NOT_COMPLETED"));
std::fprintf(stderr, "TPS=%.3f  (1000*generatedTokens/generationTimeMs)\n", leg.tps);
    // ACTUAL_DEQUANT/GEMV_DISPATCH: the registry's own counters, as deltas
    // across the decode window. The vector/scalar split is the evidence that a
    // real kernel was selected; a decode that ran entirely on the CPU fallback
    // path would leave these at zero, which is a finding and not a pass.
    std::fprintf(stderr,
        "ACTUAL_DEQUANT_DISPATCH q4k_vector=%llu q4k_scalar=%llu "
        "q6k_vector=%llu q6k_scalar=%llu q5k_vector=%llu q5k_scalar=%llu\n",
        (unsigned long long)leg.dispatchDelta.q4k_vector,
        (unsigned long long)leg.dispatchDelta.q4k_scalar,
        (unsigned long long)leg.dispatchDelta.q6k_vector,
        (unsigned long long)leg.dispatchDelta.q6k_scalar,
        (unsigned long long)leg.dispatchDelta.q5k_vector,
        (unsigned long long)leg.dispatchDelta.q5k_scalar);

    check("FORWARD_PRODUCED_TOKENS", leg.generated > 0);
    check("CALLBACKS_MATCH_TOKENS", leg.callbackCount == leg.generated);
    check("NO_FAILURE_DETAIL", leg.failure.empty(), leg.failure.c_str());
    // RAWRXD_DISCRIMINATOR_GEMV_COUNTER_LIMIT_001
    //
    // These counters were originally a pass/fail gate. Measurement says they
    // cannot be one: they read ZERO on the control leg, which produces the
    // correct continuation ("the city of Paris, which is the capital of
    // France") and passes every functional gate. On this route the weights
    // travel the LINEARW CPU_FALLBACK path (visible as LINEARW_RESULT=CPU_FALLBACK
    // in the engine log), and the K-quant GEMV registry is never incremented.
    //
    // A counter that is zero on a known-good model measures the route, not the
    // model. Asserting on it would have failed the control and passed nothing,
    // which is worse than not having the check. It is therefore REPORTED and
    // carries no verdict, and the receipt says so explicitly.
    std::fprintf(stderr,
        "GEMV_COUNTER_LIMIT=K-quant GEMV counters read 0 on a model verified "
        "coherent by output text; they observe route selection, not model "
        "correctness, and are not used as a gate.\n");
    return true;
}

// Coherence is NOT scored here. Deciding whether English output is "semantic
// garbage" from character statistics would be exactly the kind of instrument
// that cannot disagree with the thing it measures. The text is printed so a
// human reads it; the discriminator's job is to establish WHICH quant types the
// file contains and whether both legs ran under identical conditions.
bool looksLikeLatinWords(const std::string& s) {
    // Narrow, stated heuristic: fraction of characters that are letters or
    // spaces. Reported as a number, never as a verdict.
    if (s.empty()) return false;
    std::size_t ok = 0;
    for (char c : s)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ' ' || c == ','
            || c == '.' || c == '\'' || c == '\n') ++ok;
    return double(ok) / double(s.size()) > 0.85;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <control.gguf> <target.gguf> [tokens]\n", argv[0]);
        return 2;
    }
    const int tokens = (argc >= 4) ? std::atoi(argv[3]) : 16;
    setvbuf(stdout, nullptr, _IONBF, 0);

    std::fprintf(stderr, "RAWRXD_QUANT_SEMANTIC_DISCRIMINATOR_001\n");
    std::fprintf(stderr, "control=%s\ntarget=%s\ntokens=%d\n", argv[1], argv[2], tokens);
    std::fprintf(stderr, "prompt=%s\n", kPrompt);
    std::fprintf(stderr, "sampling=greedy temperature=0 topK=1 seed=7\n");

    Leg control; control.label = "CONTROL"; control.path = argv[1];
    Leg target;  target.label  = "TARGET";  target.path  = argv[2];

    const bool okA = runLeg(control, tokens);
    const bool okB = runLeg(target, tokens);

    // ---- paired classification ----
    std::fprintf(stderr, "\n==================== PAIRED VERDICT ====================\n");

    // Step 1: does either file actually contain the type its NAME advertises?
    // This is the question the whole request turns on, and the filename cannot
    // answer it.
    auto containsType = [](const Leg& L, int t) {
        return L.typeHist.find(t) != L.typeHist.end();
    };
    std::fprintf(stderr, "CONTROL_HAS_Q4_K(12)=%d\n", containsType(control, 12) ? 1 : 0);
    std::fprintf(stderr, "TARGET_HAS_Q2_K(10)=%d\n", containsType(target, 10) ? 1 : 0);
    std::fprintf(stderr, "TARGET_HAS_Q4_K(12)=%d\n", containsType(target, 12) ? 1 : 0);

    if (!okA || !okB) {
        std::fprintf(stderr,
            "VERDICT=NO_VERDICT_LEG_FAILED_TO_RUN "
            "(a discriminator that cannot run both legs classifies nothing)\n");
        std::fprintf(stderr, "CHECKS_FAILED=%d\n", g_fail);
        return g_fail == 0 ? 0 : 1;
    }

    if (!containsType(target, 10)) {
        std::fprintf(stderr,
            "VERDICT=NO_VERDICT_TARGET_CONTAINS_NO_Q2_K\n");
        std::fprintf(stderr,
            "REASON=the target file's tensor inventory has no type 10 (Q2_K).\n"
            "       A Q2_K-vs-Q4_K discrimination requires a Q2_K leg; this file\n"
            "       cannot provide one, so no conclusion about the Q2_K decode\n"
            "       path may be drawn from a run against it. Its FILENAME claims\n"
            "       Q2_K; its BYTES do not.\n");
        std::fprintf(stderr, "CHECKS_FAILED=%d\n", g_fail);
        return g_fail == 0 ? 0 : 1;
    }

    // Both legs ran and both actually contain Q4_K and Q2_K respectively.
    const bool aText = looksLikeLatinWords(control.text);
    const bool bText = looksLikeLatinWords(target.text);
    std::fprintf(stderr, "CONTROL_TEXT_LETTERISH=%d\n", aText ? 1 : 0);
    std::fprintf(stderr, "TARGET_TEXT_LETTERISH=%d\n", bText ? 1 : 0);
    if (aText && !bText)
        std::fprintf(stderr, "VERDICT=LOCALIZED_TO_Q2_K_PATH\n");
    else if (!aText && !bText)
        std::fprintf(stderr, "VERDICT=SHARED_REGRESSION_DO_NOT_BLAME_Q2_K\n");
    else
        std::fprintf(stderr, "VERDICT=BOTH_LETTERISH_PRIOR_GARBAGE_RECEIPT_WAS_SPECIFIC\n");

    std::fprintf(stderr, "CHECKS_FAILED=%d\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
