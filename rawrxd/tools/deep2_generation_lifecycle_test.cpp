// deep2_generation_lifecycle_test.cpp
// RAWRXD_DEEP2_GENERATION_LIFECYCLE_001
//
// Regression driver for the generation-lifecycle contract on ONE engine
// instance. Everything printed here is measured: values come from the engine's
// own GenerationResult, from Deep2Engine::kvCacheLength(), or from counting
// callback invocations. No field is predicted, defaulted, or asserted from a
// literal.
//
// The driver deliberately uses ONLY the API surface that already existed
// before the repair (status, completed, cancelled, generatedTokens,
// failureDetail, kvCacheLength, callback pieces). That keeps the pre-fix and
// post-fix runs comparable: same driver, same measurements, different engine.
//
//   Phase A  LOAD              one model load, one engine instance
//   Phase B  REPEATED          N independent generations, fresh prompt each,
//                             engine NOT reconstructed between them
//   Phase C  CONTRACT          per-generation result-contract invariants
//   Phase D  TERMINATION       one generation with a large token ceiling,
//                             to observe whether the engine can stop on its
//                             own or only by exhausting the ceiling
//
// usage:
//   deep2_generation_lifecycle_test <model.gguf>
//       [--generations N] [--max-tokens M] [--eos-max-tokens E]
//       [--prompt-repeats R]

#include "deep2/Deep2Engine.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

namespace {

struct Observation {
    int         index       = 0;
    uint64_t    promptTokens = 0;
    uint64_t    kvBefore    = 0;
    uint64_t    kvAfter     = 0;
    uint64_t    generatedTokens = 0;   // engine-reported sampled tokens
    uint64_t    callbackInvocations = 0;
    uint64_t    callbackEmptyPieces = 0;
    bool        completed   = false;
    bool        cancelled   = false;
    Deep2::GenerationStatus status = Deep2::GenerationStatus::InternalError;
    std::string failureDetail;
    double      wallMs      = 0.0;
    std::string text;
    // Sampled token ids, in emission order. Distinguishes a decode defect from
    // a model that genuinely emitted an unusual token.
    std::vector<int32_t> tokenIds;
};

const char* statusName(Deep2::GenerationStatus s) {
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence:  return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:      return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        case Deep2::GenerationStatus::InternalError:  return "InternalError";
    }
    return "Unknown";
}

// Fresh, distinct prompt per generation. Each is a plain instruction with no
// shared prefix so a carry-over cannot be explained by prompt similarity.
std::string promptFor(int index) {
    switch (index % 4) {
        case 0: return "Name exactly three primary colors, separated by commas.";
        case 1: return "In one sentence, what is the capital of France?";
        case 2: return "Reply with the single word: ready";
        default: return "List two uses for a paperclip.";
    }
}

Observation runOne(Deep2::Deep2Engine& engine, const std::string& prompt,
                   uint32_t maxTokens, int index, bool eosProbe = false) {
    Observation o;
    o.index   = index;
    o.kvBefore = engine.kvCacheLength();

    Deep2::GenerationOptions opts{};
    opts.maxTokens   = maxTokens;
    opts.temperature = 0.0f;   // greedy: a repeat run must produce the same text
    opts.topK        = 1;
    opts.topP        = 1.0f;
    opts.seed        = 7;
    if (eosProbe) {
        // The termination probe needs the model to be able to FINISH an answer.
        //
        // Greedy decoding with no repetition penalty on a small quantised model
        // is a repetition loop: llama3.2-3b-Q2_K emitted token 7051 ("irit")
        // 64 times in a row and never reached EOS, so a greedy probe can only
        // ever report "hit the ceiling" and proves nothing about EOS. A seeded
        // sample with a repetition penalty is still deterministic — same seed,
        // same tokens — and lets the model terminate.
        opts.temperature = 0.7f;
        opts.topK        = 40;
        opts.topP        = 0.95f;
        opts.repeatPenalty = 1.15f;
        opts.seed        = 7;
    }

    const auto t0 = std::chrono::steady_clock::now();
    std::fprintf(stderr, "ROOT:A_PRE_GENERATE idx=%d\n", index); std::fflush(stderr);
    const Deep2::GenerationResult r = engine.generateStream(
        prompt, opts,
        [&](int32_t tok, const std::string& piece) -> bool {
            ++o.callbackInvocations;
            if (piece.empty()) ++o.callbackEmptyPieces;
            // Record the sampled id alongside the decoded piece. Without this
            // a decoded observation cannot distinguish "the model emitted a
            // newline token" from "the decoder mapped every token to one", and
            // a decode defect is indistinguishable from degenerate output.
            o.tokenIds.push_back(static_cast<int32_t>(tok));
            o.text += piece;
            return true;
        });
    o.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    std::fprintf(stderr, "ROOT:B_POST_GENERATE idx=%d\n", index); std::fflush(stderr);
    o.promptTokens    = r.promptTokens;
    std::fprintf(stderr, "ROOT:C_COPY_PROMPT idx=%d\n", index); std::fflush(stderr);
    o.generatedTokens = r.generatedTokens;
    std::fprintf(stderr, "ROOT:D_COPY_RESULT idx=%d\n", index); std::fflush(stderr);
    o.completed       = r.completed;
    o.cancelled       = r.cancelled;
    o.status          = r.status;
    o.failureDetail   = r.failureDetail;
    o.kvAfter         = engine.kvCacheLength();
    std::fprintf(stderr, "ROOT:E_POST_KV idx=%d\n", index); std::fflush(stderr);
    std::fprintf(stderr, "ROOT:F_PRE_RETURN idx=%d\n", index); std::fflush(stderr);
    return o;
}

void printObservation(const char* phase, const Observation& o, uint32_t maxTokens) {
    std::printf("%s[%d] promptTokens=%llu kvBefore=%llu kvAfter=%llu "
                "status=%s completed=%d cancelled=%d generatedTokens=%llu "
                "callbackInvocations=%llu callbackEmptyPieces=%llu wallMs=%.0f\n",
        phase, o.index,
        (unsigned long long)o.promptTokens,
        (unsigned long long)o.kvBefore,
        (unsigned long long)o.kvAfter,
        statusName(o.status),
        o.completed ? 1 : 0,
        o.cancelled ? 1 : 0,
        (unsigned long long)o.generatedTokens,
        (unsigned long long)o.callbackInvocations,
        (unsigned long long)o.callbackEmptyPieces,
        o.wallMs);
    std::printf("%s[%d] maxTokens=%u failureDetail=%s\n",
        phase, o.index, maxTokens,
        o.failureDetail.empty() ? "(empty)" : o.failureDetail.c_str());
    // Sampled ids, and the decoded piece rendered with escapes. A raw "%s" of
    // control characters is invisible in a log, which is how a generation that
    // emitted only carriage returns read as an empty string.
    std::printf("%s[%d] tokenIds=[", phase, o.index);
    for (size_t i = 0; i < o.tokenIds.size(); ++i)
        std::printf("%s%d", i ? "," : "", o.tokenIds[i]);
    std::printf("]\n");
    std::printf("%s[%d] textEscaped=", phase, o.index);
    for (unsigned char ch : o.text) {
        if (ch == '\r')      std::printf("\\r");
        else if (ch == '\n') std::printf("\\n");
        else if (ch == '\t') std::printf("\\t");
        else if (ch < 0x20)  std::printf("\\x%02x", ch);
        else                 std::fputc(ch, stdout);
    }
    std::printf("\n");
    std::fflush(stdout);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: deep2_generation_lifecycle_test <model.gguf> "
            "[--generations N] [--max-tokens M] [--eos-max-tokens E]\n");
        return 2;
    }
    const std::string modelPath = argv[1];
    int   generations  = 4;
    uint32_t maxTokens = 8;
    uint32_t eosMaxTokens = 48;
    std::string customPrompt;  // if non-empty, used for every generation
    std::string customEosPrompt;  // if non-empty, used for the EOS probe

    for (int i = 2; i + 1 < argc; i += 2) {
        const std::string flag = argv[i];
        const std::string value = argv[i + 1];
        if (flag == "--generations")         generations  = std::atoi(value.c_str());
        else if (flag == "--max-tokens")     maxTokens    = (uint32_t)std::atoi(value.c_str());
        else if (flag == "--eos-max-tokens") eosMaxTokens = (uint32_t)std::atoi(value.c_str());
        else if (flag == "--prompt")         customPrompt = value;
        else if (flag == "--eos-prompt")     customEosPrompt = value;
    }

    std::printf("MODEL=%s\n", modelPath.c_str());
    std::printf("PLANNED_GENERATIONS=%d\n", generations);
    std::printf("MAX_TOKENS_PER_GENERATION=%u\n", maxTokens);
    std::printf("EOS_PROBE_MAX_TOKENS=%u\n", eosMaxTokens);
    std::printf("CUSTOM_PROMPT=%s\n", customPrompt.empty() ? "(none)" : customPrompt.c_str());
    std::printf("CUSTOM_EOS_PROMPT=%s\n", customEosPrompt.empty() ? "(none)" : customEosPrompt.c_str());
    std::printf("ENGINE_INSTANCES=1\n");
    std::printf("ENGINE_RECONSTRUCTED_BETWEEN_GENERATIONS=0\n");
    std::fflush(stdout);

// ---- Phase A: one engine, one model load --------------------------
// Heap-allocated behind a unique_ptr purely so the destruction boundary can be
// fenced. This is a diagnostic, NOT a leak workaround: ROOT:K and ROOT:L are
// emitted around an explicit reset(), so a crash is attributable to the
// destructor rather than to scope exit.
auto engineOwner = std::make_unique<Deep2::Deep2Engine>();
Deep2::Deep2Engine& engine = *engineOwner;
Deep2::EngineConfig cfg{};
    cfg.maxSeqLen    = 4096;
    cfg.useKVCache   = true;
    cfg.useThreadPool = true;
    cfg.numThreads   = 0;

    const auto tLoad0 = std::chrono::steady_clock::now();
    if (engine.initialize(cfg)) {
        std::printf("ENGINE_INIT=PASS\n");
        std::fflush(stdout);
    } else {
        std::printf("ENGINE_INIT=FAIL\n");
        std::fflush(stdout);
        return 1;
    }
    engine.enableVulkan(false);

    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(modelPath, &diag)) {
        std::printf("MODEL_LOAD=FAIL stage=%s message=%s\n",
            diag.stageName.c_str(), diag.message.c_str());
        std::fflush(stdout);
        return 1;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tLoad0).count();
    std::printf("MODEL_LOAD=PASS loadMs=%.0f kvAtLoad=%llu\n",
        loadMs, (unsigned long long)engine.kvCacheLength());
    std::fflush(stdout);

    // ---- Phase B: repeated generations on one instance -----------------
    std::vector<Observation> observations;
    observations.reserve((size_t)generations);
    for (int i = 0; i < generations; ++i) {
const std::string p = customPrompt.empty() ? promptFor(i) : customPrompt;
        std::fprintf(stderr, "ROOT:G_PRE_RUNONE idx=%d\n", i); std::fflush(stderr);
    Observation o = runOne(engine, p, maxTokens, i);
        std::fprintf(stderr, "ROOT:H_POST_RUNONE idx=%d\n", i); std::fflush(stderr);
    printObservation("B", o, maxTokens);
        std::fprintf(stderr, "ROOT:I_POST_PRINT idx=%d\n", i); std::fflush(stderr);
    observations.push_back(o);
    }

    // ---- Phase C: result-contract invariants --------------------------
    // Each invariant is a measured predicate over the recorded observations.
    int failuresReportedAsCompleted = 0;
    int cancelledReportedAsCompleted = 0;
    int successfulTurnsWithNoTokens = 0;
    int failureStatusesWithNoDetail = 0;
    int callbackCountsDisagreeing = 0;
    int kvInheritedFromPriorGenerations = 0;
    uint64_t priorTokensWritten = 0;

    for (size_t i = 0; i < observations.size(); ++i) {
        const Observation& o = observations[i];
    // D2's invariant, stated so it cannot be satisfied by accident.
    //
    // The reset runs INSIDE generate(), i.e. after runOne() has already
    // sampled kvBefore. A nonzero kvBefore is therefore the residue of the
    // previous generation, not evidence that the reset was skipped.
    //
    // What D2 forbids is a generation starting from a non-empty cache. The
    // observable form is an upper bound: the KV length after generation i can
    // never exceed the number of tokens generation i itself wrote. If a
    // previous generation's KV had survived the boundary, the length would be
    // prior_tokens + current_tokens and would exceed it.
    //
    // An earlier form of this check compared kvAfter against the PRIOR
    // generations' token total. That is wrong: with prompt 11 + 8 generated,
    // kvAfter is 18, and a preceding generation that had also written 18 tokens
    // made `18 >= 18` true — a false positive on a perfectly clean reset. The
    // bound has to be against the CURRENT generation, which is what this
    // generation's own writes can account for.
    if (i > 0 && o.kvAfter > o.promptTokens + o.generatedTokens)
        ++kvInheritedFromPriorGenerations;
        if (o.status == Deep2::GenerationStatus::ForwardFailure && o.completed)
            ++failuresReportedAsCompleted;
        if (o.status == Deep2::GenerationStatus::Cancelled && o.completed)
            ++cancelledReportedAsCompleted;
        if (o.completed && o.generatedTokens == 0)
            ++successfulTurnsWithNoTokens;
        const bool isFailureStatus =
            o.status == Deep2::GenerationStatus::ForwardFailure ||
            o.status == Deep2::GenerationStatus::InternalError ||
            o.status == Deep2::GenerationStatus::InvalidInput;
        if (isFailureStatus && o.failureDetail.empty())
            ++failureStatusesWithNoDetail;
        if (o.generatedTokens != o.callbackInvocations)
            ++callbackCountsDisagreeing;
        priorTokensWritten += o.promptTokens + o.generatedTokens;
    }

    std::printf("FORWARD_FAILURE_REPORTED_AS_COMPLETED=%d\n", failuresReportedAsCompleted);
    std::printf("CANCELLED_REPORTED_AS_COMPLETED=%d\n", cancelledReportedAsCompleted);
    std::printf("COMPLETED_WITH_ZERO_GENERATED_TOKENS=%d\n", successfulTurnsWithNoTokens);
    std::printf("FAILURE_STATUS_WITHOUT_DETAIL=%d\n", failureStatusesWithNoDetail);
    std::printf("GENERATED_TOKENS_DISAGREE_WITH_CALLBACK=%d\n", callbackCountsDisagreeing);
    std::printf("GENERATION_INHERITED_KV_FROM_PRIOR_GENERATIONS=%d\n", kvInheritedFromPriorGenerations);
    std::printf("TOKENS_WRITTEN_BY_PRIOR_GENERATIONS=%llu\n",
        (unsigned long long)priorTokensWritten);
    std::printf("KV_LENGTH_AFTER_LAST_GENERATION=%llu\n",
        (unsigned long long)(observations.empty() ? 0ULL
            : (unsigned long long)observations.back().kvAfter));

    int generationsSucceeded = 0;
    for (const Observation& o : observations)
        if (o.completed && o.status != Deep2::GenerationStatus::ForwardFailure)
            ++generationsSucceeded;
    std::printf("GENERATIONS_TOTAL=%zu\n", observations.size());
    std::printf("GENERATIONS_SUCCEEDED=%d\n", generationsSucceeded);
    std::fflush(stdout);

    // ---- Phase D: termination behaviour ------------------------------
    const std::string eosP = customEosPrompt.empty() ? promptFor(1) : customEosPrompt;
    Observation eosObs = runOne(engine, eosP, eosMaxTokens, 0, /*eosProbe=*/true);
    printObservation("D", eosObs, eosMaxTokens);
    const bool hitCeiling = eosObs.generatedTokens >= eosMaxTokens;
    std::printf("D_TERMINATED_AT_CEILING=%d\n", hitCeiling ? 1 : 0);
    std::printf("D_TERMINATED_EARLY=%d\n", hitCeiling ? 0 : 1);
    std::printf("D_EARLY_TOKENS_BEFORE_CEILING=%llu\n",
        hitCeiling ? 0ULL
                   : (unsigned long long)(eosMaxTokens - eosObs.generatedTokens));
    std::fflush(stdout);

    // ---- Derived verdict ----------------------------------------------
    //
    // Both predicates require that something was actually measured. The
    // inheritance check is guarded by `i > 0`, so with fewer than two
    // generations it cannot fail; combined with `generationsSucceeded ==
    // observations.size()` collapsing to `0 == 0`, `--generations 0` or
    // `--generations 1` printed VERDICT=PASS having measured nothing at all.
    // A lifecycle claim needs at least one prior generation to have been
    // inherited from.
    const bool enoughGenerationsToJudge = observations.size() >= 2;
    std::printf("GENERATIONS_ENOUGH_TO_JUDGE=%d\n", enoughGenerationsToJudge ? 1 : 0);

    const bool contractClean =
        failuresReportedAsCompleted == 0 &&
        cancelledReportedAsCompleted == 0 &&
        successfulTurnsWithNoTokens == 0 &&
        failureStatusesWithNoDetail == 0 &&
        callbackCountsDisagreeing == 0 &&
        !observations.empty();
    const bool lifecycleClean =
        enoughGenerationsToJudge &&
        kvInheritedFromPriorGenerations == 0 &&
        generationsSucceeded == (int)observations.size();

    std::printf("SAME_ENGINE_ALL_GENERATIONS_PASS=%d\n", lifecycleClean ? 1 : 0);
    std::printf("RESULT_CONTRACT_CLEAN=%d\n", contractClean ? 1 : 0);
    std::printf("VERDICT=%s\n",
        (lifecycleClean && contractClean) ? "PASS" : "FAIL");
    std::fflush(stdout);
    // The engine is a stack object in this scope, so its destructor and every
    // other automatic object in main run AFTER this marker. If ROOT:J prints
    // and the process then dies, the remaining suspect set is destruction or
    // CRT cleanup, not generation.
    std::fprintf(stderr, "ROOT:J_PRE_RETURN_MAIN\n"); std::fflush(stderr);

    // ROOT:K/L bracket the Deep2Engine destruction. If ROOT:K prints and the
    // process dies before ROOT:L, the destructor or the frees it performs are
    // implicated. If ROOT:L prints, Deep2Engine destruction is exonerated and
    // the remaining candidate is enclosing-object destruction or CRT cleanup.
    std::fprintf(stderr, "ROOT:K_BEFORE_ENGINE_DELETE\n"); std::fflush(stderr);
    engineOwner.reset();
    std::fprintf(stderr, "ROOT:L_AFTER_ENGINE_DELETE\n"); std::fflush(stderr);

    return (lifecycleClean && contractClean) ? 0 : 1;
}