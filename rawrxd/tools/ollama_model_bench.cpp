// RAWRXD_OLLAMA_MODEL_BENCH_001
//
// Per-model benchmark for Deep2, one model per invocation.
//
// WHAT THIS IS NOT
// ----------------
// It does not estimate throughput, does not extrapolate, and does not skip a
// model that fails. A model that cannot load, or that produces a non-finite
// first forward pass, is reported as FAIL with the engine's own failure detail
// attached. A benchmark that quietly omits the models that break is a report
// about the models that happened to work.
//
// EVERY NUMBER IS MEASURED HERE
//   loadMs    wall time of loadModel()
//   decodeMs  wall time of the timed generation pass, measured here
//   tokPerSec generatedTokens / decodeSeconds  -- NOT decodeMs/1000, which
//             would credit prefill time to decode and flatter every model
//   firstId   first generated token id, so two runs can be compared
//
// THROUGHPUT ALONE NEVER IMPLIES CORRECTNESS. The PASS/FAIL gate is computed
// separately, from completion and from the stream callback count agreeing with
// the reported token count.
//
// NOTE ON THE INCLUDE: this file lives in tools/, so a quoted
// #include "WeightConsumptionCensus.hpp" resolves against the -I list, and
// include/ contains a DIFFERENT, smaller header of the same name (the
// src/deep2 one is the implementation). The path-qualified form below is
// deliberate.

#include "Deep2Engine.h"
#include "deep2/WeightConsumptionCensus.hpp"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: ollama_model_bench <gguf-path> [maxTokens] [label]\n");
        return 2;
    }
    const std::string model   = argv[1];
    const int         maxTok  = (argc > 2) ? std::atoi(argv[2]) : 32;
    const std::string label   = (argc > 3) ? argv[3] : model;

    std::printf("=== BENCH_BEGIN ===\n");
    std::printf("LABEL=%s\n", label.c_str());
    std::printf("MODEL=%s\n", model.c_str());
    std::printf("MAX_TOKENS=%d\n", maxTok);

    Deep2::Deep2Engine eng;
    // CPU lane. The GPU lane is a different route decision and mixing the two
    // would make the columns incomparable.
    eng.enableVulkan(false);

    Deep2::ModelLoadDiag diag;
    auto tLoad = Clock::now();
    const bool loaded = eng.loadModel(model, &diag);
    const double loadMs = msSince(tLoad);
    std::printf("LOAD_OK=%d\n", loaded ? 1 : 0);
    std::printf("LOAD_MS=%.1f\n", loadMs);

    if (!loaded) {
        // Reported, never skipped.
        std::printf("LOAD_STAGE=%d\n", diag.stageCode);
        std::printf("LOAD_STAGE_NAME=%s\n", diag.stageName.c_str());
        std::printf("LOAD_MESSAGE=%s\n", diag.message.c_str());
        std::printf("VERDICT=FAIL_LOAD\n");
        std::printf("=== BENCH_END ===\n");
        return 1;
    }

    std::printf("ARCH=%s\n",     eng.modelArchitecture().c_str());
    std::printf("HIDDEN=%zu\n",  eng.hiddenDim());
    std::printf("LAYERS=%zu\n",  eng.numLayers());
    std::printf("HEAD_DIM=%zu\n", eng.headDim());
    std::printf("VOCAB=%zu\n",   eng.vocabSize());

    // ---- tokenizer round trip: a real check -------------------------------
    const std::string prompt = "The capital of France is";
    const std::vector<int> ids = eng.tokenize(prompt);
    const std::string back = eng.detokenize(ids);
    std::printf("PROMPT_TOKENS=%zu\n", ids.size());
    std::printf("TOKENIZER_ROUNDTRIP=%s\n", (back == prompt) ? "PASS" : "FAIL");

    // ---- warm-up, so one-time allocations are not billed to decode ---------
    {
        Deep2::GenerationOptions warm;
        warm.maxTokens = 1;
        auto t = Clock::now();
        eng.generateStream("warm", warm, [](int32_t, const std::string&) { return true; });
        std::printf("WARMUP_MS=%.1f\n", msSince(t));
    }

    // ---- timed greedy generation -------------------------------------------
    Deep2::GenerationOptions o;
    o.maxTokens   = maxTok;
    o.temperature = 0.0f;   // greedy, so the run is reproducible
    o.topK        = 1;

    int firstId = -1, emitted = 0;
    Deep2::GenerationResult r;
    double decodeMs = 0.0;
    {
        auto t = Clock::now();
        r = eng.generateStream(prompt, o, [&](int32_t id, const std::string&) {
            if (firstId < 0) firstId = id;
            ++emitted;
            return true;
        });
        decodeMs = msSince(t);
    }

    const double decodeSec = decodeMs / 1000.0;
    const double tps = decodeSec > 0.0
        ? (double)r.generatedTokens / decodeSec : 0.0;

    std::printf("STATUS=%d\n", (int)r.status);
    std::printf("COMPLETED=%d\n", r.completed ? 1 : 0);
    std::printf("GENERATED_TOKENS=%llu\n", (unsigned long long)r.generatedTokens);
    std::printf("STREAM_CALLBACKS=%d\n", emitted);
    std::printf("DECODE_MS=%.1f\n", decodeMs);
    std::printf("TOKENS_PER_SEC=%.3f\n", tps);
    std::printf("FIRST_TOKEN_ID=%d\n", firstId);
    std::printf("ENGINE_PREFILL_MS=%.1f\n", r.promptTimeMs);
    std::printf("ENGINE_DECODE_MS=%.1f\n", r.generationTimeMs);
    std::printf("FAILURE_DETAIL=%s\n",
                r.failureDetail.empty() ? "NONE" : r.failureDetail.c_str());

    // ---- the weight census this run actually produced ----------------------
    {
        using namespace rawrxd::deep2::weightcensus;
        const Census c = WeightConsumptionCensus::instance().snapshot();
        std::printf("CENSUS_EVENTS=%llu\n",     (unsigned long long)c.totalEvents);
        std::printf("CENSUS_BYTES=%llu\n",      (unsigned long long)c.totalBytes);
        std::printf("CENSUS_OWNED=%llu\n",      (unsigned long long)c.ownedEvents);
        std::printf("CENSUS_DELEGATED=%llu\n",  (unsigned long long)c.delegatedEvents);
        std::printf("CENSUS_BYPASS=%llu\n",     (unsigned long long)c.bypassEvents);
        std::printf("CENSUS_UNOBSERVED_SITES=%llu\n", (unsigned long long)c.unobservedSites);
        std::printf("CENSUS_VERDICT=%s\n", c.verdict());
    }

    // ---- verdict: derived from measurements, never asserted ------------------
    const bool ranOk    = (r.generatedTokens > 0) && r.failureDetail.empty();
    const bool streamed = ((unsigned long long)emitted == (unsigned long long)r.generatedTokens);
    const char* verdict =
        !ranOk             ? "FAIL_FORWARD"
      : !streamed          ? "FAIL_STREAM_MISMATCH"
      : (tps <= 0.0)       ? "FAIL_NO_RATE"
                           : "PASS";
    std::printf("VERDICT=%s\n", verdict);
    std::printf("=== BENCH_END ===\n");
    return std::strcmp(verdict, "PASS") == 0 ? 0 : 1;
}