// deepseek_e2e_driver.cpp
//
// RAWRXD_DEEPSEEK_CPU_E2E_001 -- the single-model end-to-end driver.
//
// WHY A SEPARATE DRIVER
// ---------------------
// deep2_streamer_cert is a CENSUS: it discovers artefacts under roots, spawns a
// child per model, and tallies outcomes. That shape cannot answer "why did
// DeepSeek not stream", because the census reports a per-model RESULT and
// discards the stage that failed. DeepSeek is the one model here whose
// architecture (MLA + MoE) has no CPU execution route at all, so the question
// is not "is it in the census" but "which stage, in order, first refuses".
//
// This driver therefore emits ONE model, ONE ordered stage trace, and ONE
// derived verdict. Every field printed is either an observation from the engine
// or a value the engine returned. There is no expected value written as a
// literal anywhere below.
//
// HONESTY CONSTRAINTS BUILT INTO THIS FILE
// ----------------------------------------
//  * VERDICT is computed from counted observations, never assigned.
//  * No PREDICTED_* / EXPECTED_* / DREAM_* field exists, by construction.
//  * A failure prints the stage that failed and the engine's own message; it
//    does not print a plausible number for the stages that never ran.
//  * Exit code 0 means text was streamed. Non-zero means it was not, and the
//    number says which class of failure it was.

#include "Deep2Engine.h"

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

namespace {

int g_stageFail = -1;
std::string g_stageName;
std::string g_stageDetail;

// Wall clock helper. Every duration below is measured, never declared.
double nowMs() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double, std::milli>(
               clock::now().time_since_epoch()).count();
}

void kv(const char* k, const std::string& v) {
    std::printf("%s=%s\n", k, v.c_str());
    std::fflush(stdout);
}
void kv(const char* k, long long v) { std::printf("%s=%lld\n", k, v); std::fflush(stdout); }
void kv(const char* k, int v)        { kv(k, (long long)v); }
void kv(const char* k, unsigned v)   { kv(k, (long long)v); }
void kv(const char* k, unsigned long long v) { std::printf("%s=%llu\n", k, v); std::fflush(stdout); }
void kv(const char* k, double v)    { std::printf("%s=%.6g\n", k, v);  std::fflush(stdout); }

void stage(const char* name) {
    std::printf("[STAGE] ENTER name=%s\n", name);
    std::fflush(stdout);
}
void stageOk(const char* name) {
    std::printf("[STAGE] OK    name=%s\n", name);
    std::fflush(stdout);
}
void stageFail(const char* name, const std::string& detail) {
    if (g_stageFail < 0) { g_stageFail = 1; g_stageName = name; g_stageDetail = detail; }
    std::printf("[STAGE] FAIL  name=%s detail=%s\n", name, detail.c_str());
    std::fflush(stdout);
}

} // namespace

int main(int argc, char** argv) {
    std::string modelPath;
    std::string prompt = "The capital of France is";
    uint32_t maxTokens = 16;
    bool wantVulkan = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) modelPath = argv[++i];
        else if (a == "--prompt" && i + 1 < argc) prompt = argv[++i];
        else if (a == "--tokens" && i + 1 < argc)
            maxTokens = (uint32_t)std::strtoul(argv[++i], nullptr, 10);
        else if (a == "--vulkan") wantVulkan = true;
    }
    if (modelPath.empty()) {
        std::fprintf(stderr, "usage: deepseek_e2e_driver --model PATH "
                             "[--prompt TEXT] [--tokens N] [--vulkan]\n");
        return 64;
    }

    std::printf("=== RAWRXD_DEEPSEEK_CPU_E2E_001 ===\n");
    kv("MODEL_PATH", modelPath);
    kv("PROMPT", prompt);
    kv("REQUESTED_TOKENS", (long long)maxTokens);
    kv("VULKAN_REQUESTED", wantVulkan ? 1 : 0);

    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", modelPath.c_str());
    cfg.maxSeqLen = 512;
    cfg.numThreads = 0;                 // auto
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    engine.enableVulkan(wantVulkan);

    // ---- STAGE 1: initialize -------------------------------------------------
    stage("ENGINE_INITIALIZE");
    const double tInit0 = nowMs();
    bool initialized = false;
    try {
        initialized = engine.initialize(cfg);
    } catch (const std::exception& e) {
        stageFail("ENGINE_INITIALIZE", e.what());
    }
    if (!initialized) {
        if (g_stageFail < 0) stageFail("ENGINE_INITIALIZE", "returned false");
    } else {
        stageOk("ENGINE_INITIALIZE");
    }
    kv("INIT_MS", nowMs() - tInit0);

    // ---- STAGE 2: load model ------------------------------------------------
    Deep2::ModelLoadDiag diag;
    bool loaded = false;
    if (initialized) {
        stage("MODEL_LOAD");
        const double tLoad0 = nowMs();
        try {
            loaded = engine.loadModel(modelPath, &diag);
        } catch (const std::exception& e) {
            stageFail("MODEL_LOAD", e.what());
            g_stageDetail = e.what();
        }
        kv("LOAD_MS", nowMs() - tLoad0);
        if (loaded) {
            stageOk("MODEL_LOAD");
        } else {
            kv("LOAD_STAGE_CODE", (long long)diag.stageCode);
            kv("LOAD_STAGE_NAME", diag.stageName);
            kv("LOAD_MESSAGE", diag.message);
            stageFail("MODEL_LOAD",
                      diag.stageName + ": " + diag.message);
        }
    }

    // ---- STAGE 3: generate --------------------------------------------------
    uint64_t streamedTokens = 0;
    uint64_t callbacks = 0;
    bool contiguous = true;
    bool sawNonFiniteToken = false;
    std::string text;
    Deep2::GenerationStatus status = Deep2::GenerationStatus::InternalError;
    std::string failureDetail;
    double streamMs = 0.0;

    if (loaded) {
        stage("GENERATE_STREAM");
        const double tGen0 = nowMs();

        Deep2::GenerationOptions opt;
        opt.maxTokens = maxTokens;
        opt.temperature = 0.0f;   // greedy: a non-deterministic first token is
        opt.topP = 1.0f;          // not a useful failure signal
        opt.topK = 1;
        opt.seed = 1;

        int64_t lastTok = -1;
        auto cb = [&](int32_t tokenId, const std::string& token) -> bool {
            ++callbacks;
            if (lastTok >= 0 && tokenId != lastTok + 1) contiguous = false;
            lastTok = tokenId;
            text += token;
            if (!token.empty()) {
                // A token that decoded to raw NUL/control soup is the
                // signature of reading logits that are not real logits.
                for (unsigned char c : token)
                    if (c < 0x09 || (c > 0x0d && c < 0x20)) sawNonFiniteToken = true;
            }
            std::printf("[TOKEN] id=%d text=%s\n", (int)tokenId, token.c_str());
            std::fflush(stdout);
            return true;   // never cancel: the point is to see the whole run
        };

        try {
            Deep2::GenerationResult r = engine.generateStream(prompt, opt, cb);
            status = r.status;
            streamedTokens = r.generatedTokens;
            failureDetail = r.failureDetail;
            kv("REPORTED_PROMPT_TOKENS", (long long)r.promptTokens);
            kv("REPORTED_GENERATED_TOKENS", (long long)r.generatedTokens);
        } catch (const std::exception& e) {
            stageFail("GENERATE_STREAM", e.what());
            failureDetail = e.what();
        }
        streamMs = nowMs() - tGen0;
        kv("STREAM_WALL_MS", streamMs);

        if (g_stageFail < 0 && streamedTokens > 0) stageOk("GENERATE_STREAM");
        else if (g_stageFail < 0) stageFail("GENERATE_STREAM",
                        failureDetail.empty() ? "zero tokens" : failureDetail);
    }

    // ---- STAGE 4: teardown --------------------------------------------------
    stage("TEARDOWN");
    bool cleanTeardown = true;
    try {
        engine.reset();
        kv("KV_CACHE_LENGTH_AFTER", (long long)engine.kvCacheLength());
        engine.unloadModel();
    } catch (const std::exception& e) {
        cleanTeardown = false;
        stageFail("TEARDOWN", e.what());
    }
    if (cleanTeardown) stageOk("TEARDOWN");

    // ---- DERIVED VERDICT ----------------------------------------------------
    // Computed from the counters above. There is no branch that assigns a
    // verdict without first having counted something.
    const char* statusName = "Unknown";
    switch (status) {
        case Deep2::GenerationStatus::Completed:        statusName = "Completed"; break;
        case Deep2::GenerationStatus::EndOfSequence:    statusName = "EndOfSequence"; break;
        case Deep2::GenerationStatus::Cancelled:        statusName = "Cancelled"; break;
        case Deep2::GenerationStatus::InvalidInput:     statusName = "InvalidInput"; break;
        case Deep2::GenerationStatus::ForwardFailure:   statusName = "ForwardFailure"; break;
        case Deep2::GenerationStatus::InternalError:    statusName = "InternalError"; break;
    }

    std::printf("\n=== RECEIPT ===\n");
    kv("INITIALIZED", initialized ? 1 : 0);
    kv("MODEL_LOADED", loaded ? 1 : 0);
    kv("CALLBACKS", (long long)callbacks);
    kv("STREAM_CALLBACKS_EQUAL_REPORTED",
       callbacks == streamedTokens ? 1 : 0);
    kv("TOKEN_IDS_CONTIGUOUS", contiguous ? 1 : 0);
    kv("SUSPECTED_NON_TEXT_TOKENS", sawNonFiniteToken ? 1 : 0);
    kv("CLEAN_TEARDOWN", cleanTeardown ? 1 : 0);
    kv("STATUS", statusName);
    kv("FAILURE_DETAIL", failureDetail);
    if (streamMs > 0.0 && streamedTokens > 0)
        kv("DECODE_TPS", (double)streamedTokens / (streamMs / 1000.0));
    else
        kv("DECODE_TPS", 0.0);
    kv("TEXT", text);
    kv("FIRST_FAILED_STAGE", g_stageName.empty() ? "NONE" : g_stageName);
    kv("FIRST_FAILED_STAGE_DETAIL", g_stageDetail.empty() ? "NONE" : g_stageDetail);

    const bool pass = loaded && streamedTokens > 0 && callbacks == streamedTokens
                      && cleanTeardown && g_stageFail < 0;
    // Verdict derived only after every counter above has a value.
    kv("TEXT_STREAMED", (streamedTokens > 0 && !text.empty()) ? 1 : 0);
    kv("VERDICT", pass ? "PASS" : "FAIL");

    if (!text.empty()) { std::printf("\n=== COMPLETION ===\n%s\n", text.c_str()); }
    std::fflush(stdout);
    return pass ? 0 : (g_stageFail < 0 ? 1 : (10 + g_stageFail));
}