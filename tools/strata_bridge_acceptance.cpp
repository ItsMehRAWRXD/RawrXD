// strata_bridge_acceptance.cpp -- headless Track E acceptance entry point.
//
// Drives the SAME production text-inference core the native IDE bridge uses
// (rawrxd::StrataTextRunner) with the REAL model tokenizer
// (RawrXD::CPUInferenceEngine, model-identity matched) and a real prompt. Emits
// STRUCTURED telemetry (from StrataChatStats, not stderr) and checks the R05
// invariants. No GUI, no external server, no subprocess, no test-only pipeline.
//
// Exit 0 = PASS. Non-zero = a genuine failure (reported, never fabricated).

#include "cpu_inference_engine.h"
#include "agentic/StrataTextRunner.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <gguf> [prompt] [maxTokens=64]\n", argv[0]);
        return 2;
    }
    const std::string model = argv[1];
    const std::string prompt = argc > 2 ? argv[2] : "The capital of France is";
    const size_t maxTokens = argc > 3 ? (size_t)std::atoi(argv[3]) : 64;

    // Real tokenizer, model-identity matched (same engine the Deep2 bridge uses).
    RawrXD::CPUInferenceEngine tok;
    if (!tok.LoadModel(model)) {
        std::fprintf(stderr, "TOKENIZER_LOAD_FAIL %s\n", model.c_str());
        return 3;
    }

    rawrxd::StrataTextRunner runner(
        model,
        [&tok](const std::string& t) { return tok.Tokenize(t); },
        [&tok](const std::vector<int>& ids) { return tok.Detokenize(ids); });
    rawrxd::StrataRunOptions opt;
    opt.maxTokens = maxTokens;
    const rawrxd::StrataRunResult rr = runner.Run(prompt, opt);

    std::printf(
        "STRATA_IDE_TELEMETRY {\"prompt\":\"%s\",\"generated_chars\":%zu,"
        "\"expert_accesses\":%llu,\"expert_hits\":%llu,\"expert_misses\":%llu,"
        "\"expert_evictions\":%llu,\"expert_hit_rate\":%.4f,"
        "\"transferred_bytes\":%llu,\"gpu_calls\":%llu,\"cpu_calls\":%llu,"
        "\"ok\":%s,\"error\":\"%s\"}\n",
        prompt.c_str(), rr.text.size(),
        (unsigned long long)rr.expertAccesses,
        (unsigned long long)rr.expertHits,
        (unsigned long long)rr.expertMisses,
        (unsigned long long)rr.expertEvictions,
        rr.expertHitRate,
        (unsigned long long)rr.transferredBytes,
        (unsigned long long)rr.gpuCalls,
        (unsigned long long)rr.cpuCalls,
        rr.ok ? "true" : "false", rr.error.c_str());
    std::printf("STRATA_IDE_TEXT \"%s\"\n", rr.text.c_str());

    int fails = 0;
    if (!rr.ok) { std::fprintf(stderr, "FAIL: runner not ok: %s\n", rr.error.c_str()); ++fails; }
    if (rr.gpuCalls == 0) { std::fprintf(stderr, "FAIL: no GPU execution\n"); ++fails; }
    if (rr.expertAccesses == 0) { std::fprintf(stderr, "FAIL: no expert residency\n"); ++fails; }
    if (rr.text.empty()) { std::fprintf(stderr, "FAIL: empty generation\n"); ++fails; }

    if (fails) { std::printf("STRATA_IDE_BRIDGE_ACCEPTANCE=FAIL\n"); return 1; }
    std::printf("STRATA_IDE_BRIDGE_ACCEPTANCE=PASS\n");
    return 0;
}