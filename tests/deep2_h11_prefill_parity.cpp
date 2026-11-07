// ============================================================================
// deep2_h11_prefill_parity.cpp — H11-P1..P4 prefill parity gate.
//
// Runs the SAME token sequence, initial KV state, device, precision mode and
// weights through both prefill paths and compares KV + logits:
//
//   H11-P1  PrefillBatch(1)   vs serial
//   H11-P2  PrefillBatch(2)   vs serial
//   H11-P3  PrefillBatch(16)  vs serial
//   H11-P4  PrefillBatch(128) vs serial
//
// Chunk=1 is deliberately included: it is the degenerate case where the batched
// path collapses to exactly one row per layer, so ANY divergence at chunk=1 is
// a pure implementation bug in the batched path rather than a reordering
// artifact. That makes P1 the sharpest of the four.
//
// This gate runs BEFORE H11-P5 (GPU command fusion). No submission-count
// optimisation may land while any of P1..P4 fails.
//
// H11_PARITY_AUTHORITY_001
// ============================================================================
#include "Deep2Engine.h"
#include "Tokenizer.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

using namespace Deep2;

static void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s <model.gguf> [prompt-text] [--kv-only]\n"
        "\n"
        "Runs H11-P1..P4 (chunk 1,2,16,128) against the serial prefill path.\n"
        "Exit 0 only when every gate PASSes.\n",
        argv0);
}

struct GateResult {
    int chunk = 0;
    double maxAbs = 0.0;
    bool passed = false;
    bool ran = false;
};

int main(int argc, char** argv) {
    // CTest registers this as an optional real-model gate. A build without
    // DEEP2_H11_MODEL must skip it, not report a usage error as a regression.
    if (argc < 2) { usage(argv[0]); return 77; }
    const std::string modelPath = argv[1];
    std::string promptText =
        (argc >= 3 && argv[2][0] != '-')
            ? argv[2]
            : "The quick brown fox jumps over the lazy dog. "
              "def add(a, b): return a + b  # parity probe sequence";
    bool kvOnly = false;
    for (int i = 2; i < argc; ++i)
        if (std::strcmp(argv[i], "--kv-only") == 0) kvOnly = true;

    std::printf("=== H11 PREFILL PARITY GATE ===\n");
    std::printf("model=%s\n", modelPath.c_str());

    // H11 is the serial-vs-batched implementation parity authority.  It is
    // intentionally a CPU-reference gate: the serial leg and the batched leg
    // must exercise the same host implementation before a separate GPU-vs-CPU
    // witness is allowed to make any hardware claim.  Set this before model
    // admission because loadModel() selects the execution lane.
#if defined(_WIN32)
    _putenv_s("RAWR_REAP_CPU_ONLY", "1");
#else
    setenv("RAWR_REAP_CPU_ONLY", "1", 1);
#endif
    std::printf("H11_EXECUTION_MODE=CPU_REFERENCE\n");

    // ---- engine setup ----
    Deep2Engine engine;
    EngineConfig cfg{};
    std::strncpy(cfg.modelPath, modelPath.c_str(), sizeof(cfg.modelPath) - 1);
    cfg.useKVCache = true;
    cfg.useRoPE = true;
    cfg.numThreads = 1;          // determinism: single-threaded accumulation
    cfg.maxSeqLen = 2048;

    if (!engine.initialize(cfg)) {
        std::printf("[H11] FATAL: initialize() failed\n");
        return 2;
    }
    if (!engine.loadModel(modelPath)) {
        std::printf("[H11] FATAL: loadModel() failed\n");
        return 2;
    }

    // H11 compares the serial and batched implementations, so both legs must
    // use the same KV representation.  The normal enhancement stack enables
    // the compressed Q8 KV sidecar for generation; that sidecar is not exposed
    // through the parity snapshot API.  Disable it for this controlled gate so
    // both legs write/read the authoritative FP32 KVCache.
    engine.enableCompressedKV(false);

    // ---- identical token sequence for every gate ----
    std::vector<int> tokens = engine.tokenize(promptText);
    if (tokens.empty()) {
        // Fall back to a deterministic synthetic sequence when the model has no
        // tokenizer: parity is about the forward path, not the vocab.
        for (int i = 0; i < 64; ++i)
            tokens.push_back(1 + (i * 37) % 500);
        std::printf("[H11] tokenizer empty; using synthetic 64-token sequence\n");
    }
    // Cap at 128 so H11-P4 exercises a real multi-chunk case even for short
    // tokenizers, without exceeding the 2048 context.
    if (tokens.size() > 128) tokens.resize(128);
    std::printf("[H11] prompt_tokens=%zu (identical for every gate)\n",
                tokens.size());

    const ModelMetadata meta = engine.getModelMetadata();
    const EngineConfig &loaded = engine.getConfig();
    std::printf("[H11] layers=%zu hidden=%zu heads=%zu kv_heads=%zu head_dim=%zu vocab=%zu\n",
                loaded.numLayers, loaded.hiddenDim, loaded.numHeads,
                loaded.numKVHeads, loaded.headDim, loaded.vocabSize);
    if (meta.hiddenSize != loaded.hiddenDim || meta.numLayers != loaded.numLayers ||
        meta.numHeads != loaded.numHeads || meta.numKeyValueHeads != loaded.numKVHeads) {
        std::fprintf(stderr,
                     "[H11] FATAL: metadata/config geometry mismatch "
                     "meta=(hidden=%u layers=%u heads=%u kv=%u) "
                     "config=(hidden=%zu layers=%zu heads=%zu kv=%zu)\n",
                     meta.hiddenSize, meta.numLayers, meta.numHeads,
                     meta.numKeyValueHeads, loaded.hiddenDim, loaded.numLayers,
                     loaded.numHeads, loaded.numKVHeads);
        return 2;
    }
    (void)meta;

    // ---- run P1..P4 ----
    const int chunks[] = {1, 2, 16, 128};
    GateResult results[4];
    int failures = 0;

    for (int g = 0; g < 4; ++g) {
        const int chunk = chunks[g];
        std::printf("\n--- H11-P%d chunk=%d ---\n", g + 1, chunk);
        std::fflush(stdout);
        // The engine throws when it finds something it cannot proceed with,
        // and a throw that leaves the driver is a process that dies with no
        // verdict and no explanation: the run reports a fast fail and
        // nothing else. The gate is supposed to say which gate failed and
        // why, so the throw is caught here and turned into a failed gate
        // with the engine's own message in it.
        double r = -1.0;
        try {
            r = engine.prefillParityReport(
                tokens.data(), tokens.size(), (size_t)chunk, stdout);
        }
        catch (const std::exception& e) {
            std::fflush(stdout);
            std::fprintf(stderr,
                         "[H11_PARITY] H11-P%d chunk=%d THREW: %s\n",
                         g + 1, chunk, e.what());
            std::fflush(stderr);
            r = -1.0;
        }
        catch (...) {
            std::fflush(stdout);
            std::fprintf(stderr,
                         "[H11_PARITY] H11-P%d chunk=%d THREW a non-standard exception\n",
                         g + 1, chunk);
            std::fflush(stderr);
            r = -1.0;
        }
        results[g].chunk = chunk;
        results[g].maxAbs = r;
        results[g].ran = (r >= 0.0);
        // The report prints its own PASS/FAIL; re-derive from the tolerance the
        // report used so the exit code cannot disagree with the printed verdict.
        results[g].passed = results[g].ran && r <= 1e-3;
        if (!results[g].passed) ++failures;
    }

    // ---- summary ----
    std::printf("\n=== H11 PREFILL PARITY SUMMARY ===\n");
    std::printf("%-8s %-8s %-16s %s\n", "GATE", "CHUNK", "MAX_ABS", "VERDICT");
    for (int g = 0; g < 4; ++g) {
        std::printf("%-8s %-8d %-16.6e %s\n",
                    (std::string("H11-P") + char('1' + g)).c_str(),
                    results[g].chunk,
                    results[g].maxAbs,
                    results[g].passed ? "PASS" : "FAIL");
    }

    // ---- H11 dispatch accounting ----
    // The four independent counters that separate "N compute commands" from
    // "N queue submissions". This is what decides the H11-P5 fusion strategy,
    // so it is captured here even though fusion is deliberately NOT done yet.
    const Deep2Engine::DispatchAccount acct = engine.dispatchAccount();
    std::printf("\n--- H11 DISPATCH ACCOUNTING (batched path) ---\n");
    std::printf("vkCmdDispatch_count=%llu\n",
                (unsigned long long)acct.cmdDispatchCount);
    std::printf("vkQueueSubmit_count=%llu\n",
                (unsigned long long)acct.queueSubmitCount);
    std::printf("fence_wait_count=%llu\n",
                (unsigned long long)acct.fenceWaitCount);
    std::printf("gpu_execution_ns=%llu\n",
                (unsigned long long)acct.gpuExecutionNs);
    std::printf("gpu_sync_ns=%llu\n",
                (unsigned long long)acct.gpuSyncNs);
    std::printf("matrix_rows_delta=%llu\n",
                (unsigned long long)acct.matrixRowsDelta);
    std::printf("NOTE: these counters are currently ZERO because the GEMV\n");
    std::printf("      dispatch sites in vulkan_compute.cpp have not yet been\n");
    std::printf("      wired to noteCmdDispatch()/noteQueueSubmit(). Reporting\n");
    std::printf("      zero here is honest; fabricating a count is not.\n");

    (void)kvOnly;
    const bool allPass = (failures == 0);
    std::printf("\n[H11_PREFILL_PARITY_RESULT] %s (%d/%d gates passed)\n",
                allPass ? "PASS" : "FAIL", 4 - failures, 4);
    return allPass ? 0 : 1;
}
