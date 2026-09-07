// deep2_k2_e2e_model_size_matrix_cert.cpp — K2_E2E_MODEL_SIZE_MATRIX_001
// Workload-size matrix under DEFAULT AUTO; CORPUS_GIB ≠ STREAM_BYTES.
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

static uint64_t CorpusBytes(const char* dir) {
    uint64_t n = 0;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(dir, ec);
         !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file(ec)) n += (uint64_t)it->file_size(ec);
    }
    return n;
}

static void ClearPolicyEnv() {
#ifdef _WIN32
    SetEnvironmentVariableA("DEEP2_LIVE_POLICY", nullptr);
    _putenv_s("DEEP2_LIVE_POLICY", "");
    SetEnvironmentVariableA("DEEP2_LIVE_MECH", nullptr);
    _putenv_s("DEEP2_LIVE_MECH", "");
    SetEnvironmentVariableA("DEEP2_LIVE_PATH", nullptr);
    _putenv_s("DEEP2_LIVE_PATH", "");
#endif
}

struct Cell {
    uint32_t depth = 0, tokens = 0;
    bool ok = false, active = true;
    double tps = 0;
    uint64_t streamBytes = 0, cachePeak = 0;
    K2LivePolicyDecision pol{};
};

static Cell RunLive(Deep2Engine& e, const char* prompt, uint32_t depth,
                    uint32_t tokens) {
    Cell c; c.depth = depth; c.tokens = tokens;
    ClearPolicyEnv();
#ifdef _WIN32
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
#endif
    StreamTransfer_Reset();
    K2LivePolicy_ClearSticky();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    const double ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    c.ok = r.ok;
    c.tps = (r.ok && tokens && ms > 0) ? (1000.0 * tokens / ms) : 0.0;
    c.streamBytes = r.streamBytesRead;
    c.cachePeak = K2LiveCache_Snapshot().bytesPeak;
    c.pol = K2LivePolicy_Last();
    c.active = LivePath_Active();
    return c;
}

static bool ExpectArm(const K2LivePolicyDecision& d) {
    if (d.reuseSteps < d.crossoverSteps)
        return d.mode == K2LivePolicyMode::Off;
    return d.mode == K2LivePolicyMode::TrampolineOutput &&
           d.arm && std::strcmp(d.arm, "TRAMPOLINE_OUTPUT_CACHE") == 0;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\K2_E2E_MODEL_SIZE_MATRIX_001", nullptr);
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_E2E_MODEL_SIZE_MATRIX_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_E2E_MODEL_SIZE_MATRIX_001=SKIP\n"); return 0;
    }
    const uint64_t corpus = CorpusBytes(dir);
    const double corpusGiB = corpus / (1024.0 * 1024.0 * 1024.0);
    printf("CORPUS_BYTES=%llu CORPUS_GIB=%.2f\n",
           (unsigned long long)corpus, corpusGiB);

    // --- Classification grid (CPU): depth × tokens ---
    static const uint32_t kDepths[] = {1, 2, 4, 8, 16, 61};
    static const uint32_t kToks[] = {1, 2, 4, 8};
    int classOk = 0, classN = 0;
    printf("\nCLASS_GRID (DEFAULT AUTO Decide):\n");
    printf("depth\\tok");
    for (uint32_t t : kToks) printf("\t%u", t);
    printf("\n");
    for (uint32_t d : kDepths) {
        printf("%u", d);
        for (uint32_t t : kToks) {
            K2LivePolicy_ClearSticky();
            auto pol = K2LivePolicy_Decide(d, t);
            ++classN;
            if (ExpectArm(pol)) ++classOk;
            printf("\t%s", pol.arm ? pol.arm : "?");
        }
        printf("\n");
    }
    // DEFAULT Apply sets autoSelected
    ClearPolicyEnv();
    auto applySample = K2LivePolicy_Apply(4, 2);
    const bool defaultAuto = applySample.autoSelected == 1 &&
                             applySample.mode == K2LivePolicyMode::TrampolineOutput;

    // --- Live e2e cells ---
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    Deep2Engine* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) {
        printf("K2_E2E_MODEL_SIZE_MATRIX_001=FAIL open\n"); return 2;
    }

    static const uint32_t liveCells[][2] = {{2, 2}, {4, 2}, {8, 2}, {61, 2}};
    Cell cells[4];
    int liveOk = 0;
    bool corpusDistinct = true;
    bool veto61 = false;
    printf("\nLIVE_CELLS (DEFAULT AUTO):\n");
    for (int i = 0; i < 4; ++i) {
        cells[i] = RunLive(*eng, kPrompt, liveCells[i][0], liveCells[i][1]);
        const Cell& c = cells[i];
        const bool armOk = ExpectArm(c.pol) && c.pol.autoSelected == 1;
        const bool tear = !c.active && c.pol.switches <= 1;
        const bool xferLtCorpus =
            corpus > 0 && c.streamBytes > 0 && c.streamBytes < (corpus / 20);
        const bool cacheOk =
            c.pol.mode == K2LivePolicyMode::Off ||
            c.cachePeak <= K2LivePolicy_CacheBudgetBytes();
        const bool cellPass = c.ok && armOk && tear && xferLtCorpus && cacheOk;
        if (cellPass) ++liveOk;
        if (!xferLtCorpus) corpusDistinct = false;
        if (c.depth == 61) veto61 = (c.pol.layerVeto == 1);
        printf("D%ux%u arm=%s veto=%u tps=%.3f stream=%llu cachePeak=%llu "
               "auto=%u ok=%d\n",
               c.depth, c.tokens, c.pol.arm ? c.pol.arm : "?", c.pol.layerVeto,
               c.tps, (unsigned long long)c.streamBytes,
               (unsigned long long)c.cachePeak, c.pol.autoSelected, cellPass ? 1 : 0);
    }

    const bool classPass = classOk == classN && classN > 0;
    const bool livePass = liveOk == 4;
    const bool pass = classPass && livePass && defaultAuto && corpusDistinct &&
                      veto61 && corpusGiB > 100.0;
    printf("\nCLASS_PASS=%d (%d/%d) DEFAULT_AUTO=%d CORPUS_DISTINCT=%d "
           "VETO61=%d LIVE=%d/%d\n",
           classPass ? 1 : 0, classOk, classN, defaultAuto ? 1 : 0,
           corpusDistinct ? 1 : 0, veto61 ? 1 : 0, liveOk, 4);
    printf("K2_E2E_MODEL_SIZE_MATRIX_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_E2E_MODEL_SIZE_MATRIX_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "CORPUS_GIB=%.2f CLASS=%d/%d LIVE=%d/4 DEFAULT_AUTO=%d "
                "CORPUS_DISTINCT=%d VETO61=%d\n",
                corpusGiB, classOk, classN, liveOk, defaultAuto ? 1 : 0,
                corpusDistinct ? 1 : 0, veto61 ? 1 : 0);
        for (int i = 0; i < 4; ++i) {
            const Cell& c = cells[i];
            fprintf(f, "D%ux%u arm=%s stream=%llu tps=%.3f veto=%u\n",
                    c.depth, c.tokens, c.pol.arm ? c.pol.arm : "?",
                    (unsigned long long)c.streamBytes, c.tps, c.pol.layerVeto);
        }
        fprintf(f, "K2_E2E_MODEL_SIZE_MATRIX_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
