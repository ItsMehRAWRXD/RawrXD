// deep2_k2_stream_miss_reality_cert.cpp — K2_STREAM_MISS_REALITY_001
// Fiction→reality: OFF path ≈ vocab-row STREAM_MISS; trampoline collapses it;
// cyclone+active-depth allows blk.* host-fill (not fictional ×61 WS).
#include "Deep2Engine.h"
#include "K2LivePathTensorCache.hpp"
#include "K2LivePolicy.hpp"
#include "StreamTransferCounters.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

struct Arm {
    bool ok = false;
    uint64_t miss = 0, hit = 0;
    uint64_t layerHits = 0, trampHits = 0;
    int32_t tok = -1;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t depth,
               uint32_t tokens, const char* policy) {
    Arm a{};
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", policy);
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    if (_stricmp(policy, "AUTO") == 0 || _stricmp(policy, "OFF") == 0) {
        _putenv_s("DEEP2_LIVE_PATH", "");
        _putenv_s("DEEP2_LIVE_MECH", "");
    }
    if (_stricmp(policy, "OFF") == 0)
        K2LivePolicy_ClearSticky();
#endif
    StreamTransfer_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 3072ull << 20;
    auto r = e.runK2NativeStreamPartial(kc);
    a.ok = r.ok; a.tok = r.generatedTokenId;
    auto st = StreamTransfer_Snapshot();
    a.miss = st.cacheMisses; a.hit = st.cacheHits;
    auto lc = K2LiveCache_Snapshot();
    a.layerHits = lc.cycloneLayerHits; a.trampHits = lc.trampOutHits;
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("DEEP2_LIVE_CROSSOVER_STEPS", "8");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "1");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_STREAM_MISS_REALITY_001", nullptr);
    printf("K2_STREAM_MISS_REALITY_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_STREAM_MISS_REALITY_001=SKIP\n"); return 0;
    }
    static const char* kPrompt = "Say hello in one short sentence.";
    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_STREAM_MISS_REALITY_001=FAIL open\n"); return 2;
    }

    printf("\n--- A: OFF d=1 t=1 (vocab-row fiction exposed) ---\n");
    Arm A = Run(eng, kPrompt, 1, 1, "OFF");
    printf("OK=%d MISS=%llu HIT=%llu (vocab~163840)\n",
           A.ok ? 1 : 0, (unsigned long long)A.miss, (unsigned long long)A.hit);

    printf("\n--- B: TRAMPOLINE d=1 t=2 (output pin collapses miss) ---\n");
    Arm B = Run(eng, kPrompt, 1, 2, "TRAMPOLINE");
    printf("OK=%d MISS=%llu HIT=%llu TRAMP_HITS=%llu\n",
           B.ok ? 1 : 0, (unsigned long long)B.miss, (unsigned long long)B.hit,
           (unsigned long long)B.trampHits);

    printf("\n--- C: FULL_DEPTH_PROMO d=4 t=2 (active-depth layer fill) ---\n");
    Arm C = Run(eng, kPrompt, 4, 2, "PROMO");
    printf("OK=%d MISS=%llu HIT=%llu LAYER_HITS=%llu TRAMP_HITS=%llu\n",
           C.ok ? 1 : 0, (unsigned long long)C.miss, (unsigned long long)C.hit,
           (unsigned long long)C.layerHits, (unsigned long long)C.trampHits);

    // A: OFF logits stream ≈ one RecordRead per vocab row.
    const bool vocabFiction = A.ok && A.miss >= 160000ull && A.miss <= 170000ull;
    // B: trampoline must beat 2×OFF miss by a wide margin (not 2×163k).
    const bool trampCollapse = B.ok && B.miss < A.miss && B.trampHits > 0;
    // C: with active-depth fill, either layer host hits OR miss << 2×A.
    const bool depthFill = C.ok && (C.layerHits > 0 || C.miss < (A.miss * 2));

    const bool pass = vocabFiction && trampCollapse && depthFill;
    printf("VOCAB_ROW_MISS=%u TRAMP_COLLAPSE=%u DEPTH_FILL=%u\n",
           vocabFiction ? 1u : 0u, trampCollapse ? 1u : 0u, depthFill ? 1u : 0u);
    printf("K2_STREAM_MISS_REALITY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_STREAM_MISS_REALITY_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "A_miss=%llu B_miss=%llu C_miss=%llu\n",
                (unsigned long long)A.miss, (unsigned long long)B.miss,
                (unsigned long long)C.miss);
        fprintf(f, "B_tramp=%llu C_layer=%llu\n",
                (unsigned long long)B.trampHits,
                (unsigned long long)C.layerHits);
        fprintf(f, "vocab=%d tramp=%d depth=%d\n",
                vocabFiction, trampCollapse, depthFill);
        fprintf(f, "K2_STREAM_MISS_REALITY_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f,
                "NOTE=OFF miss~vocab; trampoline pins output; "
                "LayerHostFillAllowed uses RAWRXD_K2_LAYERS not x61.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
