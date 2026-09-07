// deep2_k2_gpu_mla_re_cert.cpp — K2_GPU_MLA_RE_001
// RE: GPU MLA_OPS=6*D*T (Q4+Q8); pin u=6*D; hits>=6*D*(T-1); t1 parity.
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
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

struct Arm {
    bool ok = false;
    double tps = 0, wallMs = 0;
    int32_t tok = -1;
    std::string text;
    uint64_t mlaOk = 0, mlaFail = 0, hits = 0, uploads = 0, streamMiss = 0;
};

static Arm Run(Deep2Engine& e, const char* prompt, uint32_t depth,
               uint32_t tokens, bool gpuMla) {
    Arm a{};
#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_MLA_SERIAL", "1");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_K2_GPU_MLA", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_WEIGHT_PIN", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "0");
    _putenv_s("DEEP2_WEIGHT_OVERLAP", "0");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
#endif
    MLA_GpuGemv_Reset();
    K2GpuStreamCopy_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    if (gpuMla) {
        if (!e.isVulkanInitialized()) e.enableVulkan(true);
        if (auto* vc = e.getVulkanComputeSlot(0)) {
            vc->ReleaseWeightWindow();
            vc->ClearPinnedGemvWeights();
            K2GpuStreamCopy_Bind(vc);
        }
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    a.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    a.ok = r.ok; a.tok = r.generatedTokenId; a.text = r.generatedText;
    a.tps = (r.ok && tokens && a.wallMs > 0) ? (1000.0 * tokens / a.wallMs) : 0.0;
    a.mlaOk = MLA_GpuGemvOps(); a.mlaFail = MLA_GpuGemvFail();
    a.streamMiss = StreamTransfer_Snapshot().cacheMisses;
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.hits = vc->WeightContentHits();
        a.uploads = vc->GemvWeightUploads();
    }
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "2048");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "96");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_RE_001", nullptr);
    uint32_t nTok = 2, depth = 4;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)atoi(t);
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH")) depth = (uint32_t)atoi(d);
    if (nTok < 2) nTok = 2;
    const uint64_t unique = 6ull * depth;
    const uint64_t expectN = unique * nTok;
    printf("K2_GPU_MLA_RE_001\nMODEL=%s DEPTH=%u TOKENS=%u\n", dir, depth, nTok);
    printf("RE MLA_OPS=6*D*T STREAM_MISS~const*T PIN_U=6*D PIN_H>=6*D*(T-1)\n");
    if (!fs::is_directory(dir)) { printf("K2_GPU_MLA_RE_001=SKIP\n"); return 0; }

    static const char* kPrompt = "Say hello in one short sentence.";
    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_GPU_MLA_RE_001=FAIL open\n"); return 2;
    }

    printf("\n--- A d=1 t=1 parity ---\n");
    Arm c1 = Run(eng, kPrompt, 1, 1, false);
    Arm g1 = Run(eng, kPrompt, 1, 1, true);
    const bool ops1 = g1.mlaOk == 6 && g1.mlaFail == 0;
    const bool parity1 = c1.ok && g1.ok && c1.tok == g1.tok && c1.text == g1.text;
    printf("CPU=%d GPU=%d MLA=%llu PARITY=%d\n", (int)c1.tok, (int)g1.tok,
           (unsigned long long)g1.mlaOk, parity1 ? 1 : 0);

    printf("\n--- B d=%u t=%u ops+pin+miss ---\n", depth, nTok);
    Arm cN = Run(eng, kPrompt, depth, nTok, false);
    Arm gN = Run(eng, kPrompt, depth, nTok, true);
    const bool opsN = gN.mlaOk == expectN && gN.mlaFail == 0;
    const bool pinU = gN.uploads == unique;
    const bool pinH = gN.hits >= unique * (nTok - 1);
    const bool missEq = cN.streamMiss == gN.streamMiss && cN.streamMiss > 0;
    const bool floor = gN.tps + 1e-12 >= cN.tps * 0.85;
    printf("MLA=%llu/%llu u=%llu h=%llu want_u=%llu want_h>=%llu\n",
           (unsigned long long)gN.mlaOk, (unsigned long long)expectN,
           (unsigned long long)gN.uploads, (unsigned long long)gN.hits,
           (unsigned long long)unique, (unsigned long long)(unique * (nTok - 1)));
    printf("STREAM_MISS cpu=%llu gpu=%llu EQ=%d\n",
           (unsigned long long)cN.streamMiss, (unsigned long long)gN.streamMiss,
           missEq ? 1 : 0);

    const bool pass = ops1 && parity1 && opsN && pinU && pinH && missEq &&
                      floor && cN.ok && gN.ok;
    printf("OPS1=%d PARITY1=%d OPSN=%d PIN_U=%d PIN_H=%d MISS_EQ=%d FLOOR=%d\n",
           ops1?1:0, parity1?1:0, opsN?1:0, pinU?1:0, pinH?1:0, missEq?1:0, floor?1:0);
    printf("K2_GPU_MLA_RE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_RE_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "D=%u T=%u ops=%llu u=%llu h=%llu stream_miss=%llu\n",
                depth, nTok, (unsigned long long)gN.mlaOk,
                (unsigned long long)gN.uploads, (unsigned long long)gN.hits,
                (unsigned long long)gN.streamMiss);
        fprintf(f, "parity1=%d cpu=%d gpu=%d\n", parity1, (int)c1.tok, (int)g1.tok);
        fprintf(f, "K2_GPU_MLA_RE_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=RE tokens*layers GEMV + pin miss/hit + stream_miss.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
