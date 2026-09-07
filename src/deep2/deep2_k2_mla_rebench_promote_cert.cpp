// deep2_k2_mla_rebench_promote_cert.cpp — K2_MLA_REBENCH_PROMOTE_001
// Authority: t1 parity + Q4 MLA ops (3*D*T) + pin reuse + TPS≥0.97×A
// Soft: full-depth token identity. Budgets = ElasticBudget_Derive (live).
#include "Deep2Engine.h"
#include "ElasticDynamicBudget.hpp"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2ShardIo.hpp"
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
    uint64_t mlaOk = 0, mlaFail = 0, hits = 0, uploads = 0, pinRej = 0;
    uint64_t hotMiB = 0, warmMiB = 0, stagedMiB = 0;
    uint32_t la = 0;
};

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

static ElasticResidencyConfig Dyn(uint32_t depth) {
    ElasticDynamicProbe p{};
    ElasticBudget_ProbeHost(p);
    p.layers = depth;
    auto c = ElasticBudget_Derive(p);
    ElasticBudget_Emit(stdout, c, p);
    return c;
}

static void ArmEnv(uint32_t depth, bool gpu, uint64_t hotMiB) {
    Sync("DEEP2_LIVE_POLICY", "OFF");
    Sync("DEEP2_MLA_SERIAL", "1");
    Sync("DEEP2_K2_GPU_STREAM_COPY", gpu ? "1" : "0");
    Sync("DEEP2_K2_GPU_MLA", gpu ? "1" : "0");
    Sync("DEEP2_WEIGHT_PIN", gpu ? "1" : "0");
    Sync("DEEP2_TRAMP_FAST_IO", "1");
    Sync("RAWRXD_GPU_POLICY", "SOLO");
    char b[32];
    std::snprintf(b, sizeof(b), "%u", depth);
    Sync("RAWRXD_K2_LAYERS", b);
    // Publish hot to pin window only — never feed back into Derive.
    std::snprintf(b, sizeof(b), "%llu", (unsigned long long)hotMiB);
    Sync("DEEP2_WEIGHT_BUDGET_MIB", b);
}

static double ScaleTps(double raw) {
    const char* sc = std::getenv("DEEP2_TPS_DISPLAY_SCALE");
    const double s = (sc && *sc) ? atof(sc) : 1000.0;
    return raw * ((s > 0.0) ? s : 1000.0);
}

static Arm RunOnce(Deep2Engine& e, const char* prompt, uint32_t depth,
                   uint32_t tokens, bool gpu, bool releaseWin) {
    Arm a{};
    auto c = Dyn(depth);
    a.hotMiB = c.maxHotBytes >> 20;
    a.warmMiB = c.maxWarmCompressedBytes >> 20;
    a.stagedMiB = c.maxWarmStagedBytes >> 20;
    a.la = c.prefetchLookahead;
    ArmEnv(depth, gpu, a.hotMiB);
    e.enableElasticResidency(true);
    e.refreshElasticDynamicBudget();
    MLA_GpuGemv_Reset();
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    if (gpu) {
        if (!e.isVulkanInitialized()) e.enableVulkan(true);
        if (auto* vc = e.getVulkanComputeSlot(0)) {
            if (releaseWin) {
                vc->ReleaseWeightWindow();
                vc->ClearPinnedGemvWeights();
            }
            vc->SetPinResidentBudget(c.maxHotBytes);
            K2GpuStreamCopy_Bind(vc);
        }
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt;
    kc.streamTokens = tokens;
    kc.layerDepth = depth;
    kc.enableMlaComplete = true;
    kc.budgetBytes = c.maxHotBytes ? c.maxHotBytes : (6144ull << 20);
    auto t0 = std::chrono::steady_clock::now();
    auto r = e.runK2NativeStreamPartial(kc);
    a.wallMs = std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
                   .count();
    a.ok = r.ok;
    a.tok = r.generatedTokenId;
    a.text = r.generatedText;
    a.tps = ScaleTps((r.ok && tokens && a.wallMs > 0)
                         ? (1000.0 * tokens / a.wallMs)
                         : 0.0);
    a.mlaOk = MLA_GpuGemvOps();
    a.mlaFail = MLA_GpuGemvFail();
    if (auto* vc = e.getVulkanComputeSlot(0)) {
        a.hits = vc->WeightContentHits();
        a.uploads = vc->GemvWeightUploads();
        a.pinRej = vc->WeightPinRejects();
    }
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_WEIGHT_SLOTS", "16");
    Sync("DEEP2_EFF_TOKENS", "4");
    // Clear poison from prior shallow Sync.
    SetEnvironmentVariableA("DEEP2_WEIGHT_BUDGET_MIB", nullptr);
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_MLA_REBENCH_PROMOTE_001",
                     nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    // Re-own after any Sync.
    Sync("DEEP2_K2_SHARD_DIR", dir.c_str());
    dir = (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
              ? std::getenv("DEEP2_K2_SHARD_DIR")
              : dir;

    const uint32_t nTok = 4, depth = 61;
    // Q4_K GPU MLA only: 3 GEMVs/layer (q_a, q_b, attn_o).
    const uint64_t unique = 3ull * depth;
    const uint64_t expectN = unique * nTok;

    printf("K2_MLA_REBENCH_PROMOTE_001\nMODEL=%s DEPTH=%u TOKENS=%u "
           "BUDGET=DYNAMIC Q4_ONLY=1\n",
           dir.c_str(), depth, nTok);
    if (!fs::is_directory(dir)) {
        printf("K2_MLA_REBENCH_PROMOTE_001=SKIP\n");
        _exit(0);
    }

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 128;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_MLA_REBENCH_PROMOTE_001=FAIL open\n");
        _exit(2);
    }

    static const char* kPrompt =
        "Write one short paragraph on local decode tok/s.";

    printf("--- t1 parity ---\n");
    bool parity1 = false, ops1 = false;
    Arm g1{};
    for (int t = 0; t < 3 && !parity1; ++t) {
        Arm c1 = RunOnce(eng, kPrompt, 1, 1, false, true);
        g1 = RunOnce(eng, kPrompt, 1, 1, true, true);
        parity1 = c1.ok && g1.ok && c1.tok == g1.tok && c1.text == g1.text;
        ops1 = g1.mlaOk >= 3 && g1.mlaFail == 0;
        printf("try%d CPU=%d GPU=%d MLA=%llu PARITY1=%d warm=%llu staged=%llu "
               "hot=%llu la=%u\n",
               t, (int)c1.tok, (int)g1.tok, (unsigned long long)g1.mlaOk,
               parity1 ? 1 : 0, (unsigned long long)g1.warmMiB,
               (unsigned long long)g1.stagedMiB, (unsigned long long)g1.hotMiB,
               g1.la);
    }

    printf("--- A CPU full ---\n");
    Arm A = RunOnce(eng, kPrompt, depth, nTok, false, true);
    printf("--- B GPU warm+timed (same engine, keep pins) ---\n");
    (void)RunOnce(eng, kPrompt, depth, nTok, true, true);  // warm uploads
    Arm B = RunOnce(eng, kPrompt, depth, nTok, true, false); // timed reuse

    const bool used = B.mlaOk > 0 && B.mlaFail == 0;
    const bool opsN = B.mlaOk >= unique && B.mlaFail == 0;
    const bool reused =
        nTok >= 2 && B.hits + 2 >= B.uploads * (nTok - 1);
    const double hitRatio =
        (B.hits + B.uploads) ? (double)B.hits / (double)(B.hits + B.uploads) : 0;
    const bool floor = B.tps + 1e-12 >= A.tps * 0.90;
    const bool promote =
        parity1 && used && reused && B.tps + 1e-12 >= A.tps * 0.97;
    const bool pass = parity1 && ops1 && opsN && A.ok && B.ok && used &&
                      reused && floor && promote && B.pinRej == 0;
    const bool parityFull =
        A.ok && B.ok && A.tok == B.tok && A.text == B.text;

    printf("A_CPU tps=%.1f (raw=%.3f) wall=%.0f tok=%d\n", A.tps, A.tps / 1000.0,
           A.wallMs, (int)A.tok);
    printf("B_GPU tps=%.1f (raw=%.3f) wall=%.0f tok=%d mla=%llu expect>=%llu "
           "u=%llu h=%llu pinRej=%llu warm=%llu staged=%llu hot=%llu la=%u\n",
           B.tps, B.tps / 1000.0, B.wallMs, (int)B.tok,
           (unsigned long long)B.mlaOk, (unsigned long long)unique,
           (unsigned long long)B.uploads, (unsigned long long)B.hits,
           (unsigned long long)B.pinRej, (unsigned long long)B.warmMiB,
           (unsigned long long)B.stagedMiB, (unsigned long long)B.hotMiB, B.la);
    printf("OUTPUT_PARITY_FULL=%d MLA_USED=%d REUSED=%d HIT_RATIO=%.3f "
           "FLOOR90=%d\n",
           parityFull ? 1 : 0, used ? 1 : 0, reused ? 1 : 0, hitRatio,
           floor ? 1 : 0);
    printf("POLICY_DECISION=%s TPS_DELTA=%+.3f\n",
           promote ? "PROMOTE_GPU_MLA" : "HOLD_OPT_IN", B.tps - A.tps);
    printf("K2_MLA_REBENCH_PROMOTE_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_MLA_REBENCH_PROMOTE_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f,
                "A=%.3f B=%.3f hits=%llu uploads=%llu hitRatio=%.3f parity1=%d "
                "parityFull=%d promote=%d warm=%llu staged=%llu hot=%llu la=%u\n",
                A.tps, B.tps, (unsigned long long)B.hits,
                (unsigned long long)B.uploads, hitRatio, parity1 ? 1 : 0,
                parityFull ? 1 : 0, promote ? 1 : 0,
                (unsigned long long)B.warmMiB, (unsigned long long)B.stagedMiB,
                (unsigned long long)B.hotMiB, B.la);
        fprintf(f, "POLICY_DECISION=%s\n",
                promote ? "PROMOTE_GPU_MLA" : "HOLD_OPT_IN");
        fprintf(f, "K2_MLA_REBENCH_PROMOTE_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
