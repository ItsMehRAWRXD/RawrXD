// deep2_k2_gpu_mla_full_cert.cpp — K2_GPU_MLA_FULL_001
// Full live MLA Q4_K: Q/KV + batched K/V expand + O; CPU/GPU token parity.
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
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
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

struct RunOut {
    bool ok = false;
    int32_t genId = -1;
    std::string text;
    uint64_t mlaOps = 0, mlaFail = 0;
};

static RunOut RunOnce(Deep2Engine& e, const char* prompt, uint32_t depth,
                      uint32_t tokens, bool gpuMla) {
    RunOut o{};
#ifdef _WIN32
    _putenv_s("RAWRXD_K2_LAYERS", std::to_string(depth).c_str());
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", gpuMla ? "1" : "0");
    _putenv_s("DEEP2_K2_GPU_MLA", gpuMla ? "1" : "0");
#endif
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    K2GpuStreamCopy_Reset();
    MLA_GpuGemv_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = tokens; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto r = e.runK2NativeStreamPartial(kc);
    o.ok = r.ok; o.genId = r.generatedTokenId; o.text = r.generatedText;
    o.mlaOps = MLA_GpuGemvOps();
    o.mlaFail = MLA_GpuGemvFail();
    return o;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "4");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    _putenv_s("DEEP2_WEIGHT_OVERLAP", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_001", nullptr);
    printf("K2_GPU_MLA_FULL_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_GPU_MLA_FULL_001=SKIP\n"); return 0;
    }
    static const char* kPrompt = "Say hello in one short sentence.";
    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_GPU_MLA_FULL_001=FAIL open\n"); return 2;
    }

    printf("\n--- CPU full MLA (d=1 t=1) ---\n");
    RunOut cpu = RunOnce(eng, kPrompt, 1, 1, false);
    printf("OK=%d GEN=%d MLA_OPS=%llu\n", cpu.ok ? 1 : 0, (int)cpu.genId,
           (unsigned long long)cpu.mlaOps);

    printf("\n--- GPU full MLA (d=1 t=1) ---\n");
    RunOut gpu = RunOnce(eng, kPrompt, 1, 1, true);
    printf("OK=%d GEN=%d MLA_OPS=%llu MLA_FAIL=%llu\n",
           gpu.ok ? 1 : 0, (int)gpu.genId,
           (unsigned long long)gpu.mlaOps, (unsigned long long)gpu.mlaFail);
    K2GpuStreamCopy_Emit(stdout);
    GpuTransfer_Emit(stdout);

    // Kimi Q4_K_M: q_a/q_b/O=Q4_K; kv_a/k_b/v_b=Q8_0 → 6 GPU GEMVs/layer.
    const bool usedGpu = gpu.mlaOps >= 6 && gpu.mlaFail == 0;
    const bool parity = cpu.ok && gpu.ok && cpu.genId == gpu.genId &&
                        cpu.text == gpu.text;
    const bool pass = usedGpu && parity;
    printf("MLA_GPU_FULL=%u OPS=%llu OUTPUT_PARITY=%u\n",
           usedGpu ? 1u : 0u, (unsigned long long)gpu.mlaOps,
           parity ? 1u : 0u);
    printf("K2_GPU_MLA_FULL_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_MLA_FULL_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "cpu_gen=%d gpu_gen=%d mla_ops=%llu mla_fail=%llu\n",
                (int)cpu.genId, (int)gpu.genId,
                (unsigned long long)gpu.mlaOps,
                (unsigned long long)gpu.mlaFail);
        fprintf(f, "parity=%d usedGpu=%d\n", parity ? 1 : 0, usedGpu ? 1 : 0);
        fprintf(f, "K2_GPU_MLA_FULL_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=Batched K/V 3D expand + Q/KV/O via MLA_GemvQ4K.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
