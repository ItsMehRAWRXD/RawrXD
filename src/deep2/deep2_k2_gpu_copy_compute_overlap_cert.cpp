// deep2_k2_gpu_copy_compute_overlap_cert.cpp — K2_GPU_COPY_COMPUTE_OVERLAP_001
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "StreamTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
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
    uint64_t copyB = 0, waitUs = 0, overlapUs = 0, overlapEv = 0, overlapB = 0;
};

static Arm RunArm(Deep2Engine& eng, const char* prompt, const char* overlap,
                  const char* tag) {
    Arm a{};
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_OVERLAP", overlap);
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "1");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", "1");
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_LIVE_PATH", "0");
#endif
    StreamTransfer_Reset();
    GpuTransfer_Reset();
    K2GpuStreamCopy_Reset();
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = 2; kc.layerDepth = 2;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = eng.runK2NativeStreamPartial(kc);
    a.wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    a.tps = (r.ok && a.wallMs > 0) ? (2000.0 / a.wallMs) : 0.0;
    auto g = GpuTransfer_Snapshot();
    a.copyB = g.copyBytes; a.waitUs = g.waitUs;
    a.overlapUs = g.overlapUs; a.overlapEv = g.overlapEvents;
    a.overlapB = g.overlapBytes;
    a.ok = r.ok && g.copyOps > 0 && K2GpuStreamCopy_FailOps() == 0;
    printf("[%s] ok=%d tps=%.3f wait=%llu overlap=%llu ev=%llu copy=%llu\n",
           tag, a.ok ? 1 : 0, a.tps,
           (unsigned long long)a.waitUs, (unsigned long long)a.overlapUs,
           (unsigned long long)a.overlapEv, (unsigned long long)a.copyB);
    GpuTransfer_Emit(stdout);
    K2GpuStreamCopy_Emit(stdout);
    return a;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "4");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_K2_LAYERS", "2");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_COPY_COMPUTE_OVERLAP_001", nullptr);
    printf("K2_GPU_COPY_COMPUTE_OVERLAP_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_GPU_COPY_COMPUTE_OVERLAP_001=SKIP\n"); return 0;
    }
    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_GPU_COPY_COMPUTE_OVERLAP_001=FAIL open\n"); return 2;
    }
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    Arm A = RunArm(eng, kPrompt, "0", "A_SERIAL");
    Arm B = RunArm(eng, kPrompt, "1", "B_OVERLAP");
    const bool overlapUp = B.overlapUs > 0 && B.overlapEv > 0;
    const bool waitDown = B.waitUs < A.waitUs;
    const bool tpsUp = B.tps > A.tps;
    const bool bytesOk = B.copyB > 0;
    const bool pass = A.ok && B.ok && overlapUp && bytesOk && (waitDown || tpsUp ||
                      B.overlapEv > A.overlapEv);
    printf("A_WAIT_US=%llu B_WAIT_US=%llu\n",
           (unsigned long long)A.waitUs, (unsigned long long)B.waitUs);
    printf("A_OVERLAP_US=%llu B_OVERLAP_US=%llu\n",
           (unsigned long long)A.overlapUs, (unsigned long long)B.overlapUs);
    printf("A_TPS=%.3f B_TPS=%.3f\n", A.tps, B.tps);
    printf("K2_GPU_COPY_COMPUTE_OVERLAP_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_COPY_COMPUTE_OVERLAP_001\\GATE_STATUS.txt",
        "w");
    if (f) {
        fprintf(f, "A_ok=%d B_ok=%d overlapUp=%d waitDown=%d tpsUp=%d\n",
                A.ok, B.ok, overlapUp, waitDown, tpsUp);
        fprintf(f, "A_WAIT=%llu B_WAIT=%llu A_OV=%llu B_OV=%llu B_EV=%llu\n",
                (unsigned long long)A.waitUs, (unsigned long long)B.waitUs,
                (unsigned long long)A.overlapUs, (unsigned long long)B.overlapUs,
                (unsigned long long)B.overlapEv);
        fprintf(f, "K2_GPU_COPY_COMPUTE_OVERLAP_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
