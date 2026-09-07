// deep2_k2_gpu_stream_copy_cert.cpp — K2_GPU_STREAM_COPY_001
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2GpuStreamCopy.hpp"
#include "StreamTransferCounters.hpp"
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

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("DEEP2_K2_GPU_STREAM_COPY", "1");
    _putenv_s("DEEP2_LIVE_POLICY", "OFF");
    _putenv_s("DEEP2_LIVE_PATH", "0");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_STREAM_COPY_001", nullptr);
    printf("K2_GPU_STREAM_COPY_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_GPU_STREAM_COPY_001=SKIP\n"); return 0;
    }

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_GPU_STREAM_COPY_001=FAIL open\n"); return 2;
    }

    K2NativeStreamGate::Config kc;
    kc.prompt = "Write one short paragraph on local decode tok/s.";
    kc.streamTokens = 2; kc.layerDepth = 2;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto r = eng.runK2NativeStreamPartial(kc);
    auto g = GpuTransfer_Snapshot();
    auto s = StreamTransfer_Snapshot();
    K2GpuStreamCopy_Emit(stdout);
    GpuTransfer_Emit(stdout);

    const bool bound = K2GpuStreamCopy_Wanted() && eng.getVulkanComputeSlot(0);
    const bool moved = g.copyBytes > 0 && g.copyOps > 0;
    const bool streamTied = s.bytesToGpu == g.copyBytes && s.gpuUploadOps == g.copyOps;
    const bool laneOk = K2GpuStreamCopy_UploadOps() > 0 && K2GpuStreamCopy_FailOps() == 0;
    const bool pass = r.ok && bound && moved && streamTied && laneOk;
    printf("GPU_TRANSFER_BOUNDARY=vkCmdCopyBuffer\n");
    printf("STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.bytesToGpu);
    printf("K2_GPU_STREAM_COPY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_STREAM_COPY_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "ok=%d bound=%d moved=%d streamTied=%d laneOk=%d\n",
                r.ok ? 1 : 0, bound ? 1 : 0, moved ? 1 : 0,
                streamTied ? 1 : 0, laneOk ? 1 : 0);
        fprintf(f, "GPU_COPY_BYTES_TOTAL=%llu\nGPU_COPY_OPS_TOTAL=%llu\n",
                (unsigned long long)g.copyBytes, (unsigned long long)g.copyOps);
        fprintf(f, "K2_GPU_STREAM_COPY_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=K2 stream lane now performs real host→device vkCmdCopy; "
                "overlap is next gate.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
