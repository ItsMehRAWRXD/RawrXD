// deep2_gpu_transfer_counter_cert.cpp — GPU_TRANSFER_COUNTER_001
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "StreamTransferCounters.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\GPU_TRANSFER_COUNTER_001", nullptr);
    printf("GPU_TRANSFER_COUNTER_001\nMODEL=%s\n", model);

    StreamTransfer_Reset();
    GpuTransfer_Reset();
    Deep2Engine engine;
    if (!engine.loadModel(model)) {
        printf("GPU_TRANSFER_COUNTER_001=FAIL load\n"); return 2;
    }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 256; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!engine.initialize(cfg)) {
        printf("GPU_TRANSFER_COUNTER_001=FAIL init\n"); return 2;
    }
    engine.enableVulkan(true);

    // Force at least one host→device vkCmdCopyBuffer via GEMV upload path.
    auto* vc = engine.getVulkanComputeSlot(0);
    bool gemvOk = false;
    if (vc && !mw.layers.empty() && mw.layers[0].wq.data) {
        const auto& wt = mw.layers[0].wq;
        const uint32_t rows = (uint32_t)(wt.rows ? wt.rows : 64);
        const uint32_t cols = (uint32_t)(wt.cols ? wt.cols : 64);
        const size_t nW = (size_t)rows * cols;
        std::vector<float> W(nW, 0.01f), x(cols, 1.f), y(rows, 0.f);
        gemvOk = vc->DispatchGEMV(W.data(), x.data(), y.data(), rows, cols, 0x67C001ULL);
    }

    GenerationOptions opts{};
    opts.maxTokens = 4; opts.temperature = 0.0f; opts.topK = 1; opts.seed = 7;
    size_t nTok = 0;
    engine.generateStream("hi", opts, [&](int32_t, const std::string&) -> bool {
        ++nTok; GpuTransfer_RecordToken(); return true;
    });

    auto g = GpuTransfer_Snapshot();
    auto s = StreamTransfer_Snapshot();
    printf("GEMV_UPLOAD_PATH=%d\nGEN_TOKENS=%zu\n", gemvOk ? 1 : 0, nTok);
    GpuTransfer_Emit(stdout);
    printf("STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.bytesToGpu);
    printf("STREAM_GPU_UPLOAD_OPS=%llu\n", (unsigned long long)s.gpuUploadOps);

    const bool pathLive = gemvOk || nTok > 0;
    const bool moved = g.copyBytes > 0 && g.copyOps > 0;
    const bool streamTied = s.bytesToGpu == g.copyBytes && s.gpuUploadOps == g.copyOps;
    const bool pass = pathLive && moved && streamTied;
    printf("GPU_TRANSFER_BOUNDARY=vkCmdCopyBuffer\n");
    printf("GPU_TRANSFER_COUNTER_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\GPU_TRANSFER_COUNTER_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "GPU_TRANSFER_COUNTER_001=%s\n", pass ? "PASS" : "FAIL");
        GpuTransfer_Emit(f);
        fprintf(f, "STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.bytesToGpu);
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
