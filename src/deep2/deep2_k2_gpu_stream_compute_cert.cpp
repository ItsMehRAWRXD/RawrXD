// deep2_k2_gpu_stream_compute_cert.cpp — K2_GPU_STREAM_COMPUTE_001
// Streamed K2 Q4_K weight → vkCmdCopy → real packed GEMV with CPU parity.
#include "Deep2Engine.h"
#include "GpuTransferCounters.hpp"
#include "K2ShardIo.hpp"
#include "QuantKernelRegistry.hpp"
#include "StreamTransferCounters.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

static bool LoadRef(const GlobalTensorIndex& idx, const char* name,
                    std::vector<uint8_t>& out, GlobalTensorRef& ref) {
    auto opt = idx.Find(name);
    if (!opt) return false;
    ref = *opt;
    out.resize(ref.byteSize);
    const std::string path = idx.ShardPath(ref.shardId).string();
    if (K2ShardIo_Read(path, ref.fileOffset, out.data(), ref.byteSize)) return true;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg((std::streamoff)ref.fileOffset);
    f.read(reinterpret_cast<char*>(out.data()), (std::streamsize)ref.byteSize);
    return (size_t)f.gcount() == ref.byteSize;
}

static bool DimsOk(const GlobalTensorRef& ref, uint32_t& rows, uint32_t& cols) {
    if (ref.nDims < 2 || ref.shape.size() < 2) return false;
    const uint64_t ne0 = ref.shape[0], ne1 = ref.shape[1];
    constexpr uint64_t kBlk = 144; // block_q4_K
    auto fits = [&](uint64_t r, uint64_t c) -> bool {
        if (!r || !c || (c % 256) != 0) return false;
        return ref.byteSize == r * (c / 256) * kBlk;
    };
    if (fits(ne1, ne0)) { rows = (uint32_t)ne1; cols = (uint32_t)ne0; return true; }
    if (fits(ne0, ne1)) { rows = (uint32_t)ne0; cols = (uint32_t)ne1; return true; }
    return false;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_GPU_STREAM_COMPUTE_001", nullptr);
    printf("K2_GPU_STREAM_COMPUTE_001\nMODEL=%s\n", dir);
    if (!fs::is_directory(dir)) {
        printf("K2_GPU_STREAM_COMPUTE_001=SKIP\n"); return 0;
    }

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_GPU_STREAM_COMPUTE_001=FAIL open\n"); return 2;
    }
    eng.enableVulkan(true);
    auto* vc = eng.getVulkanComputeSlot(0);
    const auto* index = eng.k2TensorIndex();
    if (!vc || !index) {
        printf("K2_GPU_STREAM_COMPUTE_001=FAIL vulkan/index\n"); return 2;
    }

    GlobalTensorRef ref{};
    std::vector<uint8_t> packed;
    static const char* kName = "blk.0.attn_q_a.weight";
    if (!LoadRef(*index, kName, packed, ref) || ref.ggmlType != 12) {
        printf("K2_GPU_STREAM_COMPUTE_001=FAIL load %s type=%u\n",
               kName, ref.ggmlType);
        return 2;
    }
    uint32_t rows = 0, cols = 0;
    if (!DimsOk(ref, rows, cols)) {
        printf("K2_GPU_STREAM_COMPUTE_001=FAIL dims bytes=%llu\n",
               (unsigned long long)ref.byteSize);
        return 2;
    }
    printf("TENSOR=%s rows=%u cols=%u bytes=%llu\n", kName, rows, cols,
           (unsigned long long)packed.size());

    StreamTransfer_Reset();
    GpuTransfer_Reset();
    std::vector<float> x(cols), yCpu(rows), yGpu(rows);
    for (uint32_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);

    auto gemv = QuantKernelRegistry::Instance().GetGEMV(12);
    if (!gemv) { printf("K2_GPU_STREAM_COMPUTE_001=FAIL no CPU GEMV\n"); return 2; }
    gemv(packed.data(), x.data(), yCpu.data(), rows, cols);

    const bool gpuOk = vc->DispatchGEMVPacked(packed.data(), packed.size(),
                                              x.data(), yGpu.data(), rows, cols);
    double maxAbs = 0, ss = 0;
    if (gpuOk) {
        for (uint32_t r = 0; r < rows; ++r) {
            double d = std::fabs((double)yGpu[r] - (double)yCpu[r]);
            if (d > maxAbs) maxAbs = d;
            ss += d * d;
        }
    }
    const double rms = rows ? std::sqrt(ss / (double)rows) : 0.0;
    auto g = GpuTransfer_Snapshot();
    GpuTransfer_Emit(stdout);
    printf("GPU_OK=%d MAX_ABS=%.6g RMS=%.6g\n", gpuOk ? 1 : 0, maxAbs, rms);

    const bool moved = g.copyBytes > 0 && g.copyOps > 0;
    const bool parity = gpuOk && maxAbs < 1e-2 && rms < 1e-3;
    const bool pass = moved && parity;
    printf("GPU_TRANSFER_BOUNDARY=vkCmdCopyBuffer\n");
    printf("K2_GPU_STREAM_COMPUTE_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_GPU_STREAM_COMPUTE_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "tensor=%s rows=%u cols=%u gpuOk=%d moved=%d maxAbs=%.6g rms=%.6g\n",
                kName, rows, cols, gpuOk ? 1 : 0, moved ? 1 : 0, maxAbs, rms);
        fprintf(f, "GPU_COPY_OPS=%llu GPU_COPY_BYTES=%llu\n",
                (unsigned long long)g.copyOps, (unsigned long long)g.copyBytes);
        fprintf(f, "K2_GPU_STREAM_COMPUTE_001=%s\n", pass ? "PASS" : "FAIL");
        fprintf(f, "NOTE=Streamed K2 Q4_K weight used for real packed GEMV; "
                "MLA live-path substitution is next.\n");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
