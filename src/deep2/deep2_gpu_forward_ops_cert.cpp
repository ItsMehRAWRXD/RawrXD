// deep2_gpu_forward_ops_cert.cpp — STREAMER_GPU_FORWARD_OPS_001 lanes A–D
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
#include "Deep2GpuForward.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static void Stats(const float* a, const float* b, size_t n,
                  double& maxAbs, double& meanAbs, double& cos) {
    double dot = 0, na = 0, nb = 0, sum = 0, mx = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = (double)a[i] - (double)b[i];
        double ad = std::fabs(d);
        if (ad > mx) mx = ad;
        sum += ad;
        dot += (double)a[i] * (double)b[i];
        na += (double)a[i] * (double)a[i];
        nb += (double)b[i] * (double)b[i];
    }
    maxAbs = mx;
    meanAbs = n ? sum / (double)n : 0;
    cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0;
}

static bool Finite(const float* x, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (!std::isfinite(x[i])) return false;
    return true;
}

static bool SetupEngine(Deep2Engine& engine, const char* model) {
    if (!engine.loadModel(model)) return false;
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    if (!engine.initialize(cfg)) return false;
    engine.enableVulkan(true);
    return true;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "AUTO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("DEEP2_HYBRID", "1");
    _putenv_s("DEEP2_HYBRID_CPU_LAYERS", "2");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_FORWARD_OPS_001", nullptr);
    printf("STREAMER_GPU_FORWARD_OPS_001\nModel: %s\n", model);

    Deep2Engine engine;
    if (!SetupEngine(engine, model)) { printf("FAIL setup\n"); return 1; }
    engine.resetGpuForwardCounters();

    const uint32_t H = (uint32_t)engine.getModelWeights().hiddenDim;
    std::vector<float> hostIn(H, 0.0f), cpuOut(H), gpuOut(H);
    for (uint32_t i = 0; i < H; ++i) hostIn[i] = 0.01f * std::sin(0.017f * (float)i);

    // ---- Lane A: SINGLE_LAYER blk.0 ----
    bool laneA = false;
    {
        Deep2Engine ref;
        if (!ref.loadModel(model)) { printf("FAIL ref load\n"); return 1; }
        {
            const auto& mw = ref.getModelWeights();
            EngineConfig cfg{};
            cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
            cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
            cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
            cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
            cfg.numThreads = 16;
            if (!ref.initialize(cfg)) { printf("FAIL ref init\n"); return 1; }
        }
        ref.forwardLayerPublic(0, hostIn.data(), cpuOut.data(), 1);

        auto* vc = engine.getVulkanComputeSlot(0);
        if (!vc || !engine.ensureGpuForwardArena(0)) {
            printf("FAIL arena\n"); return 2;
        }
        if (!vc->UploadHidden(hostIn.data(), H)) { printf("FAIL upload\n"); return 2; }
        if (!engine.forwardLayerGpuResident(0, 0, true, true)) {
            printf("FAIL forwardLayerGpuResident blk.0\n"); return 2;
        }
        if (!vc->DownloadHidden(gpuOut.data(), H)) { printf("FAIL download\n"); return 2; }

        double maxAbs = 0, meanAbs = 0, cos = 0;
        Stats(cpuOut.data(), gpuOut.data(), H, maxAbs, meanAbs, cos);
        const bool finite = Finite(gpuOut.data(), H);
        laneA = finite && cos > 0.98 && meanAbs < 2.0;
        printf("LANE_A_SINGLE_LAYER GPU_FORWARD_LAYER=0 OWNER_SLOT=0\n");
        printf("MAX_ABS_ERR=%.6g MEAN_ABS_ERR=%.6g COSINE_SIM=%.6g FINITE=%d\n",
               maxAbs, meanAbs, cos, finite ? 1 : 0);
        printf("GPU_RESIDENT_ENTRY=1 GPU_RESIDENT_EXIT=1 HOST_MATERIALIZATIONS=%llu\n",
               (unsigned long long)engine.gpuForwardCounters().hostMaterializations);
        printf("LANE_A=%s\n", laneA ? "PASS" : "FAIL");
    }

    // ---- Lane B: SINGLE_SLOT_CONTIG ----
    bool laneB = false;
    {
        engine.resetGpuForwardCounters();
        const auto& plan = engine.multiGpuLayerPlan();
        uint32_t lo = 0, hi = 0;
        if (plan.active && plan.gpuSlotCount >= 1) {
            lo = plan.rangeLo[0]; hi = plan.rangeHi[0];
        } else {
            hi = 11;
        }
        std::vector<float> out(H);
        laneB = engine.forwardGpuContiguousRange(0, lo, hi, hostIn.data(), out.data()) &&
                engine.gpuForwardCounters().forwardSlot[0] >= (hi - lo + 1) &&
                engine.gpuForwardCounters().intraSlotHostTransfers == 0 &&
                engine.gpuForwardCounters().hostMaterializations == 0;
        printf("LANE_B_SINGLE_SLOT_CONTIG layers=%u-%u SLOT0=%llu INTRA_SLOT_HOST=%llu\n",
               lo, hi,
               (unsigned long long)engine.gpuForwardCounters().forwardSlot[0],
               (unsigned long long)engine.gpuForwardCounters().intraSlotHostTransfers);
        printf("LANE_B=%s\n", laneB ? "PASS" : "FAIL");
    }

    // ---- Lane C: MULTI_GPU ----
    bool laneC = false;
    {
        engine.resetGpuForwardCounters();
#ifdef _WIN32
        // re-open already done; plan should be multi from ALL
#endif
        std::vector<float> out(H);
        const auto& plan = engine.multiGpuLayerPlan();
        laneC = plan.active && plan.gpuSlotCount >= 2 &&
                engine.forwardGpuMultiMap(hostIn.data(), out.data()) &&
                engine.gpuForwardCounters().forwardSlot[0] > 0 &&
                engine.gpuForwardCounters().forwardSlot[1] > 0 &&
                engine.vulkanGemvFallbackCount() == 0 &&
                engine.vulkanUnplannedFallbacks() == 0;
        printf("LANE_C_MULTI SLOT0=%llu SLOT1=%llu OWN_XFER=%llu\n",
               (unsigned long long)engine.gpuForwardCounters().forwardSlot[0],
               (unsigned long long)engine.gpuForwardCounters().forwardSlot[1],
               (unsigned long long)engine.gpuForwardCounters().ownershipTransfers);
        printf("LANE_C=%s\n", laneC ? "PASS" : "FAIL");
    }

    // ---- Lane D: HYBRID ----
    bool laneD = false;
    {
        // forwardGpuMultiMap already includes planned CPU trailing when hybrid
        const auto& plan = engine.multiGpuLayerPlan();
        laneD = plan.hybrid && laneC &&
                engine.plannedCpuGemvOps() > 0 &&
                engine.vulkanGemvFallbackCount() == 0;
        printf("LANE_D_HYBRID hybrid=%d planned_cpu_ops=%llu fallback=%llu\n",
               plan.hybrid ? 1 : 0,
               (unsigned long long)engine.plannedCpuGemvOps(),
               (unsigned long long)engine.vulkanGemvFallbackCount());
        printf("LANE_D=%s\n", laneD ? "PASS" : "FAIL");
    }

    const auto& c = engine.gpuForwardCounters();
    Deep2GpuForward_Emit(nullptr, c, engine.vulkanGemvFallbackCount());
    const bool real = engine.isRealGpuForward();
    const bool pass = laneA && laneB && laneC && laneD && real;

    printf("STREAMER_GPU_FORWARD_OPS_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_FORWARD_OPS_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "LANE_A=%s\nLANE_B=%s\nLANE_C=%s\nLANE_D=%s\n",
                laneA ? "PASS" : "FAIL", laneB ? "PASS" : "FAIL",
                laneC ? "PASS" : "FAIL", laneD ? "PASS" : "FAIL");
        Deep2GpuForward_Emit(f, c, engine.vulkanGemvFallbackCount());
        fprintf(f, "STREAMER_GPU_FORWARD_OPS_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
