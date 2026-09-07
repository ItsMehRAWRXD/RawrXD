// deep2_gpu_numeric_parity_cert.cpp — STREAMER_GPU_NUMERIC_PARITY_001
#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"
#include <cmath>
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

static void Stats(const float* a, const float* b, size_t n, double& mx, double& rms) {
    double s = 0, m = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = (double)a[i] - (double)b[i];
        if (std::fabs(d) > m) m = std::fabs(d);
        s += d * d;
    }
    mx = m; rms = n ? std::sqrt(s / (double)n) : 0;
}

static bool Setup(Deep2Engine& e, const char* model) {
    if (!e.loadModel(model)) return false;
    const auto& mw = e.getModelWeights();
    EngineConfig c{};
    c.hiddenDim = mw.hiddenDim; c.numLayers = mw.numLayers; c.numHeads = mw.numHeads;
    c.numKVHeads = mw.numKVHeads; c.headDim = mw.headDim; c.vocabSize = mw.vocabSize;
    c.maxSeqLen = 128; c.useKVCache = true; c.useThreadPool = true; c.numThreads = 8;
    return e.initialize(c) && (e.enableVulkan(true), e.isVulkanEnabled());
}

static bool Report(const char* name, const float* cpu, const float* gpu, size_t n, double thr) {
    double mx = 0, rms = 0;
    Stats(cpu, gpu, n, mx, rms);
    const bool ok = mx < thr && rms < thr;
    printf("%s MAX_ABS=%.6g RMS=%.6g %s\n", name, mx, rms, ok ? "PASS" : "FAIL");
    return ok;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_NUMERIC_PARITY_001", nullptr);
    printf("STREAMER_GPU_NUMERIC_PARITY_001\nModel: %s\n", model);
    Deep2Engine e;
    if (!Setup(e, model)) { printf("FAIL setup\n"); return 1; }
    auto* vc = e.getVulkanComputeSlot(0);
    if (!vc || !e.ensureGpuForwardArena(0)) { printf("FAIL arena\n"); return 2; }
    const auto& mw = e.getModelWeights();
    const uint32_t H = (uint32_t)mw.hiddenDim, hd = (uint32_t)mw.headDim;
    const uint32_t nh = (uint32_t)mw.numHeads, nkv = (uint32_t)mw.numKVHeads;
    std::vector<float> x(H), cpu(H), gpu(H), q(nh * hd), k(nkv * hd), q2, k2;
    for (uint32_t i = 0; i < H; ++i) x[i] = 0.01f * std::sin(0.017f * (float)i);
    bool pass = true;
    e.RMSNormW(mw.layers[0].attnNorm, x.data(), cpu.data(), H, mw.normEps);
    vc->UploadHidden(x.data(), H);
    vc->UploadNormWeight(vc->ArenaAttnW(),
        reinterpret_cast<const float*>(mw.layers[0].attnNorm.data), H);
    vc->DispatchRmsNorm(vc->ArenaHidden(), vc->ArenaAttnW(), vc->ArenaNormed(), H, mw.normEps);
    vc->DownloadBuf(vc->ArenaNormed(), gpu.data(), H);
    pass = Report("RMSNORM", cpu.data(), gpu.data(), H, 2e-3) && pass;
    for (uint32_t i = 0; i < H; ++i) cpu[i] = x[i] + gpu[i];
    vc->UploadBuf(vc->ArenaDown(), gpu.data(), H);
    vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(), vc->ArenaResidual(), H);
    vc->DownloadBuf(vc->ArenaResidual(), gpu.data(), H);
    pass = Report("RESIDUAL", cpu.data(), gpu.data(), H, 1e-5) && pass;
    std::vector<float> gate(256), up(256), ycpu(256), ygpu(256);
    for (int i = 0; i < 256; ++i) { gate[i] = 0.1f * (float)(i - 128); up[i] = 0.02f * (float)i; }
    e.SwiGLU(gate.data(), up.data(), ycpu.data(), 256);
    vc->UploadBuf(vc->ArenaGate(), gate.data(), 256);
    vc->UploadBuf(vc->ArenaUp(), up.data(), 256);
    vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), 256);
    vc->DownloadBuf(vc->ArenaFFNAct(), ygpu.data(), 256);
    pass = Report("SWIGLU", ycpu.data(), ygpu.data(), 256, 1e-5) && pass;
    q.assign(nh * hd, 0); k.assign(nkv * hd, 0); q2 = q; k2 = k;
    for (uint32_t i = 0; i < nh * hd; ++i) q[i] = 0.01f * std::sin(0.03f * (float)i);
    for (uint32_t i = 0; i < nkv * hd; ++i) k[i] = 0.01f * std::cos(0.04f * (float)i);
    q2 = q; k2 = k;
    e.applyRoPE(q2.data(), k2.data(), hd, nh, nkv, 3, mw.ropeTheta, 1.0f);
    vc->UploadBuf(vc->ArenaQ(), q.data(), nh * hd);
    vc->UploadBuf(vc->ArenaK(), k.data(), nkv * hd);
    vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), hd, nh, nkv, 3, mw.ropeTheta);
    std::vector<float> qg(nh * hd), kg(nkv * hd);
    vc->DownloadBuf(vc->ArenaQ(), qg.data(), nh * hd);
    vc->DownloadBuf(vc->ArenaK(), kg.data(), nkv * hd);
    pass = Report("ROPE_Q", q2.data(), qg.data(), nh * hd, 2e-4) && pass;
    pass = Report("ROPE_K", k2.data(), kg.data(), nkv * hd, 2e-4) && pass;
    printf("STREAMER_GPU_NUMERIC_PARITY_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_NUMERIC_PARITY_001\\GATE_STATUS.txt", "w");
    if (f) { fprintf(f, "STREAMER_GPU_NUMERIC_PARITY_001=%s\n", pass ? "PASS" : "FAIL"); fclose(f); }
    return pass ? 0 : 2;
}
