// deep2_gpu_q6k_gemv_cert.cpp — STREAMER_GPU_Q6K_GEMV_001
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include <chrono>
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

static void DeqQ6k(const uint8_t* blk, float* y) {
    uint16_t d16; std::memcpy(&d16, blk + 208, 2);
    uint32_t s = (uint32_t)(d16 & 0x8000) << 16, e = (d16 >> 10) & 31, f = d16 & 0x3FF;
    uint32_t bits;
    if (e == 0) {
        if (f == 0) bits = s;
        else {
            uint32_t ee = 1, ff = f;
            while ((ff & 0x0400) == 0) { ff <<= 1; ++ee; }
            ff &= 0x03FF;
            bits = s | ((127 - 15 + 2 - ee) << 23) | (ff << 13);
        }
    } else if (e == 31) bits = s | 0x7F800000 | (f << 13);
    else bits = s | ((e + 127 - 15) << 23) | (f << 13);
    float d; std::memcpy(&d, &bits, 4);
    const uint8_t* ql = blk; const uint8_t* qh = blk + 128; const int8_t* sc = (const int8_t*)(blk + 192);
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            int is = l / 16;
            int q1 = (int)((ql[l] & 15) | ((qh[l] & 3) << 4)) - 32;
            int q2 = (int)((ql[l + 32] & 15) | (((qh[l] >> 2) & 3) << 4)) - 32;
            int q3 = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            int q4 = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            y[l] = d * (float)sc[is] * (float)q1;
            y[l + 32] = d * (float)sc[is + 2] * (float)q2;
            y[l + 64] = d * (float)sc[is + 4] * (float)q3;
            y[l + 96] = d * (float)sc[is + 6] * (float)q4;
        }
        y += 128; ql += 64; qh += 32; sc += 8;
    }
}

static size_t RunGen(Deep2Engine& e, const char* p, int n) {
    GenerationOptions o{}; o.maxTokens = n; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t k = 0;
    e.generateStream(p, o, [&](int32_t, const std::string&) -> bool { ++k; return true; });
    return k;
}

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
    printf("STREAMER_GPU_Q6K_GEMV_001\nModel: %s\n", model);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_Q6K_GEMV_001", nullptr);
    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL load\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 16;
    if (!engine.initialize(cfg)) { printf("FAIL init\n"); return 1; }
    engine.enableVulkan(true); engine.enableMedusa(false);
    const WeightTensor* wt = nullptr;
    auto pick = [&](const WeightTensor& w) {
        if (w.type != (int)GGMLType::GGML_TYPE_Q6_K || !w.data) return;
        if (!wt || w.rows * w.cols < wt->rows * wt->cols) wt = &w;
    };
    for (const auto& L : mw.layers) {
        pick(L.wq); pick(L.wk); pick(L.wv); pick(L.wo); pick(L.attnO);
        pick(L.wGate); pick(L.wUp); pick(L.wDown);
    }
    pick(mw.lmHead);
    if (!wt) { printf("FAIL no Q6_K tensor\n"); return 2; }
    auto* vc = engine.getVulkanComputeSlot(0);
    const size_t rows = wt->rows, cols = wt->cols;
    std::vector<float> W(rows * cols), x(cols), yCpu(rows), yGpu(rows);
    size_t nb = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r)
        for (size_t b = 0; b < nb; ++b)
            DeqQ6k((const uint8_t*)wt->data + (r * nb + b) * 210, W.data() + r * cols + b * 256);
    for (size_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);
    for (size_t r = 0; r < rows; ++r) {
        double s = 0; for (size_t c = 0; c < cols; ++c) s += (double)W[r * cols + c] * (double)x[c];
        yCpu[r] = (float)s;
    }
    if (!vc || !vc->DispatchGEMVQuant(14, wt->data, wt->sizeBytes, x.data(), yGpu.data(),
                                      (uint32_t)rows, (uint32_t)cols)) {
        printf("FAIL dispatch\n"); return 3;
    }
    double maxAbs = 0, ss = 0;
    for (size_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yGpu[r] - (double)yCpu[r]);
        if (d > maxAbs) maxAbs = d; ss += d * d;
    }
    double rms = std::sqrt(ss / (double)rows);
    RunGen(engine, "hi", 1);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = RunGen(engine, "hello", 8);
    auto t1 = std::chrono::steady_clock::now();
    double tps = n / std::chrono::duration<double>(t1 - t0).count();
    const auto& c = engine.gpuForwardCounters();
    uint64_t q6 = vc->Q6kPackedOps();
    const bool pass = n > 0 && maxAbs < 1e-2 && rms < 1e-3 && q6 > 0 &&
        c.cpuF32Expands == 0 && c.liveDecodeResidentTokens > 0 &&
        engine.vulkanGemvFallbackCount() == 0 && vc->WeightHotpathCreateBuf() == 0 &&
        vc->WeightResidentGrowthAfterInit() == 0;
    printf("Q6K_GEMV_MAX_ABS=%.6g RMS=%.6g y0 cpu=%.6g gpu=%.6g\n",
           maxAbs, rms, yCpu[0], yGpu[0]);
    printf("DEEP2_GPU_Q6K_PACKED_OPS=%llu\n", (unsigned long long)q6);
    printf("DEEP2_GPU_CPU_F32_EXPANDS=%llu\n", (unsigned long long)c.cpuF32Expands);
    printf("warm_solo8_e2e_tok_s=%.3f\n", tps);
    printf("STREAMER_GPU_Q6K_GEMV_001=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_Q6K_GEMV_001\\GATE_STATUS.txt", "w");
    if (f) { fprintf(f, "STREAMER_GPU_Q6K_GEMV_001=%s\n", pass ? "PASS" : "FAIL"); fclose(f); }
    _exit(pass ? 0 : 2);
}
