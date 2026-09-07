// deep2_gpu_quant_family_cert.cpp — Q5_K/Q3_K/Q2_K/Q8_0 packed GEMV
#include "Deep2Engine.h"
#include <cmath>
#include <cstdio>
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

static float F16(uint16_t h) {
    uint32_t s = (uint32_t)(h & 0x8000) << 16, e = (h >> 10) & 31, f = h & 0x3FF;
    uint32_t b = (e == 0) ? s : (e == 31 ? (s | 0x7F800000 | (f << 13))
                                         : (s | ((e + 127 - 15) << 23) | (f << 13)));
    float v; std::memcpy(&v, &b, 4); return v;
}
static int I8(uint8_t b) { return (int)b - ((b >= 128) ? 256 : 0); }

static void DeqQ8(const uint8_t* blk, float* y) {
    float d = F16((uint16_t)(blk[0] | (blk[1] << 8)));
    for (int j = 0; j < 32; ++j) y[j] = d * (float)I8(blk[2 + j]);
}
static void ScMin(const uint8_t* scb, uint32_t j, uint32_t& sc, uint32_t& m) {
    if (j < 4) { sc = scb[j] & 63; m = scb[j + 4] & 63; }
    else {
        uint32_t a = scb[j + 4], b = scb[j - 4], c = scb[j];
        sc = (a & 15) | ((b >> 6) << 4); m = (a >> 4) | ((c >> 6) << 4);
    }
}
static void DeqQ5(const uint8_t* blk, float* y) {
    float d = F16((uint16_t)(blk[0] | (blk[1] << 8)));
    float dmin = F16((uint16_t)(blk[2] | (blk[3] << 8)));
    const uint8_t* scb = blk + 4; const uint8_t* qh = blk + 16; const uint8_t* ql = blk + 48;
    uint32_t is = 0, u1 = 1, u2 = 2, elem = 0;
    for (uint32_t p = 0; p < 4; ++p) {
        uint32_t sc0, m0, sc1, m1; ScMin(scb, is, sc0, m0); ScMin(scb, is + 1, sc1, m1);
        float d1 = d * (float)sc0, min1 = dmin * (float)m0;
        float d2 = d * (float)sc1, min2 = dmin * (float)m1;
        for (uint32_t l = 0; l < 32; ++l) {
            uint32_t qv = ql[l], hv = qh[l];
            y[elem + l] = d1 * (float)((qv & 15) + ((hv & u1) ? 16u : 0u)) - min1;
            y[elem + l + 32] = d2 * (float)((qv >> 4) + ((hv & u2) ? 16u : 0u)) - min2;
        }
        ql += 32; elem += 64; is += 2; u1 <<= 2; u2 <<= 2;
    }
}
static void DeqQ3(const uint8_t* blk, float* y) {
    float dall = F16((uint16_t)(blk[108] | (blk[109] << 8)));
    auto u32 = [&](uint32_t o) -> uint32_t {
        return (uint32_t)blk[o] | ((uint32_t)blk[o + 1] << 8) |
               ((uint32_t)blk[o + 2] << 16) | ((uint32_t)blk[o + 3] << 24);
    };
    uint32_t a0 = u32(96), a1 = u32(100), tmp = u32(104);
    uint32_t k1 = 0x03030303u, k2 = 0x0f0f0f0fu;
    uint32_t s2 = ((a0 >> 4) & k2) | (((tmp >> 4) & k1) << 4);
    uint32_t s3 = ((a1 >> 4) & k2) | (((tmp >> 6) & k1) << 4);
    uint32_t s0 = (a0 & k2) | (((tmp >> 0) & k1) << 4);
    uint32_t s1 = (a1 & k2) | (((tmp >> 2) & k1) << 4);
    int sc[16];
    auto spl = [&](uint32_t s, int i) {
        sc[i] = I8((uint8_t)(s & 255)); sc[i + 1] = I8((uint8_t)((s >> 8) & 255));
        sc[i + 2] = I8((uint8_t)((s >> 16) & 255)); sc[i + 3] = I8((uint8_t)(s >> 24));
    };
    spl(s0, 0); spl(s1, 4); spl(s2, 8); spl(s3, 12);
    const uint8_t* q = blk + 32; const uint8_t* hm = blk;
    uint32_t isv = 0, m = 1, elem = 0;
    for (uint32_t n = 0; n < 2; ++n) {
        uint32_t shift = 0;
        for (uint32_t j = 0; j < 4; ++j) {
            float dl = dall * (float)(sc[isv++] - 32);
            for (uint32_t l = 0; l < 16; ++l) {
                int qq = (int)((q[l] >> shift) & 3u);
                qq -= ((hm[l] & m) != 0) ? 0 : 4;
                y[elem + l] = dl * (float)qq;
            }
            elem += 16;
            dl = dall * (float)(sc[isv++] - 32);
            for (uint32_t l = 0; l < 16; ++l) {
                int qq = (int)((q[l + 16] >> shift) & 3u);
                qq -= ((hm[l + 16] & m) != 0) ? 0 : 4;
                y[elem + l] = dl * (float)qq;
            }
            elem += 16; shift += 2; m <<= 1;
        }
        q += 32;
    }
}
static void DeqQ2(const uint8_t* blk, float* y) {
    float d = F16((uint16_t)(blk[80] | (blk[81] << 8)));
    float dmin = F16((uint16_t)(blk[82] | (blk[83] << 8)));
    const uint8_t* q = blk + 16; uint32_t is = 0, elem = 0;
    for (uint32_t n = 0; n < 2; ++n) {
        uint32_t shift = 0;
        for (uint32_t j = 0; j < 4; ++j) {
            uint8_t sc = blk[is++]; float dl = d * (float)(sc & 15), ml = dmin * (float)(sc >> 4);
            for (uint32_t l = 0; l < 16; ++l) y[elem + l] = dl * (float)((q[l] >> shift) & 3) - ml;
            elem += 16; sc = blk[is++]; dl = d * (float)(sc & 15); ml = dmin * (float)(sc >> 4);
            for (uint32_t l = 0; l < 16; ++l) y[elem + l] = dl * (float)((q[l + 16] >> shift) & 3) - ml;
            elem += 16; shift += 2;
        }
        q += 32;
    }
}

static bool Parity(CPUInference::VulkanCompute* vc, int ty, const uint8_t* pk, size_t nb,
                   uint32_t rows, uint32_t cols, size_t blkB, void (*deq)(const uint8_t*, float*)) {
    const uint32_t nblk = (cols + (ty == 8 ? 31u : 255u)) / (ty == 8 ? 32u : 256u);
    std::vector<float> W((size_t)rows * cols), x(cols), yc(rows), yg(rows);
    for (uint32_t r = 0; r < rows; ++r)
        for (uint32_t b = 0; b < nblk; ++b)
            deq(pk + ((size_t)r * nblk + b) * blkB, W.data() + (size_t)r * cols + b * (ty == 8 ? 32 : 256));
    for (uint32_t i = 0; i < cols; ++i) x[i] = 0.01f * (float)((i % 17) + 1);
    for (uint32_t r = 0; r < rows; ++r) {
        float s = 0.f;
        for (uint32_t c = 0; c < cols; ++c) s += W[r * cols + c] * x[c];
        yc[r] = s;
    }
    if (!vc->DispatchGEMVQuant(ty, pk, nb, x.data(), yg.data(), rows, cols)) {
        printf("FAIL dispatch type=%d bytes=%zu\n", ty, nb);
        fflush(stdout);
        return false;
    }
    double maxAbs = 0, ss = 0;
    for (uint32_t r = 0; r < rows; ++r) {
        double d = std::fabs((double)yg[r] - (double)yc[r]);
        if (d > maxAbs) maxAbs = d; ss += d * d;
    }
    printf("type=%d maxAbs=%.6g rms=%.6g\n", ty, maxAbs, std::sqrt(ss / rows));
    return maxAbs < 2e-2 && std::sqrt(ss / rows) < 5e-3;
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
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_QUANT_FAMILY_001", nullptr);
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
    auto* vc = engine.getVulkanComputeSlot(0);
    if (!vc) { printf("FAIL vulkan\n"); return 2; }
    const uint32_t rows = 64, cols = 256;
    auto fill = [](std::vector<uint8_t>& b) {
        for (size_t i = 0; i < b.size(); ++i) b[i] = (uint8_t)((i * 17 + 3) & 255);
    };
    auto setD = [](std::vector<uint8_t>& b, size_t off) { b[off] = 0x00; b[off + 1] = 0x3C; };
    std::vector<uint8_t> q8((size_t)rows * 8 * 34), q5((size_t)rows * 176);
    std::vector<uint8_t> q3((size_t)rows * 110), q2((size_t)rows * 84);
    fill(q8); fill(q5); fill(q3); fill(q2);
    for (uint32_t r = 0; r < rows; ++r) {
        for (int b = 0; b < 8; ++b) setD(q8, ((size_t)r * 8 + b) * 34);
        setD(q5, (size_t)r * 176); setD(q5, (size_t)r * 176 + 2);
        setD(q3, (size_t)r * 110 + 108);
        setD(q2, (size_t)r * 84 + 80); setD(q2, (size_t)r * 84 + 82);
    }
    const bool p8 = Parity(vc, 8, q8.data(), q8.size(), rows, cols, 34, DeqQ8);
    const bool p5 = Parity(vc, 13, q5.data(), q5.size(), rows, cols, 176, DeqQ5);
    const bool p3 = Parity(vc, 11, q3.data(), q3.size(), rows, cols, 110, DeqQ3);
    const bool p2 = Parity(vc, 10, q2.data(), q2.size(), rows, cols, 84, DeqQ2);
    printf("STREAMER_GPU_Q5K_GEMV_001=%s\n", p5 ? "PASS" : "FAIL");
    printf("STREAMER_GPU_Q3K_GEMV_001=%s\n", p3 ? "PASS" : "FAIL");
    printf("STREAMER_GPU_Q2K_GEMV_001=%s\n", p2 ? "PASS" : "FAIL");
    printf("STREAMER_GPU_Q8_GEMV_001=%s\n", p8 ? "PASS" : "FAIL");
    fflush(stdout);
    const bool pass = p5 && p3 && p2 && p8;
    auto writeOne = [&](const char* gate, bool p) {
        std::string dir = std::string("G:\\~dev\\rawrxd\\evidence\\") + gate;
        CreateDirectoryA(dir.c_str(), nullptr);
        FILE* f = nullptr;
        fopen_s(&f, (dir + "\\GATE_STATUS.txt").c_str(), "wb");
        if (!f) return;
        fprintf(f, "%s=%s\n", gate, p ? "PASS" : "FAIL");
        fclose(f);
    };
    writeOne("STREAMER_GPU_Q5K_GEMV_001", p5);
    writeOne("STREAMER_GPU_Q3K_GEMV_001", p3);
    writeOne("STREAMER_GPU_Q2K_GEMV_001", p2);
    writeOne("STREAMER_GPU_Q8_GEMV_001", p8);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_GPU_QUANT_FAMILY_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "STREAMER_GPU_Q5K_GEMV_001=%s\n", p5 ? "PASS" : "FAIL");
        fprintf(f, "STREAMER_GPU_Q3K_GEMV_001=%s\n", p3 ? "PASS" : "FAIL");
        fprintf(f, "STREAMER_GPU_Q2K_GEMV_001=%s\n", p2 ? "PASS" : "FAIL");
        fprintf(f, "STREAMER_GPU_Q8_GEMV_001=%s\n", p8 ? "PASS" : "FAIL");
        fprintf(f, "STREAMER_GPU_QUANT_FAMILY_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    _exit(pass ? 0 : 2);
}
