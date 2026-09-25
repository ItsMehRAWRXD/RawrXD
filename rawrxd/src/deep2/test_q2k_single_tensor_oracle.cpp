// test_q2k_single_tensor_oracle.cpp — Q2_K CPU GEMV numerical parity oracle
// Usage: test_q2k_single_tensor_oracle <path-to-model.gguf>
#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <limits>

// Local copy of fp16→fp32 conversion (same as QuantKernelRegistry.cpp)
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;
    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
}

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1]
        : "D:\\rawrxd\\llama3.2-3b-Q2_K.gguf";

    std::fprintf(stderr, "GATE=Q2K_SINGLE_TENSOR_ORACLE\n");
    std::fprintf(stderr, "MODEL=%s\n", modelPath);

    Deep2Engine engine;
    EngineConfig cfg{};
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 16;
    cfg.useRoPE     = true;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", modelPath);

    if (!engine.initialize(cfg)) { std::fprintf(stderr, "FAIL=initialize\n"); return 1; }
    std::fprintf(stderr, "PASS=initialize\n");

    if (!engine.loadModel(modelPath)) { std::fprintf(stderr, "FAIL=loadModel\n"); return 1; }
    std::fprintf(stderr, "PASS=loadModel\n");

    const auto& mw = engine.getModelWeights();
    if (mw.layers.empty()) { std::fprintf(stderr, "FAIL=no_layers\n"); return 1; }

    const WeightTensor& wq = mw.layers[0].wq;
    if (!wq.data || wq.rows == 0 || wq.cols == 0) {
        std::fprintf(stderr, "FAIL=blk.0.attn_q.weight_not_loaded\n");
        return 1;
    }

    const size_t inDim  = wq.cols;  // 3072
    const size_t outDim = wq.rows;  // 3072
    const size_t numElements = inDim * outDim;

    std::fprintf(stderr, "TENSOR=blk.0.attn_q.weight type=%d rows=%zu cols=%zu elements=%zu\n",
                 wq.type, wq.rows, wq.cols, numElements);

    // ------------------------------------------------------------------
    // Diagnostic: dump block 0 raw bytes and decoded values
    // ------------------------------------------------------------------
    {
        const block_q2_K* blk0 = reinterpret_cast<const block_q2_K*>(wq.data);
        uint16_t raw_d = blk0->d;
        uint16_t raw_dmin = blk0->dmin;
        float d_f = f16_to_f32(raw_d);
        float dmin_f = f16_to_f32(raw_dmin);
        std::fprintf(stderr, "Q2K_BLOCK=0 RAW_D_HEX=%04X RAW_DMIN_HEX=%04X D_FLOAT=%.9g DMIN_FLOAT=%.9g\n",
                     raw_d, raw_dmin, d_f, dmin_f);
        std::fprintf(stderr, "Q2K_BLOCK=0 SCALES=");
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02X ", blk0->scales[i]);
        std::fprintf(stderr, "\n");
        std::fprintf(stderr, "Q2K_BLOCK=0 QS=");
        for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02X ", blk0->qs[i]);
        std::fprintf(stderr, "...\n");
        // Decode first 16 weights using same logic as dequant_q2_k
        float w_min = std::numeric_limits<float>::infinity();
        float w_max = -std::numeric_limits<float>::infinity();
        std::fprintf(stderr, "Q2K_BLOCK=0 W=");
        for (int chunk = 0; chunk < 2; ++chunk) {
            for (int subBlock = 0; subBlock < 4; ++subBlock) {
                for (int group = 0; group < 2; ++group) {
                    int scaleIdx = chunk * 8 + subBlock * 2 + group;
                    uint8_t sc = blk0->scales[scaleIdx];
                    float dl = d_f * (float)(sc & 0x0F);
                    float ml = dmin_f * (float)(sc >> 4);
                    for (int pos = 0; pos < 16; ++pos) {
                        int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                        if (i >= 16) break; // only first 16 weights
                        int qsIdx = chunk * 32 + group * 16 + pos;
                        int qsShift = subBlock * 2;
                        int q = (blk0->qs[qsIdx] >> qsShift) & 0x03;
                        float wv = dl * (float)q - ml;
                        std::fprintf(stderr, "%.4f ", wv);
                        if (wv < w_min) w_min = wv;
                        if (wv > w_max) w_max = wv;
                    }
                }
            }
        }
        std::fprintf(stderr, "\nQ2K_BLOCK=0 W_MIN=%.6f W_MAX=%.6f\n", w_min, w_max);
        if (!std::isfinite(d_f) || !std::isfinite(dmin_f) || std::fabsf(w_max) > 100.0f || std::fabsf(w_min) > 100.0f) {
            std::fprintf(stderr, "Q2K_PLAUSIBILITY_FAIL\n");
        } else {
            std::fprintf(stderr, "Q2K_PLAUSIBILITY_PASS\n");
        }
    }

    // ------------------------------------------------------------------
    // Input vector: unit vector of 1.0f (same as prior test to keep continuity)
    // ------------------------------------------------------------------
    std::vector<float> input(inDim, 1.0f);
    float inputMin = input[0], inputMax = input[0], inputSum = 0.0f, inputL2 = 0.0f;
    for (size_t i = 0; i < inDim; ++i) {
        if (input[i] < inputMin) inputMin = input[i];
        if (input[i] > inputMax) inputMax = input[i];
        inputSum += input[i];
        inputL2  += input[i] * input[i];
    }
    std::fprintf(stderr, "INPUT_MIN=%.6f INPUT_MAX=%.6f INPUT_MEAN=%.6f INPUT_L2=%.6f\n",
                 inputMin, inputMax, inputSum / inDim, std::sqrt(inputL2));

    // ------------------------------------------------------------------
    // Run registered Q2_K GEMV via LinearW (product path)
    // ------------------------------------------------------------------
    std::vector<float> gemvOutput(outDim, 0.0f);
    engine.LinearW(wq, input.data(), nullptr, gemvOutput.data(), outDim);

    bool gemvAllFinite = true;
    for (size_t i = 0; i < outDim; ++i) {
        if (!std::isfinite(gemvOutput[i])) { gemvAllFinite = false; break; }
    }
    std::fprintf(stderr, "GEMV_OUTPUT_FINITE=%s\n", gemvAllFinite ? "PASS" : "FAIL");

    // ------------------------------------------------------------------
    // Dequantize entire tensor via registered kernel
    // ------------------------------------------------------------------
    const auto& registry = QuantKernelRegistry::Instance();
    DequantKernelFn dequantFn = registry.GetDequant(wq.type);
    if (!dequantFn) {
        std::fprintf(stderr, "FAIL=no_dequant_kernel_for_type=%d\n", wq.type);
        return 1;
    }

    std::vector<float> dequant(numElements);
    dequantFn(static_cast<const uint8_t*>(wq.data), dequant.data(), numElements);

    bool dequantAllFinite = true;
    float dqMin = dequant[0], dqMax = dequant[0], dqSum = 0.0f;
    for (size_t i = 0; i < numElements; ++i) {
        if (!std::isfinite(dequant[i])) { dequantAllFinite = false; break; }
        if (dequant[i] < dqMin) dqMin = dequant[i];
        if (dequant[i] > dqMax) dqMax = dequant[i];
        dqSum += dequant[i];
    }
    std::fprintf(stderr, "DEQUANT_FINITE=%s DEQUANT_MIN=%.6f DEQUANT_MAX=%.6f DEQUANT_MEAN=%.6f\n",
                 dequantAllFinite ? "PASS" : "FAIL", dqMin, dqMax, dqSum / numElements);

    // ------------------------------------------------------------------
    // Reference: double-precision scalar dot(input, dequantized_row)
    // ------------------------------------------------------------------
    auto referenceDot = [&](size_t row) -> double {
        double acc = 0.0;
        const float* wRow = &dequant[row * inDim];
        for (size_t c = 0; c < inDim; ++c) {
            acc += static_cast<double>(input[c]) * static_cast<double>(wRow[c]);
        }
        return acc;
    };

    const size_t checkRows[] = { 0, 1, outDim - 1 };
    double maxAbsError = 0.0;
    double maxRelError = 0.0;
    bool parityPass = true;
    const double ABS_TOL = 1e-3;
    const double REL_TOL = 1e-3;

    for (size_t idx = 0; idx < 3; ++idx) {
        size_t row = checkRows[idx];
        double refVal = referenceDot(row);
        double gemvVal = static_cast<double>(gemvOutput[row]);
        double absErr = std::abs(refVal - gemvVal);
        double relErr = absErr / std::max(1e-12, std::abs(refVal));
        bool rowPass = (absErr <= ABS_TOL) || (relErr <= REL_TOL);
        if (!rowPass) parityPass = false;
        if (absErr > maxAbsError) maxAbsError = absErr;
        if (relErr > maxRelError) maxRelError = relErr;

        std::fprintf(stderr,
            "ROW=%zu REF=%.12f GEMV=%.12f ABS_ERR=%.12f REL_ERR=%.12f %s\n",
            row, refVal, gemvVal, absErr, relErr, rowPass ? "PASS" : "FAIL");
    }

    std::fprintf(stderr, "MAX_ABS_ERROR=%.12f MAX_REL_ERROR=%.12f\n", maxAbsError, maxRelError);
    std::fprintf(stderr, "NUMERICAL_PARITY=%s\n", parityPass ? "PASS" : "FAIL");
    std::fprintf(stderr, "RESULT=%s\n", parityPass ? "PASS" : "FAIL");
    return parityPass ? 0 : 1;
}
