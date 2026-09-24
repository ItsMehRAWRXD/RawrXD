// test_q2k_single_tensor_oracle.cpp — Q2_K CPU GEMV numerical parity oracle
// Usage: test_q2k_single_tensor_oracle <path-to-model.gguf>
#include "Deep2Engine.h"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>

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
