// ============================================================================
// TransformerBlock_NumericalTest.cpp
// ============================================================================
// End-to-end numerical validation of a single transformer block.
// Verifies the format-agnostic runtime produces correct outputs.
//
// Test: Create synthetic F32 weights, run a block, compare against
// a pure reference implementation. Then verify the universal runtime
// path (descriptor → tensor view → executor) produces identical results.
// ============================================================================

#include "../deep2/UniversalTensorDescriptor.hpp"
#include "../deep2/KernelRegistry.hpp"
#include "../deep2/TensorView.hpp"
#include "../deep2/TransformerBlockExecutor.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <random>

using namespace RawrXD;

// ============================================================================
// Test Configuration (small model for fast validation)
// ============================================================================
constexpr uint32_t H = 64;       // hidden dim
constexpr uint32_t nH = 4;       // num heads
constexpr uint32_t nKV = 4;      // num KV heads
constexpr uint32_t hd = 16;      // head dim (H / nH)
constexpr uint32_t I = 128;      // inter dim
constexpr float    eps = 1e-6f;
constexpr float    theta = 10000.0f;

// ============================================================================
// Generate random F32 weights
// ============================================================================
static float* makeRandomF32(uint64_t count, std::mt19937& rng) {
    float* data = static_cast<float*>(_aligned_malloc(count * sizeof(float), 64));
    std::uniform_real_distribution<float> dist(-0.1f, 0.1f);
    for (uint64_t i = 0; i < count; ++i) {
        data[i] = dist(rng);
    }
    return data;
}

// ============================================================================
// Create a 2D F32 tensor descriptor
// ============================================================================
static TensorView makeF32Tensor(uint32_t rows, uint32_t cols, float* data) {
    auto desc = TensorDescriptorBuilder()
        .shape({rows, cols})
        .quant(QuantType::F32)
        .layout(TensorLayout::DENSE)
        .role(TensorRole::WEIGHT)
        .data(data)
        .build();
    return TensorView::FromResident(desc);
}

// ============================================================================
// Reference implementation (pure, no runtime)
// ============================================================================
static void reference_block(
    const float* input, float* output,
    const float* attnNormW,
    const float* qW, const float* kW, const float* vW, const float* oW,
    const float* ffnNormW,
    const float* gateW, const float* upW, const float* downW,
    uint32_t position
) {
    float* normed = new float[H];
    float* q = new float[nH * hd];
    float* k = new float[nKV * hd];
    float* v = new float[nKV * hd];
    float* attnOut = new float[nH * hd];
    float* projOut = new float[H];
    float* ffnNormed = new float[H];
    float* ffnOut = new float[H];

    // RMSNorm
    ScalarRef::rmsnorm(input, attnNormW, normed, H, eps);

    // QKV
    ScalarRef::gemv_f32(qW, normed, q, nH * hd, H);
    ScalarRef::gemv_f32(kW, normed, k, nKV * hd, H);
    ScalarRef::gemv_f32(vW, normed, v, nKV * hd, H);

    // RoPE
    for (uint32_t h = 0; h < nH; ++h) ScalarRef::rope(q + h * hd, hd, position, theta);
    for (uint32_t h = 0; h < nKV; ++h) ScalarRef::rope(k + h * hd, hd, position, theta);

    // Single-token attention (seqLen=1): output = V
    for (uint32_t h = 0; h < nH; ++h) {
        uint32_t kvH = h % nKV;
        std::memcpy(attnOut + h * hd, v + kvH * hd, hd * sizeof(float));
    }

    // Output projection
    ScalarRef::gemv_f32(oW, attnOut, projOut, H, nH * hd);

    // Residual
    for (uint32_t i = 0; i < H; ++i) projOut[i] += input[i];

    // FFN norm
    ScalarRef::rmsnorm(projOut, ffnNormW, ffnNormed, H, eps);

    // SwiGLU FFN
    ScalarRef::swiglu_ffn(gateW, upW, downW, ffnNormed, ffnOut, H, I);

    // Residual
    for (uint32_t i = 0; i < H; ++i) output[i] = ffnOut[i] + projOut[i];

    delete[] normed; delete[] q; delete[] k; delete[] v;
    delete[] attnOut; delete[] projOut; delete[] ffnNormed; delete[] ffnOut;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=============================================================================\n");
    printf("Transformer Block Numerical Validation\n");
    printf("Format-agnostic runtime end-to-end test\n");
    printf("=============================================================================\n\n");

    std::mt19937 rng(42);  // Fixed seed for reproducibility

    // Generate random weights
    float* attnNormW = makeRandomF32(H, rng);
    float* qW = makeRandomF32(nH * hd * H, rng);
    float* kW = makeRandomF32(nKV * hd * H, rng);
    float* vW = makeRandomF32(nKV * hd * H, rng);
    float* oW = makeRandomF32(H * nH * hd, rng);
    float* ffnNormW = makeRandomF32(H, rng);
    float* gateW = makeRandomF32(I * H, rng);
    float* upW = makeRandomF32(I * H, rng);
    float* downW = makeRandomF32(H * I, rng);

    // Generate random input
    float* input = makeRandomF32(H, rng);

    // Create tensor views (universal runtime path)
    auto attnNormView = makeF32Tensor(H, 1, attnNormW);
    auto qView = makeF32Tensor(nH * hd, H, qW);
    auto kView = makeF32Tensor(nKV * hd, H, kW);
    auto vView = makeF32Tensor(nKV * hd, H, vW);
    auto oView = makeF32Tensor(H, nH * hd, oW);
    auto ffnNormView = makeF32Tensor(H, 1, ffnNormW);
    auto gateView = makeF32Tensor(I, H, gateW);
    auto upView = makeF32Tensor(I, H, upW);
    auto downView = makeF32Tensor(H, I, downW);

    // Verify tensor views are valid
    printf("Tensor View Validation:\n");
    printf("  qProj: shape=[%u, %u] bytes=%llu quant=%s valid=%s\n",
           nH * hd, H, (unsigned long long)qView.byteSize(),
           quantTypeName(qView.quantType()),
           qView.isValid() ? "YES" : "NO");
    printf("  gateProj: shape=[%u, %u] bytes=%llu quant=%s valid=%s\n",
           I, H, (unsigned long long)gateView.byteSize(),
           quantTypeName(gateView.quantType()),
           gateView.isValid() ? "YES" : "NO");
    printf("\n");

    // Run reference implementation
    float* refOutput = new float[H];
    reference_block(input, refOutput,
                    attnNormW, qW, kW, vW, oW,
                    ffnNormW, gateW, upW, downW, 0);

    // Run universal runtime executor
    BlockConfig config;
    config.hiddenDim = H;
    config.numHeads = nH;
    config.numKVHeads = nKV;
    config.headDim = hd;
    config.interDim = I;
    config.rmsNormEps = eps;
    config.ropeTheta = theta;
    config.isMoE = false;

    ResolvedKernelTable kernels = ResolvedKernelTable::Resolve(QuantType::F32, QuantType::F32);
    TransformerBlockExecutor executor(config, kernels);

    BlockTensors btensors;
    btensors.attnNormWeight = &attnNormView;
    btensors.qProjWeight = &qView;
    btensors.kProjWeight = &kView;
    btensors.vProjWeight = &vView;
    btensors.oProjWeight = &oView;
    btensors.ffnNormWeight = &ffnNormView;
    btensors.gateProjWeight = &gateView;
    btensors.upProjWeight = &upView;
    btensors.downProjWeight = &downView;

    float* rtOutput = new float[H];
    bool execResult = executor.Execute(input, rtOutput, btensors, 0, 1);

    if (!execResult) {
        printf("FAIL: Executor returned false\n");
        return 1;
    }

    // Compare
    printf("Numerical Comparison:\n");
    float maxError = 0.0f;
    float sumError = 0.0f;
    for (uint32_t i = 0; i < H; ++i) {
        float err = std::abs(refOutput[i] - rtOutput[i]);
        if (err > maxError) maxError = err;
        sumError += err;
    }
    float avgError = sumError / H;

    printf("  Max error:  %.6e\n", maxError);
    printf("  Avg error:  %.6e\n", avgError);
    printf("  Tolerance:  1.0e-5\n\n");

    bool passed = maxError < 1e-5f;

    // Show first few outputs
    printf("Output samples (first 8 elements):\n");
    printf("  %-12s %-12s %-12s\n", "Reference", "Runtime", "Error");
    for (uint32_t i = 0; i < 8 && i < H; ++i) {
        printf("  %-12.6f %-12.6f %-12.2e\n",
               refOutput[i], rtOutput[i], std::abs(refOutput[i] - rtOutput[i]));
    }
    printf("\n");

    printf("=============================================================================\n");
    printf("Result: %s\n", passed ? "PASS - Numerical parity confirmed" : "FAIL");
    printf("=============================================================================\n");

    if (passed) {
        printf("\nThe format-agnostic runtime produces numerically identical\n");
        printf("results to the reference implementation. The universal tensor\n");
        printf("descriptor → tensor view → executor pipeline is correct.\n");
    }

    // Cleanup
    _aligned_free(attnNormW);
    _aligned_free(qW);
    _aligned_free(kW);
    _aligned_free(vW);
    _aligned_free(oW);
    _aligned_free(ffnNormW);
    _aligned_free(gateW);
    _aligned_free(upW);
    _aligned_free(downW);
    _aligned_free(input);
    delete[] refOutput;
    delete[] rtOutput;

    return passed ? 0 : 1;
}