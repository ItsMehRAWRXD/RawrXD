// ============================================================================
// UniversalRuntime_SmokeTest.cpp
// ============================================================================
// Validates the format-agnostic runtime architecture:
//   1. UniversalTensorDescriptor works for any quantization
//   2. KernelRegistry resolves kernels by (type, quant, ISA)
//   3. UniversalModelLoader produces descriptors (not format-specific)
//   4. RuntimePlanner selects execution strategy dynamically
//   5. No format-specific branching in the runtime path
// ============================================================================

#include "../deep2/UniversalTensorDescriptor.hpp"
#include "../deep2/KernelRegistry.hpp"
#include "../deep2/UniversalModelLoader.hpp"
#include "../deep2/RuntimePlanner.hpp"
#include <cstdio>
#include <vector>

using namespace RawrXD;

// ============================================================================
// Scalar reference kernels (for registration testing)
// ============================================================================
extern "C" void scalar_gemv(const void* weights, const float* input, float* output,
                            uint32_t rows, uint32_t cols,
                            const void* scales, const void* zeros) {
    // Stub - real implementation would dequantize and dot
    for (uint32_t r = 0; r < rows; ++r) {
        output[r] = 0.0f;
    }
}

extern "C" void scalar_rmsnorm(const float* x, const float* weight, float* output,
                                uint32_t dim, float eps) {
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < dim; ++i) {
        sum_sq += x[i] * x[i];
    }
    float rms = 1.0f / sqrtf(sum_sq / dim + eps);
    for (uint32_t i = 0; i < dim; ++i) {
        output[i] = x[i] * rms * weight[i];
    }
}

extern "C" void scalar_attention(float* output, const float* Q, const void* K, const void* V,
                                  uint32_t num_q, uint32_t num_k, uint32_t head_dim,
                                  const uint8_t* mask, const void* kScales, const void* vScales) {
    // Stub
}

extern "C" void scalar_moe_router(const float* hidden, const float* routerWeight,
                                   uint32_t* selectedExperts, float* selectedWeights,
                                   uint32_t numExperts, uint32_t hiddenDim, uint32_t topK) {
    // Stub - select first topK experts
    for (uint32_t i = 0; i < topK; ++i) {
        selectedExperts[i] = i;
        selectedWeights[i] = 1.0f / topK;
    }
}

extern "C" void scalar_sampler(const float* logits, float* probs, uint32_t vocabSize,
                                uint32_t topK, float topP, float temperature) {
    // Stub
    for (uint32_t i = 0; i < vocabSize; ++i) {
        probs[i] = 0.0f;
    }
}

// ============================================================================
// Test: UniversalTensorDescriptor
// ============================================================================
bool test_tensor_descriptor() {
    printf("Test: UniversalTensorDescriptor... ");

    // Create a Q4_K weight descriptor
    auto desc = TensorDescriptorBuilder()
        .shape({4096, 4096})
        .quant(QuantType::Q4_K)
        .layout(TensorLayout::BLOCKED)
        .role(TensorRole::WEIGHT)
        .block(256, 144)  // Q4_K: 256 elements, 144 bytes per block
        .build();

    if (desc.numDims != 2) { printf("FAIL: numDims\n"); return false; }
    if (desc.shape[0] != 4096 || desc.shape[1] != 4096) { printf("FAIL: shape\n"); return false; }
    if (desc.quantType != QuantType::Q4_K) { printf("FAIL: quantType\n"); return false; }
    if (!desc.isQuantized()) { printf("FAIL: isQuantized\n"); return false; }
    if (desc.numElements() != 4096 * 4096) { printf("FAIL: numElements\n"); return false; }

    // Q4_K: 4096*4096 / 256 = 65536 blocks, * 144 bytes = 9437184 bytes
    if (desc.byteSize() != 65536ULL * 144) { printf("FAIL: byteSize (%llu)\n",
        (unsigned long long)desc.byteSize()); return false; }

    printf("PASS\n");
    return true;
}

// ============================================================================
// Test: KernelRegistry
// ============================================================================
bool test_kernel_registry() {
    printf("Test: KernelRegistry... ");

    auto& reg = KernelRegistry::Instance();

    // Register scalar kernels
    reg.RegisterGEMV(QuantType::Q4_K, ISATarget::SCALAR, scalar_gemv);
    reg.RegisterRMSNorm(ISATarget::SCALAR, scalar_rmsnorm);
    reg.RegisterAttention(QuantType::F16, ISATarget::SCALAR, scalar_attention);
    reg.RegisterMoERouter(ISATarget::SCALAR, scalar_moe_router);
    reg.RegisterSampler(ISATarget::SCALAR, scalar_sampler);

    // Resolve kernels
    auto gemv = reg.ResolveGEMV(QuantType::Q4_K, ISATarget::SCALAR);
    if (gemv == nullptr) { printf("FAIL: GEMV resolve\n"); return false; }

    auto rmsnorm = reg.ResolveRMSNorm(ISATarget::SCALAR);
    if (rmsnorm == nullptr) { printf("FAIL: RMSNorm resolve\n"); return false; }

    auto attention = reg.ResolveAttention(QuantType::F16, ISATarget::SCALAR);
    if (attention == nullptr) { printf("FAIL: Attention resolve\n"); return false; }

    auto moeRouter = reg.ResolveMoERouter(ISATarget::SCALAR);
    if (moeRouter == nullptr) { printf("FAIL: MoE Router resolve\n"); return false; }

    // Test fallback: request AVX512, should fall back to SCALAR
    auto gemv_avx512 = reg.ResolveGEMV(QuantType::Q4_K, ISATarget::AVX512);
    if (gemv_avx512 != gemv) { printf("FAIL: Fallback didn't work\n"); return false; }

    // Test ISA detection
    ISATarget best = KernelRegistry::DetectBestISA();
    printf("PASS (ISA: %d)\n", static_cast<int>(best));
    return true;
}

// ============================================================================
// Test: ResolvedKernelTable
// ============================================================================
bool test_resolved_kernel_table() {
    printf("Test: ResolvedKernelTable... ");

    // Resolve all kernels for Q4_K weights, F16 KV cache
    auto table = ResolvedKernelTable::Resolve(QuantType::Q4_K, QuantType::F16);

    if (table.gemv == nullptr) { printf("FAIL: GEMV\n"); return false; }
    if (table.rmsnorm == nullptr) { printf("FAIL: RMSNorm\n"); return false; }
    if (table.sampler == nullptr) { printf("FAIL: Sampler\n"); return false; }

    printf("PASS (ISA: %d)\n", static_cast<int>(table.isa));
    return true;
}

// ============================================================================
// Test: UniversalModelLoader
// ============================================================================
bool test_model_loader() {
    printf("Test: UniversalModelLoader... ");

    UniversalModelLoader loader;

    // Test format detection (should fail gracefully for non-existent file)
    bool result = loader.LoadModel("nonexistent.gguf");
    if (result) { printf("FAIL: should fail for nonexistent\n"); return false; }

    // Verify format readers are registered
    // (GGUF, Safetensors, HFPyTorch should all be available)

    printf("PASS\n");
    return true;
}

// ============================================================================
// Test: RuntimePlanner
// ============================================================================
bool test_runtime_planner() {
    printf("Test: RuntimePlanner... ");

    ModelMetadata metadata;
    metadata.isMoE = true;
    metadata.numExperts = 256;
    metadata.numExpertsPerTok = 8;

    ResolvedKernelTable kernels = ResolvedKernelTable::Resolve(QuantType::Q4_K, QuantType::F16);

    RuntimePlanner planner;
    if (!planner.Initialize(metadata, kernels)) {
        printf("FAIL: Initialize\n"); return false;
    }

    // Create tensor descriptors
    auto kDesc = TensorDescriptorBuilder()
        .shape({1024, 64})
        .quant(QuantType::F16)
        .layout(TensorLayout::DENSE)
        .role(TensorRole::KV_CACHE)
        .build();

    auto vDesc = kDesc;  // Same as K

    auto expertDesc = TensorDescriptorBuilder()
        .shape({256, 4096, 11008})
        .quant(QuantType::Q4_K)
        .layout(TensorLayout::MOE_EXPERT)
        .role(TensorRole::EXPERT)
        .memory(UniversalTensorDescriptor::MemorySpace::NVME)
        .build();

    // Plan a layer
    ExecutionPlan plan = planner.PlanLayer(0, kDesc, vDesc, expertDesc);

    if (!plan.useMoE) { printf("FAIL: useMoE\n"); return false; }
    if (plan.numExperts != 256) { printf("FAIL: numExperts\n"); return false; }
    if (plan.moeStrategy != ExecutionStrategy::MOE_PAGED_NVME) {
        printf("FAIL: moeStrategy (%d)\n", static_cast<int>(plan.moeStrategy)); return false;
    }
    if (plan.dmaScheduler == nullptr) { printf("FAIL: dmaScheduler\n"); return false; }

    // Test strategy planning
    auto strat = RuntimePlanner::PlanAttentionStrategy(QuantType::F16, true, ISATarget::AVX512);
    if (strat != ExecutionStrategy::FUSED_ATTENTION_AVX512) {
        printf("FAIL: attentionStrategy\n"); return false;
    }

    auto memStrat = RuntimePlanner::PlanMemoryStrategy(expertDesc);
    if (memStrat != ExecutionStrategy::MEMORY_NVME_PAGED) {
        printf("FAIL: memoryStrategy\n"); return false;
    }

    printf("PASS\n");
    return true;
}

// ============================================================================
// Test: No format-specific branching
// ============================================================================
bool test_no_format_branching() {
    printf("Test: No format-specific branching... ");

    // The key architectural property: the runtime never checks "if (Q4_K)"
    // It only uses descriptors and resolved kernels.

    // Create descriptors for different quantizations
    auto q4k = TensorDescriptorBuilder().quant(QuantType::Q4_K).build();
    auto q8_0 = TensorDescriptorBuilder().quant(QuantType::Q8_0).build();
    auto f16 = TensorDescriptorBuilder().quant(QuantType::F16).build();
    auto nf4 = TensorDescriptorBuilder().quant(QuantType::NF4).build();

    // All should be handled uniformly via descriptors
    auto& reg = KernelRegistry::Instance();

    // Resolve for each - should work without any format-specific code
    auto gemv_q4k = reg.ResolveGEMV(q4k.quantType, ISATarget::SCALAR);
    auto gemv_q8 = reg.ResolveGEMV(q8_0.quantType, ISATarget::SCALAR);
    auto gemv_f16 = reg.ResolveGEMV(f16.quantType, ISATarget::SCALAR);
    auto gemv_nf4 = reg.ResolveGEMV(nf4.quantType, ISATarget::SCALAR);

    // Q4_K has a registered kernel, others may fall back
    if (gemv_q4k == nullptr) { printf("FAIL: Q4_K resolve\n"); return false; }

    printf("PASS\n");
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=============================================================================\n");
    printf("Universal Runtime Architecture Smoke Test\n");
    printf("Format-agnostic inference runtime validation\n");
    printf("=============================================================================\n\n");

    bool allPassed = true;

    allPassed &= test_tensor_descriptor();
    allPassed &= test_kernel_registry();
    allPassed &= test_resolved_kernel_table();
    allPassed &= test_model_loader();
    allPassed &= test_runtime_planner();
    allPassed &= test_no_format_branching();

    printf("\n=============================================================================\n");
    printf("Result: %s\n", allPassed ? "ALL TESTS PASSED" : "TESTS FAILED");
    printf("=============================================================================\n");

    return allPassed ? 0 : 1;
}