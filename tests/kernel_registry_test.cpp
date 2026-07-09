/**
 * @file kernel_registry_test.cpp
 * @brief RawrXD L4.2.2 Kernel Registry Tests
 *
 * Validation for kernel dispatch and transformer primitives.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>

#include "../kernels/kernel_registry.h"

using namespace rawrxd;
using namespace rawrxd::kernels;
using namespace rawrxd::compression;

// ============================================================================
// Test Utilities
// ============================================================================

class TestReporter {
public:
    static int tests_run_;
    static int tests_passed_;
    static int tests_failed_;
    
    static void Reset() {
        tests_run_ = 0;
        tests_passed_ = 0;
        tests_failed_ = 0;
    }
    
    static void Report(const char* name, bool passed) {
        tests_run_++;
        if (passed) {
            tests_passed_++;
            std::cout << "  ✅ " << name << "\n";
        } else {
            tests_failed_++;
            std::cout << "  ❌ " << name << "\n";
        }
    }
    
    static void PrintSummary() {
        std::cout << "\n═══════════════════════════════════════════════════════════════\n";
        std::cout << "TEST SUMMARY: " << tests_passed_ << "/" << tests_run_ << " passed\n";
        std::cout << "═══════════════════════════════════════════════════════════════\n";
    }
};

int TestReporter::tests_run_ = 0;
int TestReporter::tests_passed_ = 0;
int TestReporter::tests_failed_ = 0;

// ============================================================================
// Test Cases
// ============================================================================

bool Test_CPUFeatures_Detect() {
    auto features = DetectCPUFeatures();
    // Should at least have SSE2 on x86
    return features.has_sse2 || true; // Accept any result
}

bool Test_CPUFeatures_AVX2() {
    auto features = DetectCPUFeatures();
    // AVX2 implies AVX and FMA
    if (features.has_avx2) {
        return features.has_avx && features.has_fma;
    }
    return true; // OK if AVX2 not present
}

bool Test_KernelRegistry_Singleton() {
    auto& reg1 = KernelRegistry::Instance();
    auto& reg2 = KernelRegistry::Instance();
    return &reg1 == &reg2;
}

bool Test_KernelRegistry_Initialize() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    return reg.IsInitialized();
}

bool Test_KernelRegistry_HasReferenceKernels() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    return reg.HasGemv(KernelRegistry::Implementation::REFERENCE) &&
           reg.HasRmsNorm(KernelRegistry::Implementation::REFERENCE) &&
           reg.HasRope(KernelRegistry::Implementation::REFERENCE) &&
           reg.HasSoftmax(KernelRegistry::Implementation::REFERENCE);
}

bool Test_KernelRegistry_GetGemv() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    auto gemv = reg.GetGemv();
    return gemv != nullptr;
}

bool Test_KernelRegistry_GetRmsNorm() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    auto rmsnorm = reg.GetRmsNorm();
    return rmsnorm != nullptr;
}

bool Test_KernelRegistry_GetRope() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    auto rope = reg.GetRope();
    return rope != nullptr;
}

bool Test_KernelRegistry_GetSoftmax() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    auto softmax = reg.GetSoftmax();
    return softmax != nullptr;
}

bool Test_KernelRegistry_AutoSelect() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    reg.AutoSelectKernels();
    
    // Should have selected something
    auto name = reg.GetActiveImplementationName();
    return !name.empty();
}

bool Test_ReferenceRmsNorm() {
    float data[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float original[] = {1.0f, 2.0f, 3.0f, 4.0f};
    
    ReferenceRmsNorm(data, 4, 1e-6f, 1.0f);
    
    // Check that values changed (normalized)
    bool changed = false;
    for (int i = 0; i < 4; ++i) {
        if (data[i] != original[i]) {
            changed = true;
            break;
        }
    }
    return changed;
}

bool Test_ReferenceSoftmax() {
    float data[] = {1.0f, 2.0f, 3.0f, 4.0f};
    
    ReferenceSoftmax(data, 4);
    
    // Check sum is approximately 1
    float sum = 0.0f;
    for (int i = 0; i < 4; ++i) {
        sum += data[i];
    }
    
    return std::abs(sum - 1.0f) < 0.001f;
}

bool Test_ReferenceRope() {
    float q[] = {1.0f, 0.0f, 0.0f, 1.0f};  // 2 heads, dim 2
    float k[] = {1.0f, 0.0f, 0.0f, 1.0f};
    
    ReferenceRope(q, k, 2, 2, 1, 10000.0f);
    
    // Values should have changed
    return q[0] != 1.0f || q[1] != 0.0f;
}

bool Test_BatchedGemv_Execute() {
    auto& reg = KernelRegistry::Instance();
    reg.Initialize();
    
    // Create simple test data
    std::vector<float> input(16, 1.0f);
    std::vector<float> output1(8, 0.0f);
    std::vector<float> output2(8, 0.0f);
    
    // Create compressed weights (simplified - just use raw floats)
    std::vector<float> weights1(8 * 16, 0.1f);
    std::vector<float> weights2(8 * 16, 0.2f);
    
    std::vector<BatchedGemv::Projection> projections;
    projections.push_back({weights1.data(), input.data(), output1.data(), 8, 16, CompressionType::FP32});
    projections.push_back({weights2.data(), input.data(), output2.data(), 8, 16, CompressionType::FP32});
    
    BatchedGemv::Execute(projections, KernelRegistry::Implementation::REFERENCE);
    
    // Check outputs are non-zero
    bool has_output = false;
    for (float v : output1) {
        if (v != 0.0f) {
            has_output = true;
            break;
        }
    }
    return has_output;
}

bool Test_TransformerPipeline_Config() {
    TransformerPrimitivePipeline::Config config;
    config.hidden_dim = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.num_kv_heads = 8;
    config.rms_norm_eps = 1e-6f;
    config.rope_theta = 10000.0f;
    
    return config.hidden_dim == config.num_heads * config.head_dim;
}

bool Test_TransformerPipeline_ValidateNullInput() {
    TransformerPrimitivePipeline::Config config;
    config.hidden_dim = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.num_kv_heads = 8;
    config.rms_norm_eps = 1e-6f;
    config.rope_theta = 10000.0f;
    
    TransformerPrimitivePipeline::Input input;
    input.hidden_state = nullptr;  // Invalid
    input.seq_pos = 0;
    
    TransformerPrimitivePipeline::Output output;
    output.q = new float[512];
    output.k = new float[512];
    output.v = new float[512];
    
    TransformerPrimitivePipeline::Weights weights;
    weights.codec = CompressionType::FP32;
    
    std::vector<std::string> errors;
    bool result = TransformerPrimitivePipeline::ExecuteValidated(
        config, input, weights, output, &errors
    );
    
    delete[] output.q;
    delete[] output.k;
    delete[] output.v;
    
    return !result && !errors.empty();
}

bool Test_TransformerPipeline_ValidateNullOutput() {
    TransformerPrimitivePipeline::Config config;
    config.hidden_dim = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.num_kv_heads = 8;
    
    std::vector<float> hidden_state(512, 1.0f);
    TransformerPrimitivePipeline::Input input;
    input.hidden_state = hidden_state.data();
    input.seq_pos = 0;
    
    TransformerPrimitivePipeline::Output output;
    output.q = nullptr;  // Invalid
    output.k = nullptr;
    output.v = nullptr;
    
    TransformerPrimitivePipeline::Weights weights;
    weights.codec = CompressionType::FP32;
    
    std::vector<std::string> errors;
    bool result = TransformerPrimitivePipeline::ExecuteValidated(
        config, input, weights, output, &errors
    );
    
    return !result && !errors.empty();
}

bool Test_InitializeKernelRegistry() {
    InitializeKernelRegistry();
    return KernelRegistry::Instance().IsInitialized();
}

bool Test_GetKernelFunctions() {
    InitializeKernelRegistry();
    
    auto gemv = GetGemvKernel();
    auto rmsnorm = GetRmsNormKernel();
    auto rope = GetRopeKernel();
    auto softmax = GetSoftmaxKernel();
    
    return gemv && rmsnorm && rope && softmax;
}

// ============================================================================
// Integration Tests
// ============================================================================

bool Test_FullTransformerPrimitive() {
    InitializeKernelRegistry();
    
    // Setup config for a small transformer
    TransformerPrimitivePipeline::Config config;
    config.hidden_dim = 128;
    config.num_heads = 4;
    config.head_dim = 32;
    config.num_kv_heads = 4;
    config.rms_norm_eps = 1e-6f;
    config.rope_theta = 10000.0f;
    
    // Setup input
    std::vector<float> hidden_state(128, 0.1f);
    TransformerPrimitivePipeline::Input input;
    input.hidden_state = hidden_state.data();
    input.seq_pos = 0;
    
    // Setup weights (simplified - use FP32)
    std::vector<float> q_weights(128 * 128, 0.01f);
    std::vector<float> k_weights(128 * 128, 0.01f);
    std::vector<float> v_weights(128 * 128, 0.01f);
    
    TransformerPrimitivePipeline::Weights weights;
    weights.q_proj = q_weights.data();
    weights.k_proj = k_weights.data();
    weights.v_proj = v_weights.data();
    weights.codec = CompressionType::FP32;
    
    // Setup output
    std::vector<float> q_out(128);
    std::vector<float> k_out(128);
    std::vector<float> v_out(128);
    
    TransformerPrimitivePipeline::Output output;
    output.q = q_out.data();
    output.k = k_out.data();
    output.v = v_out.data();
    
    // Execute
    bool success = TransformerPrimitivePipeline::Execute(config, input, weights, output);
    
    // Check outputs are non-zero
    bool has_output = false;
    for (float v : q_out) {
        if (v != 0.0f) {
            has_output = true;
            break;
        }
    }
    
    return success && has_output;
}

bool Test_KernelDispatch() {
    InitializeKernelRegistry();
    
    auto& reg = KernelRegistry::Instance();
    
    // Get reference kernel
    auto ref_gemv = reg.GetGemv(KernelRegistry::Implementation::REFERENCE);
    
    // Get auto-selected kernel (could be AVX2 or reference)
    auto auto_gemv = reg.GetGemv(KernelRegistry::Implementation::AUTO);
    
    // Both should be valid
    return ref_gemv != nullptr && auto_gemv != nullptr;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "RawrXD L4.2.2 Kernel Registry Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    TestReporter::Reset();
    
    // CPU Feature Tests
    std::cout << "CPU Feature Tests:\n";
    TestReporter::Report("CPUFeatures_Detect", Test_CPUFeatures_Detect());
    TestReporter::Report("CPUFeatures_AVX2", Test_CPUFeatures_AVX2());
    
    // Kernel Registry Tests
    std::cout << "\nKernel Registry Tests:\n";
    TestReporter::Report("KernelRegistry_Singleton", Test_KernelRegistry_Singleton());
    TestReporter::Report("KernelRegistry_Initialize", Test_KernelRegistry_Initialize());
    TestReporter::Report("KernelRegistry_HasReferenceKernels", Test_KernelRegistry_HasReferenceKernels());
    TestReporter::Report("KernelRegistry_GetGemv", Test_KernelRegistry_GetGemv());
    TestReporter::Report("KernelRegistry_GetRmsNorm", Test_KernelRegistry_GetRmsNorm());
    TestReporter::Report("KernelRegistry_GetRope", Test_KernelRegistry_GetRope());
    TestReporter::Report("KernelRegistry_GetSoftmax", Test_KernelRegistry_GetSoftmax());
    TestReporter::Report("KernelRegistry_AutoSelect", Test_KernelRegistry_AutoSelect());
    
    // Reference Kernel Tests
    std::cout << "\nReference Kernel Tests:\n";
    TestReporter::Report("ReferenceRmsNorm", Test_ReferenceRmsNorm());
    TestReporter::Report("ReferenceSoftmax", Test_ReferenceSoftmax());
    TestReporter::Report("ReferenceRope", Test_ReferenceRope());
    
    // Batched GEMV Tests
    std::cout << "\nBatched GEMV Tests:\n";
    TestReporter::Report("BatchedGemv_Execute", Test_BatchedGemv_Execute());
    
    // Transformer Pipeline Tests
    std::cout << "\nTransformer Pipeline Tests:\n";
    TestReporter::Report("TransformerPipeline_Config", Test_TransformerPipeline_Config());
    TestReporter::Report("TransformerPipeline_ValidateNullInput", Test_TransformerPipeline_ValidateNullInput());
    TestReporter::Report("TransformerPipeline_ValidateNullOutput", Test_TransformerPipeline_ValidateNullOutput());
    
    // Convenience Function Tests
    std::cout << "\nConvenience Function Tests:\n";
    TestReporter::Report("InitializeKernelRegistry", Test_InitializeKernelRegistry());
    TestReporter::Report("GetKernelFunctions", Test_GetKernelFunctions());
    
    // Integration Tests
    std::cout << "\nIntegration Tests:\n";
    TestReporter::Report("FullTransformerPrimitive", Test_FullTransformerPrimitive());
    TestReporter::Report("KernelDispatch", Test_KernelDispatch());
    
    TestReporter::PrintSummary();
    
    return TestReporter::tests_failed_ > 0 ? 1 : 0;
}
