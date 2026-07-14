//==============================================================================
// test_masm_backend.cpp
// Phase 7C.2 - MASM Backend Validation
//
// Validates MASM kernels against Reference backend
//==============================================================================

#include <stdio>
#include <cstdlib>
#include <cstring>
#include <math.h>

#include "../src/core/execution/KernelRegistry.hpp"
#include "../src/core/execution/MASMBackend.hpp"
#include "../src/core/execution/ReferenceBackend.hpp"

using namespace sovereign;

//==============================================================================
// Test Helpers
//==============================================================================
bool approxEqual(float a, float b, float epsilon = 1e-4f) {
    return fabsf(a - b) < epsilon;
}

void printResult(const char* test, bool pass) {
    printf("  [%s] %s\n", pass ? "PASS" : "FAIL", test);
}

//==============================================================================
// Test 1: MASM Backend Initialization
//==============================================================================
bool testMASMInit() {
    printf("\n=== Test 1: MASM Backend Initialization ===\n");
    
    MASMBackend masm;
    bool available = masm.IsAvailable();
    printResult("MASM backend available", available);
    
    if (available) {
        BackendInfo info = masm.GetInfo();
        printf("  Backend: %s\n", info.name.c_str());
        printf("  Supported kernels: %zu\n", info.supportedKernels.size());
        for (auto kid : info.supportedKernels) {
            printf("    - %d\n", (int)kid);
        }
    }
    
    return available;
}

//==============================================================================
// Test 2: MASM vs Reference - RMSNorm
//==============================================================================
bool testRMSNorm() {
    printf("\n=== Test 2: RMSNorm Validation (MASM vs Reference) ===\n");
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[n] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float outputRef[n] = {0};
    float outputMASM[n] = {0};
    
    // Reference
    ReferenceBackend ref;
    KernelContext ctxRef;
    ctxRef.input = {input, {n}, DataType::F32};
    ctxRef.output = {outputRef, {n}, DataType::F32};
    ctxRef.params.rmsNorm.weight = weight;
    ctxRef.params.rmsNorm.epsilon = 1e-6f;
    
    Status sRef = ref.Execute(KernelId::RMSNorm_F32, ctxRef);
    printResult("Reference execution", sRef == Status::Success);
    
    // MASM
    MASMBackend masm;
    if (!masm.IsAvailable()) {
        printf("  MASM not available, skipping\n");
        return true;  // Not a failure if MASM not present
    }
    
    if (!masm.Supports(KernelId::RMSNorm_F32)) {
        printf("  RMSNorm not supported by MASM, skipping\n");
        return true;
    }
    
    KernelContext ctxMASM;
    ctxMASM.input = {input, {n}, DataType::F32};
    ctxMASM.output = {outputMASM, {n}, DataType::F32};
    ctxMASM.params.rmsNorm.weight = weight;
    ctxMASM.params.rmsNorm.epsilon = 1e-6f;
    
    Status sMASM = masm.Execute(KernelId::RMSNorm_F32, ctxMASM);
    printResult("MASM execution", sMASM == Status::Success);
    
    // Compare
    bool match = true;
    for (size_t i = 0; i < n; i++) {
        if (!approxEqual(outputRef[i], outputMASM[i])) {
            printf("  Mismatch at %zu: ref=%.6f masm=%.6f\n", 
                   i, outputRef[i], outputMASM[i]);
            match = false;
        }
    }
    printResult("Output match", match);
    
    return sRef == Status::Success && sMASM == Status::Success && match;
}

//==============================================================================
// Test 3: MASM vs Reference - Residual Add
//==============================================================================
bool testResidualAdd() {
    printf("\n=== Test 3: Residual Add Validation (MASM vs Reference) ===\n");
    
    const size_t n = 4;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f};
    float residual[n] = {0.5f, 0.5f, 0.5f, 0.5f};
    float outputRef[n] = {0};
    float outputMASM[n] = {0};
    
    // Reference
    ReferenceBackend ref;
    KernelContext ctxRef;
    ctxRef.input = {input, {n}, DataType::F32};
    ctxRef.output = {outputRef, {n}, DataType::F32};
    ctxRef.params.residual.residual = residual;
    ctxRef.params.residual.scale = 1.0f;
    
    Status sRef = ref.Execute(KernelId::Residual_Add, ctxRef);
    printResult("Reference execution", sRef == Status::Success);
    
    // MASM
    MASMBackend masm;
    if (!masm.IsAvailable() || !masm.Supports(KernelId::Residual_Add)) {
        printf("  MASM not available or unsupported, skipping\n");
        return true;
    }
    
    KernelContext ctxMASM;
    ctxMASM.input = {input, {n}, DataType::F32};
    ctxMASM.output = {outputMASM, {n}, DataType::F32};
    ctxMASM.params.residual.residual = residual;
    ctxMASM.params.residual.scale = 1.0f;
    
    Status sMASM = masm.Execute(KernelId::Residual_Add, ctxMASM);
    printResult("MASM execution", sMASM == Status::Success);
    
    // Compare
    bool match = true;
    for (size_t i = 0; i < n; i++) {
        if (!approxEqual(outputRef[i], outputMASM[i])) {
            printf("  Mismatch at %zu: ref=%.6f masm=%.6f\n", 
                   i, outputRef[i], outputMASM[i]);
            match = false;
        }
    }
    printResult("Output match", match);
    
    return sRef == Status::Success && sMASM == Status::Success && match;
}

//==============================================================================
// Test 4: Registry Integration
//==============================================================================
bool testRegistryIntegration() {
    printf("\n=== Test 4: Registry Integration ===\n");
    
    KernelRegistry& reg = KernelRegistry::Instance();
    
    // Register MASM backend
    auto masm = std::make_unique<MASMBackend>();
    if (!masm->IsAvailable()) {
        printf("  MASM not available, skipping\n");
        return true;
    }
    
    uint32_t masmId = reg.RegisterBackend(std::move(masm));
    printf("  Registered MASM backend with ID: %u\n", masmId);
    
    // List backends
    auto backends = reg.ListBackends();
    printf("  Registered backends: %zu\n", backends.size());
    for (auto& [id, info] : backends) {
        printf("    - %s (ID=%u)\n", info.name.c_str(), id);
    }
    
    return backends.size() > 0;
}

//==============================================================================
// Main
//==============================================================================
int main() {
    printf("==============================================================================\n");
    printf("MASM Backend Validation Test\n");
    printf("Phase 7C.2 - MASM Integration\n");
    printf("==============================================================================\n");
    
    int passed = 0;
    int total = 0;
    
    // Run tests
    total++; if (testMASMInit()) passed++;
    total++; if (testRMSNorm()) passed++;
    total++; if (testResidualAdd()) passed++;
    total++; if (testRegistryIntegration()) passed++;
    
    // Summary
    printf("\n==============================================================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("==============================================================================\n");
    
    return (passed == total) ? 0 : 1;
}
