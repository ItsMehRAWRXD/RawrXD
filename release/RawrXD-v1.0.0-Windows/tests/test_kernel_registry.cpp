//==============================================================================
// test_kernel_registry.cpp
// Kernel Registry Validation Test
//
// Validates:
// - Backend registration
// - Automatic backend selection
// - Cross-backend numerical comparison
// - Performance tracking
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Validation
//==============================================================================

#include <iostream>
#include <iomanip>
#include <cmath>
#include "../src/core/execution/KernelRegistry.hpp"
#include "../src/core/execution/IKernelBackend.hpp"

using namespace sovereign;

//==============================================================================
// Test Configuration
//==============================================================================
struct TestConfig {
    size_t matmulM{128};
    size_t matmulN{128};
    size_t matmulK{128};
    double errorTolerance{1e-4};
};

//==============================================================================
// Helper Functions
//==============================================================================

void PrintHeader(const char* title) {
    std::cout << "\n" << std::string(70, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(70, '=') << "\n";
}

void PrintResult(const char* test, bool passed) {
    std::cout << "  [" << (passed ? "PASS" : "FAIL") << "] " << test << "\n";
}

float* AllocateAlignedFloat(size_t count) {
    return (float*)_aligned_malloc(count * sizeof(float), 64);
}

void FreeAligned(void* ptr) {
    _aligned_free(ptr);
}

//==============================================================================
// Test 1: Backend Registration
//==============================================================================
bool Test_BackendRegistration() {
    PrintHeader("Test 1: Backend Registration");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Initialize default backends
    bool init = InitializeDefaultBackends();
    PrintResult("InitializeDefaultBackends", init);
    
    // List backends
    auto backends = registry.ListBackends();
    std::cout << "  Registered backends: " << backends.size() << "\n";
    
    for (const auto& [id, info] : backends) {
        std::cout << "    [" << id << "] " << info.name 
                  << " v" << info.version << "\n";
    }
    
    return init && backends.size() >= 1; // At least Reference
}

//==============================================================================
// Test 2: Backend Selection
//==============================================================================
bool Test_BackendSelection() {
    PrintHeader("Test 2: Backend Selection");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Test AUTO selection
    registry.SetSelectionPolicy(SelectionPolicy::AUTO);
    IKernelBackend* autoBackend = registry.SelectBackend(KernelId::MatMul_Q4_Q8, 1024*1024);
    PrintResult("AUTO selection", autoBackend != nullptr);
    if (autoBackend) {
        std::cout << "    Selected: " << autoBackend->GetInfo().name << "\n";
    }
    
    // Test REFERENCE_ONLY
    registry.SetSelectionPolicy(SelectionPolicy::REFERENCE_ONLY);
    IKernelBackend* refBackend = registry.SelectBackend(KernelId::MatMul_Q4_Q8, 1024*1024);
    PrintResult("REFERENCE_ONLY selection", refBackend != nullptr);
    if (refBackend) {
        std::cout << "    Selected: " << refBackend->GetInfo().name << "\n";
    }
    
    return autoBackend != nullptr && refBackend != nullptr;
}

//==============================================================================
// Test 3: MatMul Numerical Validation
//==============================================================================
bool Test_MatMulValidation(const TestConfig& config) {
    PrintHeader("Test 3: MatMul Numerical Validation");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Allocate test matrices
    size_t M = config.matmulM;
    size_t N = config.matmulN;
    size_t K = config.matmulK;
    
    float* A = AllocateAlignedFloat(M * K);
    float* B = AllocateAlignedFloat(K * N);
    float* C_ref = AllocateAlignedFloat(M * N);
    float* C_test = AllocateAlignedFloat(M * N);
    
    // Initialize with simple pattern
    for (size_t i = 0; i < M * K; i++) A[i] = (float)(i % 10) / 10.0f;
    for (size_t i = 0; i < K * N; i++) B[i] = (float)(i % 10) / 10.0f;
    
    // Setup tensor descriptors
    TensorDesc descA{};
    descA.data = A;
    descA.sizeBytes = M * K * sizeof(float);
    descA.dims[0] = M;
    descA.dims[1] = K;
    descA.numDims = 2;
    descA.dtype = TensorDesc::DataType::F32;
    
    TensorDesc descB{};
    descB.data = B;
    descB.sizeBytes = K * N * sizeof(float);
    descB.dims[0] = K;
    descB.dims[1] = N;
    descB.numDims = 2;
    descB.dtype = TensorDesc::DataType::F32;
    
    TensorDesc descC{};
    descC.data = C_test;
    descC.sizeBytes = M * N * sizeof(float);
    descC.dims[0] = M;
    descC.dims[1] = N;
    descC.numDims = 2;
    descC.dtype = TensorDesc::DataType::F32;
    
    MatMulParams mmParams{};
    mmParams.M = M;
    mmParams.N = N;
    mmParams.K = K;
    
    // Test with Reference backend
    registry.SetSelectionPolicy(SelectionPolicy::REFERENCE_ONLY);
    IKernelBackend* refBackend = registry.SelectBackend(KernelId::MatMul_F32, M * K * sizeof(float));
    
    bool refSuccess = false;
    if (refBackend) {
        ExecutionStats refStats;
        refSuccess = refBackend->MatMul(descA, descB, descC, mmParams, &refStats);
        PrintResult("Reference MatMul execution", refSuccess);
        if (refSuccess) {
            std::cout << "    Time: " << refStats.executionTimeUs << " us\n";
            std::cout << "    GFLOP/s: " << std::fixed << std::setprecision(2) 
                      << refStats.gflops << "\n";
        }
    }
    
    // Copy reference result
    std::memcpy(C_ref, C_test, M * N * sizeof(float));
    
    // Test with other backends and compare
    auto backends = registry.ListBackends();
    bool allMatch = true;
    
    for (const auto& [id, info] : backends) {
        if (info.name == "Reference") continue;
        
        IKernelBackend* backend = registry.GetBackend(id);
        if (!backend || !backend->SupportsKernel(KernelId::MatMul_F32)) continue;
        
        // Execute
        ExecutionStats stats;
        bool success = backend->MatMul(descA, descB, descC, mmParams, &stats);
        
        std::cout << "\n  [" << info.name << "]\n";
        PrintResult("Execution", success);
        
        if (success) {
            std::cout << "    Time: " << stats.executionTimeUs << " us\n";
            std::cout << "    GFLOP/s: " << std::fixed << std::setprecision(2) 
                      << stats.gflops << "\n";
            
            // Compare with reference
            double maxError = 0.0;
            double sumError = 0.0;
            for (size_t i = 0; i < M * N; i++) {
                double diff = std::abs(C_test[i] - C_ref[i]);
                maxError = std::max(maxError, diff);
                sumError += diff * diff;
            }
            double rmsError = std::sqrt(sumError / (M * N));
            
            std::cout << "    Max error: " << std::scientific << maxError << "\n";
            std::cout << "    RMS error: " << std::scientific << rmsError << "\n";
            
            bool match = maxError < config.errorTolerance;
            PrintResult("Numerical match", match);
            allMatch = allMatch && match;
        }
    }
    
    // Cleanup
    FreeAligned(A);
    FreeAligned(B);
    FreeAligned(C_ref);
    FreeAligned(C_test);
    
    return refSuccess && allMatch;
}

//==============================================================================
// Test 4: Performance Comparison
//==============================================================================
bool Test_PerformanceComparison() {
    PrintHeader("Test 4: Performance Comparison");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Test different matrix sizes
    size_t sizes[] = {64, 128, 256, 512};
    
    std::cout << "\n  Matrix Size | Reference | Intrinsics | Speedup\n";
    std::cout << "  " << std::string(60, '-') << "\n";
    
    for (size_t size : sizes) {
        // Allocate
        float* A = AllocateAlignedFloat(size * size);
        float* B = AllocateAlignedFloat(size * size);
        float* C = AllocateAlignedFloat(size * size);
        
        // Initialize
        for (size_t i = 0; i < size * size; i++) {
            A[i] = (float)(i % 10) / 10.0f;
            B[i] = (float)(i % 10) / 10.0f;
        }
        
        // Setup descriptors
        TensorDesc descA{}, descB{}, descC{};
        descA.data = A; descA.sizeBytes = size * size * sizeof(float);
        descA.dims[0] = size; descA.dims[1] = size; descA.numDims = 2;
        descA.dtype = TensorDesc::DataType::F32;
        
        descB.data = B; descB.sizeBytes = size * size * sizeof(float);
        descB.dims[0] = size; descB.dims[1] = size; descB.numDims = 2;
        descB.dtype = TensorDesc::DataType::F32;
        
        descC.data = C; descC.sizeBytes = size * size * sizeof(float);
        descC.dims[0] = size; descC.dims[1] = size; descC.numDims = 2;
        descC.dtype = TensorDesc::DataType::F32;
        
        MatMulParams params{};
        params.M = params.N = params.K = size;
        
        // Benchmark Reference
        uint64_t refTime = 0;
        registry.SetSelectionPolicy(SelectionPolicy::REFERENCE_ONLY);
        IKernelBackend* ref = registry.SelectBackend(KernelId::MatMul_F32, size * size * sizeof(float));
        if (ref) {
            ExecutionStats stats;
            ref->MatMul(descA, descB, descC, params, &stats);
            refTime = stats.executionTimeUs;
        }
        
        // Benchmark Intrinsics
        uint64_t intrTime = 0;
        registry.SetSelectionPolicy(SelectionPolicy::FASTEST);
        IKernelBackend* intr = registry.SelectBackend(KernelId::MatMul_F32, size * size * sizeof(float));
        if (intr && intr->GetInfo().name != "Reference") {
            ExecutionStats stats;
            intr->MatMul(descA, descB, descC, params, &stats);
            intrTime = stats.executionTimeUs;
        }
        
        // Print results
        double speedup = intrTime > 0 ? (double)refTime / intrTime : 0.0;
        std::cout << "  " << std::setw(11) << size << "x" << size 
                  << " | " << std::setw(9) << refTime << " us"
                  << " | " << std::setw(10) << intrTime << " us"
                  << " | " << std::fixed << std::setprecision(2) 
                  << speedup << "x\n";
        
        // Cleanup
        FreeAligned(A);
        FreeAligned(B);
        FreeAligned(C);
    }
    
    return true;
}

//==============================================================================
// Main
//==============================================================================
int main() {
    std::cout << "======================================================================\n";
    std::cout << "Kernel Registry Validation Test\n";
    std::cout << "Phase 7C.1 - Backend Abstraction Layer\n";
    std::cout << "======================================================================\n";
    
    TestConfig config{};
    
    bool allPassed = true;
    
    allPassed &= Test_BackendRegistration();
    allPassed &= Test_BackendSelection();
    allPassed &= Test_MatMulValidation(config);
    allPassed &= Test_PerformanceComparison();
    
    PrintHeader("Final Results");
    std::cout << "Overall: " << (allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    std::cout << "\nNext Steps:\n";
    std::cout << "  1. Integrate KernelRegistry into SovereignGraphRunner\n";
    std::cout << "  2. Add MASM backend when available\n";
    std::cout << "  3. Add GPU (Vulkan/CUDA) backends\n";
    std::cout << "  4. Tune auto-selection heuristics\n";
    std::cout << "======================================================================\n";
    
    return allPassed ? 0 : 1;
}
