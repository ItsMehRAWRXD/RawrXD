// Phase 20: MASM Kernel Integration Bridge
// src/tests/e2e/kernel_bridge.cpp

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>

// MASM Kernel Declaration
extern "C" {
    // ApplyLoRA_Optimized.asm entry point
    // RCX=base_output, RDX=input, R8=result, R9=beacon_state, R10=token_count
    void ApplyLoRA_Optimized(float* base_output, float* input, float* result, 
                              void* beacon_state, uint64_t token_count);
}

// LoRA Beacon State (matches MASM layout exactly)
#pragma pack(push, 1)
struct alignas(64) LoRABeaconState {
    uint32_t version;
    uint32_t status;
    uint32_t rank;
    uint32_t hidden_dim;
    float* ptr_A;
    float* ptr_B;
    float scale_factor;
    float reserved;
    LoRABeaconState* next_adapter;
    float composite_weight;
    uint8_t padding[32];
};
#pragma pack(pop)

static_assert(sizeof(LoRABeaconState) == 64, "BeaconState must be 64 bytes");

// Aligned memory allocator for MASM
float* aligned_alloc_float(size_t count, size_t alignment = 64) {
    void* ptr = _aligned_malloc(count * sizeof(float), alignment);
    if (!ptr) throw std::bad_alloc();
    return static_cast<float*>(ptr);
}

void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// Shadow Run: Compare simulator vs MASM kernel
class KernelValidator {
public:
    bool RunShadowTest(int iterations = 100) {
        std::cout << "[ShadowRun] Phase 20 Kernel Validation" << std::endl;
        std::cout << "[ShadowRun] Running " << iterations << " shadow iterations..." << std::endl;
        
        // Test parameters
        const uint32_t rank = 8;
        const uint32_t hidden_dim = 128;
        const uint32_t tokens = 1;
        
        // Allocate aligned buffers
        float* base_output = aligned_alloc_float(hidden_dim);
        float* input = aligned_alloc_float(hidden_dim);
        float* result_sim = aligned_alloc_float(hidden_dim);
        float* result_masm = aligned_alloc_float(hidden_dim);
        
        // Allocate matrices
        float* matrix_A = aligned_alloc_float(rank * hidden_dim);
        float* matrix_B = aligned_alloc_float(hidden_dim * rank);
        
        // Initialize test data
        InitializeTestData(base_output, input, matrix_A, matrix_B, 
                          rank, hidden_dim);
        
        // Setup beacon state
        LoRABeaconState beacon = {};
        beacon.version = 1;
        beacon.status = 1; // Active
        beacon.rank = rank;
        beacon.hidden_dim = hidden_dim;
        beacon.ptr_A = matrix_A;
        beacon.ptr_B = matrix_B;
        beacon.scale_factor = 1.0f;
        beacon.next_adapter = nullptr;
        
        int passed = 0;
        int failed = 0;
        double max_error = 0.0;
        
        for (int i = 0; i < iterations; ++i) {
            // Clear results
            std::memset(result_sim, 0, hidden_dim * sizeof(float));
            std::memset(result_masm, 0, hidden_dim * sizeof(float));
            
            // Run simulator
            SimulateLoRA(base_output, input, result_sim, 
                        matrix_A, matrix_B, rank, hidden_dim);
            
            // Run MASM kernel
            ApplyLoRA_Optimized(base_output, input, result_masm, 
                               &beacon, tokens);
            
            // Compare
            double error = CompareResults(result_sim, result_masm, 
                                         hidden_dim, i + 1);
            max_error = std::max(max_error, error);
            
            if (error < 1e-4) {
                passed++;
            } else {
                failed++;
                if (failed <= 3) {
                    std::cerr << "  [ShadowRun] Iteration " << (i+1) 
                              << " FAILED (error=" << error << ")" << std::endl;
                }
            }
        }
        
        // Cleanup
        aligned_free(base_output);
        aligned_free(input);
        aligned_free(result_sim);
        aligned_free(result_masm);
        aligned_free(matrix_A);
        aligned_free(matrix_B);
        
        std::cout << std::endl;
        std::cout << "=== Shadow Run Results ===" << std::endl;
        std::cout << "Passed: " << passed << "/" << iterations << std::endl;
        std::cout << "Failed: " << failed << "/" << iterations << std::endl;
        std::cout << "Max Error: " << max_error << std::endl;
        
        bool success = (failed == 0);
        std::cout << "Status: " << (success ? "PASS ✓" : "FAIL ✗") << std::endl;
        
        if (success) {
            std::cout << std::endl;
            std::cout << "✓ MASM kernel math parity confirmed" << std::endl;
            std::cout << "✓ Ready for full integration" << std::endl;
        }
        
        return success;
    }
    
private:
    void InitializeTestData(float* base, float* input, float* A, float* B,
                           uint32_t rank, uint32_t hidden_dim) {
        // Initialize with deterministic pattern
        for (size_t i = 0; i < hidden_dim; ++i) {
            base[i] = static_cast<float>(i) * 0.01f;
            input[i] = static_cast<float>(i) * 0.001f;
        }
        
        for (size_t i = 0; i < rank * hidden_dim; ++i) {
            A[i] = static_cast<float>(i) * 0.0001f;
        }
        
        for (size_t i = 0; i < hidden_dim * rank; ++i) {
            B[i] = static_cast<float>(i) * 0.0001f;
        }
    }
    
    void SimulateLoRA(float* base, float* input, float* result,
                       float* A, float* B, uint32_t rank, uint32_t hidden_dim) {
        // Reference implementation: h = base + B * A * input
        
        // Step 1: temp = A * input (rank elements)
        std::vector<float> temp(rank, 0.0f);
        for (uint32_t r = 0; r < rank; ++r) {
            for (uint32_t h = 0; h < hidden_dim; ++h) {
                temp[r] += A[r * hidden_dim + h] * input[h];
            }
        }
        
        // Step 2: result = base + B * temp
        for (uint32_t h = 0; h < hidden_dim; ++h) {
            float sum = base[h];
            for (uint32_t r = 0; r < rank; ++r) {
                sum += B[h * rank + r] * temp[r];
            }
            result[h] = sum;
        }
    }
    
    double CompareResults(float* sim, float* masm, uint32_t count, int iter) {
        double max_err = 0.0;
        for (uint32_t i = 0; i < count; ++i) {
            double err = std::abs(sim[i] - masm[i]);
            max_err = std::max(max_err, err);
            
            if (err > 1e-3 && iter <= 3) {
                std::cerr << "    Index " << i << ": sim=" << sim[i] 
                          << " masm=" << masm[i] << std::endl;
            }
        }
        return max_err;
    }
};

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Phase 20: Kernel Shadow Run" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    KernelValidator validator;
    bool success = validator.RunShadowTest(100);
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << (success ? "Phase 20: READY FOR INTEGRATION" : "Phase 20: VALIDATION FAILED") << std::endl;
    std::cout << "========================================" << std::endl;
    
    return success ? 0 : 1;
}
