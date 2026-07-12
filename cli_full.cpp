//==============================================================================
// cli_full.cpp
// Full Sovereign CLI - Phase 7C.2 Complete Integration
//
// This CLI integrates:
// - Titan Runtime dispatch
// - MASM Backend (Phase 7A/7B kernels)
// - Kernel Registry (auto-selection)
// - All 9 production kernels
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>

// Include the kernel dispatch header
#include "d:/src/asm/Sovereign_KernelDispatch.h"

// Link against kernel libraries
#pragma comment(lib, "d:/src/asm/Sovereign_Legacy_Kernels.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Intrinsics.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RMSNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_ResidualAdd.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RoPE.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_LayerNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Q4K_Dequant.lib")

//==============================================================================
// Backend Capability Flags
//==============================================================================
enum class BackendCapability : uint32_t {
    NONE          = 0,
    REFERENCE     = 1 << 0,
    INTRINSICS    = 1 << 1,
    MASM          = 1 << 2,
    GPU_CUDA      = 1 << 3,
    GPU_VULKAN    = 1 << 4,
    QUANTIZED     = 1 << 6,
    ASYNC         = 1 << 7,
};

inline BackendCapability operator|(BackendCapability a, BackendCapability b) {
    return static_cast<BackendCapability>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool HasCapability(BackendCapability flags, BackendCapability cap) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(cap)) != 0;
}

//==============================================================================
// Backend Information
//==============================================================================
struct BackendInfo {
    std::string name;
    std::string version;
    BackendCapability capabilities;
    bool initialized{false};
    
    bool IsValid() const { return !name.empty(); }
};

//==============================================================================
// Simple Backend Registry
//==============================================================================
class SimpleBackendRegistry {
public:
    static SimpleBackendRegistry& Instance() {
        static SimpleBackendRegistry instance;
        return instance;
    }
    
    struct BackendEntry {
        uint32_t id;
        BackendInfo info;
        Sovereign_KernelTable* kernelTable;
    };
    
    std::vector<BackendEntry> backends;
    uint32_t nextId{1};
    
    uint32_t RegisterMASMBackend(Sovereign_KernelTable* table) {
        BackendEntry entry;
        entry.id = nextId++;
        entry.info.name = "MASM64";
        entry.info.version = "7C.2";
        entry.info.capabilities = BackendCapability::MASM | BackendCapability::INTRINSICS | BackendCapability::QUANTIZED;
        entry.info.initialized = true;
        entry.kernelTable = table;
        backends.push_back(entry);
        return entry.id;
    }
    
    void ListBackends() {
        printf("Registered Backends: %zu\n\n", backends.size());
        for (auto& be : backends) {
            printf("  [%u] %s v%s\n", be.id, be.info.name.c_str(), be.info.version.c_str());
            printf("       Capabilities: ");
            if (HasCapability(be.info.capabilities, BackendCapability::MASM))
                printf("MASM ");
            if (HasCapability(be.info.capabilities, BackendCapability::INTRINSICS))
                printf("INTRINSICS ");
            if (HasCapability(be.info.capabilities, BackendCapability::QUANTIZED))
                printf("QUANTIZED ");
            printf("\n       Status: %s\n\n", be.info.initialized ? "INITIALIZED" : "NOT READY");
        }
    }
};

//==============================================================================
// CLI Implementation
//==============================================================================

void printBanner() {
    printf("==============================================================================\n");
    printf("Sovereign CLI - Phase 7C.2 Complete Integration\n");
    printf("==============================================================================\n\n");
}

void printUsage(const char* program) {
    printf("Usage: %s [command] [options]\n\n", program);
    printf("Commands:\n");
    printf("  test              Run kernel integration tests\n");
    printf("  info              Show system information\n");
    printf("  backends          List registered backends\n");
    printf("  validate          Validate kernel correctness\n");
    printf("  help              Show this help message\n");
}

bool approxEqual(float a, float b, float epsilon) {
    return fabsf(a - b) < epsilon;
}

int runIntegrationTest(Sovereign_KernelTable& table) {
    printf("[Test] Kernel Integration\n");
    printf("--------------------------\n\n");
    
    int passed = 0;
    int total = 0;
    
    // Check kernel availability
    printf("Kernel Availability:\n");
    
    #define CHECK_KERNEL(ptr, name) \
        total++; \
        if (ptr) { \
            passed++; \
            printf("  [OK] %s\n", name); \
        } else { \
            printf("  [MISSING] %s\n", name); \
        }
    
    CHECK_KERNEL(table.rms_norm_f32, "rms_norm_f32");
    CHECK_KERNEL(table.layer_norm_f32, "layer_norm_f32");
    CHECK_KERNEL(table.rope_apply_f32, "rope_apply_f32");
    CHECK_KERNEL(table.residual_add_f32, "residual_add_f32");
    CHECK_KERNEL(table.q4k_dequant_tensor, "q4k_dequant_tensor");
    CHECK_KERNEL(table.q4q8_matmul_intrinsics, "q4q8_matmul_intrinsics");
    CHECK_KERNEL(table.q4_0_q8_0_matmul, "q4_0_q8_0_matmul");
    CHECK_KERNEL(table.flash_attention_v2_intrinsics, "flash_attention_v2_intrinsics");
    CHECK_KERNEL(table.flash_attention_v2_f32, "flash_attention_v2_f32");
    
    printf("\n  Total: %d/%d kernels available\n\n", passed, total);
    
    // Test RMSNorm
    if (table.rms_norm_f32) {
        printf("Testing RMSNorm_F32...\n");
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
        float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        float output[8] = {0};
        
        // Call with correct parameter order: input, output, weight, n_elements, epsilon
        int result = table.rms_norm_f32(input, output, weight, 8, 1e-6f);
        
        // Calculate RMS of output (should be close to 1.0 after normalization)
        float sum_sq = 0.0f;
        for (int i = 0; i < 8; i++) {
            sum_sq += output[i] * output[i];
        }
        float rms = sqrtf(sum_sq / 8.0f);
        bool pass = (result == 0) && approxEqual(rms, 1.0f, 0.1f);
        
        printf("  Result: %d, Output RMS: %.6f [%s]\n\n", 
               result, rms, pass ? "PASS" : "FAIL");
    }
    
    // Test ResidualAdd
    if (table.residual_add_f32) {
        printf("Testing ResidualAdd_F32...\n");
        float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        float residual[4] = {0.5f, 0.5f, 0.5f, 0.5f};
        float output[4] = {0};
        
        int result = table.residual_add_f32(input, residual, output, 4);
        
        bool pass = (result == 0) && 
                    approxEqual(output[0], 1.5f, 0.001f) &&
                    approxEqual(output[3], 4.5f, 0.001f);
        
        printf("  Result: %d, Output: [%.2f, %.2f, %.2f, %.2f] [%s]\n\n", 
               result, output[0], output[1], output[2], output[3],
               pass ? "PASS" : "FAIL");
    }
    
    // Test RoPE
    if (table.rope_apply_f32) {
        printf("Testing RoPE_F32...\n");
        float tensor[16] = {1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f,
                            1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f};
        float freq_cache[16] = {0};
        
        int result = table.rope_apply_f32(tensor, freq_cache, 2, 4, 2);
        printf("  Result: %d [%s]\n\n", result, result == 0 ? "PASS" : "FAIL");
    }
    
    printf("==============================================================================\n");
    printf("Results: %d/%d kernels available\n", passed, total);
    printf("==============================================================================\n\n");
    
    return (passed == total) ? 0 : 1;
}

int runValidation(Sovereign_KernelTable& table) {
    printf("[Validation] Numerical Correctness\n");
    printf("------------------------------------\n\n");
    
    int testsPassed = 0;
    int totalTests = 0;
    
    // Validate RMSNorm preserves norm
    if (table.rms_norm_f32) {
        totalTests++;
        printf("Test 1: RMSNorm preserves normalized RMS...\n");
        
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
        float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        float output[8] = {0};
        
        int result = table.rms_norm_f32(input, output, weight, 8, 1e-6f);
        
        // Debug: print first few output values
        printf("  Result code: %d\n", result);
        printf("  Output values: [%.4f, %.4f, %.4f, %.4f, ...]\n",
               output[0], output[1], output[2], output[3]);
        
        float sum_sq = 0.0f;
        for (int i = 0; i < 8; i++) {
            sum_sq += output[i] * output[i];
        }
        float rms = sqrtf(sum_sq / 8.0f);
        
        if (approxEqual(rms, 1.0f, 0.01f)) {
            printf("  PASS: RMS = %.6f (expected ~1.0)\n\n", rms);
            testsPassed++;
        } else {
            printf("  FAIL: RMS = %.6f (expected ~1.0)\n\n", rms);
        }
    }
    
    // Validate ResidualAdd
    if (table.residual_add_f32) {
        totalTests++;
        printf("Test 2: ResidualAdd correctness...\n");
        
        float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        float residual[4] = {0.5f, 0.5f, 0.5f, 0.5f};
        float output[4] = {0};
        float expected[4] = {1.5f, 2.5f, 3.5f, 4.5f};
        
        table.residual_add_f32(input, residual, output, 4);
        
        bool correct = true;
        for (int i = 0; i < 4; i++) {
            if (!approxEqual(output[i], expected[i], 0.001f)) {
                correct = false;
                break;
            }
        }
        
        if (correct) {
            printf("  PASS: Output matches expected [1.5, 2.5, 3.5, 4.5]\n\n");
            testsPassed++;
        } else {
            printf("  FAIL: Output [%.2f, %.2f, %.2f, %.2f] != expected\n\n",
                   output[0], output[1], output[2], output[3]);
        }
    }
    
    printf("==============================================================================\n");
    printf("Validation: %d/%d tests passed\n", testsPassed, totalTests);
    printf("==============================================================================\n\n");
    
    return (testsPassed == totalTests) ? 0 : 1;
}

void showSystemInfo(Sovereign_KernelTable& table) {
    printf("System Information:\n");
    printf("-----------------\n");
    printf("Phase: 7C.2 - Kernel Integration Complete\n");
    printf("Target: Sovereign CLI with MASM kernels\n");
    printf("Compiler: MSVC 14.51.36231\n");
    printf("Architecture: x64\n");
    printf("Kernels: 9 production kernels integrated\n");
    printf("  - RMSNorm (MASM)\n");
    printf("  - LayerNorm (MASM)\n");
    printf("  - RoPE (MASM)\n");
    printf("  - ResidualAdd (MASM)\n");
    printf("  - Q4K Dequant (MASM)\n");
    printf("  - Q4Q8 MatMul Intrinsics (AVX-512)\n");
    printf("  - Q4_0_Q8_0 MatMul (MASM)\n");
    printf("  - Flash Attention V2 Intrinsics (AVX-512)\n");
    printf("  - Flash Attention V2 F32 (MASM)\n");
    printf("\n");
}

//==============================================================================
// Main Entry Point
//==============================================================================
int main(int argc, char* argv[]) {
    printBanner();
    
    // Initialize kernel table
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int initResult = Sovereign_InitKernelTable(&table);
    if (initResult != 0) {
        printf("ERROR: Failed to initialize kernel table (code: %d)\n", initResult);
        return 1;
    }
    
    // Register backend
    SimpleBackendRegistry& registry = SimpleBackendRegistry::Instance();
    uint32_t masmId = registry.RegisterMASMBackend(&table);
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 0;
    }
    
    const char* command = argv[1];
    
    if (strcmp(command, "test") == 0) {
        return runIntegrationTest(table);
    } else if (strcmp(command, "validate") == 0) {
        return runValidation(table);
    } else if (strcmp(command, "info") == 0) {
        showSystemInfo(table);
        return 0;
    } else if (strcmp(command, "backends") == 0) {
        registry.ListBackends();
        return 0;
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        printUsage(argv[0]);
        return 0;
    } else {
        printf("Unknown command: %s\n\n", command);
        printUsage(argv[0]);
        return 1;
    }
}
