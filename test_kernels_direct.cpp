// Test direct kernel calls
#include <iostream>
#include <cstring>

extern "C" {
    #include "src/asm/Sovereign_KernelDispatch.h"
}

int main() {
    std::cout << "Testing Sovereign Kernel Direct Calls\n";
    std::cout << "=====================================\n\n";
    
    // Initialize kernel table
    Sovereign_KernelTable table;
    int result = Sovereign_InitKernelTable(&table);
    
    if (result != 0) {
        std::cerr << "Failed to initialize kernel table: " << result << "\n";
        return 1;
    }
    
    std::cout << "Kernel table initialized successfully\n";
    std::cout << "Version: " << Sovereign_GetKernelVersion() << "\n\n";
    
    // Test RMSNorm
    std::cout << "Testing RMSNorm kernel...\n";
    alignas(64) float input[64] = {1.0f, 2.0f, 3.0f, 4.0f};
    alignas(64) float output[64] = {0};
    alignas(64) float weight[64] = {1.0f};
    
    if (table.rms_norm_f32) {
        int rms_result = table.rms_norm_f32(input, output, weight, 64, 1e-6f);
        std::cout << "  RMSNorm result: " << rms_result << "\n";
        std::cout << "  Output[0]: " << output[0] << "\n";
        std::cout << "  ✅ RMSNorm kernel callable\n\n";
    } else {
        std::cout << "  ❌ RMSNorm kernel not available\n\n";
    }
    
    // Test LayerNorm
    std::cout << "Testing LayerNorm kernel...\n";
    alignas(64) float gamma[64] = {1.0f};
    alignas(64) float beta[64] = {0.0f};
    memset(output, 0, sizeof(output));
    
    if (table.layer_norm_f32) {
        int ln_result = table.layer_norm_f32(input, output, gamma, beta, 64, 1e-6f);
        std::cout << "  LayerNorm result: " << ln_result << "\n";
        std::cout << "  Output[0]: " << output[0] << "\n";
        std::cout << "  ✅ LayerNorm kernel callable\n\n";
    } else {
        std::cout << "  ❌ LayerNorm kernel not available\n\n";
    }
    
    // Test ResidualAdd
    std::cout << "Testing ResidualAdd kernel...\n";
    alignas(64) float residual[64] = {0.5f};
    memset(output, 0, sizeof(output));
    
    if (table.residual_add_f32) {
        int res_result = table.residual_add_f32(input, residual, output, 64);
        std::cout << "  ResidualAdd result: " << res_result << "\n";
        std::cout << "  Output[0]: " << output[0] << " (expected: 1.5)\n";
        std::cout << "  ✅ ResidualAdd kernel callable\n\n";
    } else {
        std::cout << "  ❌ ResidualAdd kernel not available\n\n";
    }
    
    std::cout << "=====================================\n";
    std::cout << "Kernel test complete!\n";
    
    return 0;
}
