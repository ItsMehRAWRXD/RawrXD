//==============================================================================
// SovereignCLI_Integrated.cpp
// Full CLI with MASM Backend + Memory Bridge + Kernel Registry
//
// Phase 7 Complete Integration
// Date: July 10, 2026
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

// Core headers
#include "../core/execution/IKernelBackend.hpp"
#include "../core/execution/MASMBackend.hpp"
#include "../../../../src/asm/SovereignMemoryBridge.hpp"
#include "../core/execution/SovereignKernelTypes.hpp"

using namespace sovereign;

//==============================================================================
// CLI Commands
//==============================================================================

void PrintUsage(const char* prog) {
    printf("Sovereign CLI - Phase 7 Complete\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  run <model>     Run inference with model\n");
    printf("  benchmark       Run kernel benchmarks\n");
    printf("  validate        Validate kernel correctness\n");
    printf("  status          Show system status\n");
    printf("  memory          Show memory bridge status\n");
    printf("\nOptions:\n");
    printf("  --backend <name>  Select backend (masm/intrinsics/reference)\n");
    printf("  --prompt <text>   Prompt for inference\n");
    printf("  --tokens <n>      Max tokens to generate\n");
    printf("  --verbose         Enable verbose output\n");
}

//==============================================================================
// Status Command
//==============================================================================

int CmdStatus() {
    printf("==============================================================================\n");
    printf("Sovereign System Status\n");
    printf("==============================================================================\n\n");
    
    // Initialize registry
    KernelRegistry& registry = KernelRegistry::Instance();
    if (!registry.Initialize()) {
        printf("ERROR: Failed to initialize KernelRegistry\n");
        return 1;
    }
    
    // Get backend info
    auto* masm = registry.GetBackend("MASM");
    auto* intrinsics = registry.GetBackend("Intrinsics");
    auto* reference = registry.GetBackend("Reference");
    
    printf("Backends:\n");
    printf("  MASM:        %s\n", masm ? "AVAILABLE" : "NOT FOUND");
    printf("  Intrinsics:  %s\n", intrinsics ? "AVAILABLE" : "NOT FOUND");
    printf("  Reference:   %s\n", reference ? "AVAILABLE" : "NOT FOUND");
    
    if (masm) {
        auto info = masm->GetInfo();
        printf("\nMASM Backend:\n");
        printf("  Version:     %s\n", info.version.c_str());
        printf("  Capabilities:");
        if (HasCapability(info.capabilities, BackendCapability::MASM)) printf(" MASM");
        if (HasCapability(info.capabilities, BackendCapability::INTRINSICS)) printf(" INTRINSICS");
        if (HasCapability(info.capabilities, BackendCapability::QUANTIZED)) printf(" QUANTIZED");
        printf("\n");
    }
    
    // Memory bridge status
    auto& bridge = MemoryBridge::Instance();
    uint64_t hostUsed, deviceUsed, pinnedUsed, totalAllocated;
    bridge.GetStats(hostUsed, deviceUsed, pinnedUsed, totalAllocated);
    
    printf("\nMemory Bridge:\n");
    printf("  Host (DDR5):   %6.2f GB used\n", hostUsed / (1024.0 * 1024 * 1024));
    printf("  Device (VRAM): %6.2f GB used\n", deviceUsed / (1024.0 * 1024 * 1024));
    printf("  Pinned:        %6.2f GB used\n", pinnedUsed / (1024.0 * 1024 * 1024));
    printf("  Total:         %6.2f GB unified\n", 
           (hostUsed + deviceUsed) / (1024.0 * 1024 * 1024));
    
    printf("\n==============================================================================\n");
    
    return 0;
}

//==============================================================================
// Benchmark Command
//==============================================================================

int CmdBenchmark(const char* backendName, bool verbose) {
    printf("==============================================================================\n");
    printf("Sovereign Kernel Benchmark\n");
    printf("Backend: %s\n", backendName ? backendName : "AUTO");
    printf("==============================================================================\n\n");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    if (!registry.Initialize()) {
        printf("ERROR: Failed to initialize KernelRegistry\n");
        return 1;
    }
    
    // Select backend
    IKernelBackend* backend = nullptr;
    if (backendName) {
        backend = registry.GetBackend(backendName);
        if (!backend) {
            printf("ERROR: Backend '%s' not found\n", backendName);
            return 1;
        }
    } else {
        // Auto-select best backend
        backend = registry.SelectBackend(KernelId::MatMul_F32_F32, 1024 * 1024);
    }
    
    auto info = backend->GetInfo();
    printf("Using backend: %s v%s\n\n", info.name.c_str(), info.version.c_str());
    
    // Benchmark RMSNorm
    printf("Benchmarking RMSNorm (4096 elements)...\n");
    {
        TensorDesc input{}, weight{}, output{};
        input.data = new float[4096];
        input.dims[0] = 4096; input.numDims = 1;
        input.dtype = TensorDesc::DataType::F32;
        input.sizeBytes = 4096 * sizeof(float);
        
        weight.data = new float[4096];
        weight.dims[0] = 4096; weight.numDims = 1;
        weight.dtype = TensorDesc::DataType::F32;
        weight.sizeBytes = 4096 * sizeof(float);
        
        output.data = new float[4096];
        output.dims[0] = 4096; output.numDims = 1;
        output.dtype = TensorDesc::DataType::F32;
        output.sizeBytes = 4096 * sizeof(float);
        
        // Initialize
        for (int i = 0; i < 4096; i++) {
            ((float*)input.data)[i] = 1.0f;
            ((float*)weight.data)[i] = 1.0f;
        }
        
        ExecutionStats stats{};
        bool ok = backend->RMSNorm(input, weight, output, 1e-6f, &stats);
        
        if (ok) {
            printf("  Time: %llu us\n", stats.executionTimeUs);
            printf("  Throughput: %.2f GB/s\n", 
                   (input.sizeBytes + output.sizeBytes) / (1024.0 * 1024 * 1024) / 
                   (stats.executionTimeUs / 1e6));
        } else {
            printf("  FAILED\n");
        }
        
        delete[] (float*)input.data;
        delete[] (float*)weight.data;
        delete[] (float*)output.data;
    }
    
    // Benchmark ResidualAdd
    printf("\nBenchmarking ResidualAdd (4096 elements)...\n");
    {
        TensorDesc input{}, residual{}, output{};
        input.data = new float[4096];
        input.dims[0] = 4096; input.numDims = 1;
        input.dtype = TensorDesc::DataType::F32;
        input.sizeBytes = 4096 * sizeof(float);
        
        residual.data = new float[4096];
        residual.dims[0] = 4096; residual.numDims = 1;
        residual.dtype = TensorDesc::DataType::F32;
        residual.sizeBytes = 4096 * sizeof(float);
        
        output.data = new float[4096];
        output.dims[0] = 4096; output.numDims = 1;
        output.dtype = TensorDesc::DataType::F32;
        output.sizeBytes = 4096 * sizeof(float);
        
        ExecutionStats stats{};
        bool ok = backend->ResidualAdd(input, residual, output, &stats);
        
        if (ok) {
            printf("  Time: %llu us\n", stats.executionTimeUs);
        } else {
            printf("  FAILED\n");
        }
        
        delete[] (float*)input.data;
        delete[] (float*)residual.data;
        delete[] (float*)output.data;
    }
    
    printf("\n==============================================================================\n");
    
    return 0;
}

//==============================================================================
// Validate Command
//==============================================================================

int CmdValidate() {
    printf("==============================================================================\n");
    printf("Sovereign Kernel Validation\n");
    printf("==============================================================================\n\n");
    
    KernelRegistry& registry = KernelRegistry::Instance();
    if (!registry.Initialize()) {
        printf("ERROR: Failed to initialize KernelRegistry\n");
        return 1;
    }
    
    // Get all backends
    auto* masm = registry.GetBackend("MASM");
    auto* intrinsics = registry.GetBackend("Intrinsics");
    auto* reference = registry.GetBackend("Reference");
    
    int totalTests = 0;
    int passedTests = 0;
    
    // Test RMSNorm
    printf("Testing RMSNorm...\n");
    totalTests++;
    {
        // Create test data
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
        float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        float output[8] = {0};
        
        TensorDesc inDesc{}, wDesc{}, outDesc{};
        inDesc.data = input; inDesc.dims[0] = 8; inDesc.numDims = 1;
        inDesc.dtype = TensorDesc::DataType::F32;
        
        wDesc.data = weight; wDesc.dims[0] = 8; wDesc.numDims = 1;
        wDesc.dtype = TensorDesc::DataType::F32;
        
        outDesc.data = output; outDesc.dims[0] = 8; outDesc.numDims = 1;
        outDesc.dtype = TensorDesc::DataType::F32;
        
        bool ok = false;
        if (masm) {
            ok = masm->RMSNorm(inDesc, wDesc, outDesc, 1e-6f, nullptr);
        } else if (reference) {
            ok = reference->RMSNorm(inDesc, wDesc, outDesc, 1e-6f, nullptr);
        }
        
        if (ok) {
            // Check output RMS is ~1.0
            float sum_sq = 0;
            for (int i = 0; i < 8; i++) sum_sq += output[i] * output[i];
            float rms = sqrt(sum_sq / 8);
            
            if (rms > 0.99f && rms < 1.01f) {
                printf("  [PASS] RMSNorm (RMS=%.4f)\n", rms);
                passedTests++;
            } else {
                printf("  [FAIL] RMSNorm (RMS=%.4f, expected ~1.0)\n", rms);
            }
        } else {
            printf("  [FAIL] RMSNorm (kernel error)\n");
        }
    }
    
    // Test ResidualAdd
    printf("\nTesting ResidualAdd...\n");
    totalTests++;
    {
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
        float residual[8] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
        float output[8] = {0};
        
        TensorDesc inDesc{}, resDesc{}, outDesc{};
        inDesc.data = input; inDesc.dims[0] = 8; inDesc.numDims = 1;
        inDesc.dtype = TensorDesc::DataType::F32;
        
        resDesc.data = residual; resDesc.dims[0] = 8; resDesc.numDims = 1;
        resDesc.dtype = TensorDesc::DataType::F32;
        
        outDesc.data = output; outDesc.dims[0] = 8; outDesc.numDims = 1;
        outDesc.dtype = TensorDesc::DataType::F32;
        
        bool ok = false;
        if (masm) {
            ok = masm->ResidualAdd(inDesc, resDesc, outDesc, nullptr);
        } else if (reference) {
            ok = reference->ResidualAdd(inDesc, resDesc, outDesc, nullptr);
        }
        
        if (ok) {
            // Check output = input + residual
            bool correct = true;
            for (int i = 0; i < 8; i++) {
                if (output[i] != input[i] + residual[i]) {
                    correct = false;
                    break;
                }
            }
            
            if (correct) {
                printf("  [PASS] ResidualAdd\n");
                passedTests++;
            } else {
                printf("  [FAIL] ResidualAdd (wrong output)\n");
            }
        } else {
            printf("  [FAIL] ResidualAdd (kernel error)\n");
        }
    }
    
    printf("\n==============================================================================\n");
    printf("Results: %d/%d passed\n", passedTests, totalTests);
    printf("==============================================================================\n");
    
    return (passedTests == totalTests) ? 0 : 1;
}

//==============================================================================
// Memory Command
//==============================================================================

int CmdMemory() {
    printf("==============================================================================\n");
    printf("Sovereign Memory Bridge Status\n");
    printf("==============================================================================\n\n");
    
    auto& bridge = MemoryBridge::Instance();
    
    if (!bridge.Initialize()) {
        printf("ERROR: Failed to initialize MemoryBridge\n");
        return 1;
    }
    
    uint64_t hostUsed, deviceUsed, pinnedUsed, totalAllocated;
    bridge.GetStats(hostUsed, deviceUsed, pinnedUsed, totalAllocated);
    
    printf("Memory Configuration:\n");
    printf("  DDR5 (Host):   64 GB\n");
    printf("  VRAM (Device): 16 GB\n");
    printf("  Pinned:        4 GB\n");
    printf("  Unified Total: 80 GB\n\n");
    
    printf("Current Usage:\n");
    printf("  Host:   %8.2f MB (%5.2f%%)\n", 
           hostUsed / (1024.0 * 1024), 
           100.0 * hostUsed / (64ULL * 1024 * 1024 * 1024));
    printf("  Device: %8.2f MB (%5.2f%%)\n", 
           deviceUsed / (1024.0 * 1024),
           100.0 * deviceUsed / (16ULL * 1024 * 1024 * 1024));
    printf("  Pinned: %8.2f MB (%5.2f%%)\n", 
           pinnedUsed / (1024.0 * 1024),
           100.0 * pinnedUsed / (4ULL * 1024 * 1024 * 1024));
    printf("  Total:  %8.2f MB\n", 
           (hostUsed + deviceUsed + pinnedUsed) / (1024.0 * 1024));
    
    printf("\n==============================================================================\n");
    
    return 0;
}

//==============================================================================
// Main
//==============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    const char* command = argv[1];
    const char* backend = nullptr;
    bool verbose = false;
    
    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            backend = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        }
    }
    
    if (strcmp(command, "status") == 0) {
        return CmdStatus();
    } else if (strcmp(command, "benchmark") == 0) {
        return CmdBenchmark(backend, verbose);
    } else if (strcmp(command, "validate") == 0) {
        return CmdValidate();
    } else if (strcmp(command, "memory") == 0) {
        return CmdMemory();
    } else {
        printf("Unknown command: %s\n", command);
        PrintUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
