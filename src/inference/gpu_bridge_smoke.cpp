// =============================================================================
// Sovereign GPU Bridge Smoke Test — PCIe Enumeration + VRAM Aperture Verification
// =============================================================================
#include "Sovereign_GPU_Bridge.h"
#include "inference_profiler_simple.h"
#include <cstdio>

int main() {
    printf("=== Sovereign GPU Bridge Smoke Test ===\n\n");
    
    // Initialize profiler
    Profiler_Initialize();
    
    // Initialize GPU bridge
    printf("[1/4] Initializing GPU Bridge...\n");
    {
        PROFILE_BLOCK("gpu_init");
        SovereignGPUHandle gpu = SovereignGPU_Initialize();
        if (!gpu) {
            printf("      ✗ Failed to initialize GPU bridge\n");
            printf("      Error: %s\n", SovereignGPU_GetErrorString(nullptr));
            return 1;
        }
        
        // Get capabilities
        SovereignGPUCaps caps = {};
        SovereignGPU_GetCaps(gpu, &caps);
        
        printf("      ✓ GPU Bridge initialized\n");
        printf("      Device: %04X:%04X\n", caps.vendorId, caps.deviceId);
        printf("      VRAM: %llu GB\n", caps.vramSize / (1024ULL*1024*1024));
        printf("      BAR: %llu MB\n", caps.barSize / (1024ULL*1024));
        printf("      Resizable BAR: %s\n", caps.resizableBAR ? "YES" : "NO");
        printf("      SAM: %s\n\n", caps.smartAccessMemory ? "YES" : "NO");
        
        // Run aperture test
        printf("[2/4] Running VRAM Aperture Test...\n");
        {
            PROFILE_BLOCK("aperture_test");
            int result = SovereignGPU_TestAperture(gpu);
            if (result != SOVEREIGN_GPU_OK) {
                printf("      ✗ Aperture test failed: %s\n", SovereignGPU_GetErrorString(gpu));
            }
        }
        printf("\n");
        
        // Dump state
        printf("[3/4] GPU Bridge State:\n");
        SovereignGPU_DumpState(gpu);
        printf("\n");
        
        // Shutdown
        printf("[4/4] Shutting down GPU Bridge...\n");
        {
            PROFILE_BLOCK("gpu_shutdown");
            SovereignGPU_Shutdown(gpu);
        }
        printf("      ✓ GPU Bridge shutdown complete\n\n");
    }
    
    // Dump profiler report
    printf("=== Profiler Report ===\n");
    rxdn::prof_dump();
    
    printf("\n=== Smoke Test Complete ===\n");
    printf("\nNext Steps:\n");
    printf("  1. Build MASM kernel driver for true BAR access\n");
    printf("  2. Run VRAM write/read pattern verification\n");
    printf("  3. Measure DMA latency with RDTSC\n");
    printf("  4. Integrate with llama.cpp for token injection\n");
    
    return 0;
}
