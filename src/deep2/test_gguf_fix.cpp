//=============================================================================
// test_gguf_fix.cpp - Quick test for GGUF loading fixes
//=============================================================================

#include "GGUFLoader.hpp"
#include "GGUFDiagnostics.hpp"
#include <cstdio>
#include "gguf_loader.h"

using namespace Deep2;

int main(int argc, char** argv) {
    printf("========================================\n");
    printf("  GGUF Fix Verification Test\n");
    printf("========================================\n\n");
    
    const char* testFile = (argc > 1) ? argv[1] : "model.gguf";
    
    printf("Testing file: %s\n\n", testFile);
    
    // Run diagnostics
    printf("Running diagnostics...\n");
    auto diag = GGUFDiagnostics::RunFullDiagnostic(testFile);
    diag.Print();
    
    if (!diag.dataLoadable) {
        printf("\nDiagnostics failed. Attempting to load anyway...\n");
    }
    
    // Try to load with verbose output
    printf("\nAttempting full load with verbose output...\n");
    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = true;
    opts.maxMemoryMB = 0;
    
    GGUFLoadResult result = GGUFLoader::Load(testFile, opts);
    
    if (result.success) {
        printf("\n✓ Load successful!\n");
        printf("  Tensors: %zu\n", result.tensors.size());
        printf("  Total size: %.2f MB\n", result.totalSize / (1024.0 * 1024.0));
        printf("  Time: %.2f ms\n", result.loadTimeMs);
        
        // Verify memory alignment
        printf("\nVerifying memory alignment...\n");
        int aligned = 0, misaligned = 0;
        for (const auto& t : result.tensors) {
            if (GGUFDiagnostics::CheckAlignment(t.data, 64)) {
                aligned++;
            } else {
                misaligned++;
                printf("  Misaligned: %s\n", t.name.c_str());
            }
        }
        printf("  Aligned: %d, Misaligned: %d\n", aligned, misaligned);
        
        // Validate memory ranges
        printf("\nValidating memory ranges...\n");
        int valid = 0, invalid = 0;
        for (const auto& t : result.tensors) {
            if (GGUFDiagnostics::ValidateMemoryRange(t.data, t.size)) {
                valid++;
            } else {
                invalid++;
                printf("  Invalid: %s\n", t.name.c_str());
            }
        }
        printf("  Valid: %d, Invalid: %d\n", valid, invalid);
        
        return (invalid == 0) ? 0 : 1;
    } else {
        printf("\n✗ Load failed: %s\n", result.error);
        return 1;
    }
}

