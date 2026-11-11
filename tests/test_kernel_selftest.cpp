//=============================================================================
// Kernel Registry Self-Test
// Validates runtime kernel validation
//=============================================================================

#include <cstdio>
#include "../src/kernels/KernelRegistry.hpp"

using namespace RawrXD::Kernels;

int main() {
    printf("Kernel Registry Self-Test\n");
    printf("=========================\n\n");
    
    // Initialize registry
    KernelRegistry::Initialize();
    
    // Print diagnostics
    KernelRegistry::PrintDiagnostics();
    
    // Run self-test
    printf("Running self-test...\n");
    bool passed = KernelRegistry::RunSelfTest();
    
    if (passed) {
        printf("\n✓ Self-test PASSED\n");
        printf("  Kernel is production ready\n");
        return 0;
    } else {
        printf("\n✗ Self-test FAILED\n");
        printf("  Kernel will not be used\n");
        return 1;
    }
}
