// ============================================================================
// simple_rmsnorm.cpp - Simple RMSNorm test with hardcoded values
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External MASM kernel with simplified signature
extern "C" void SimpleRMSNorm();

int main() {
    printf("Testing Simple RMSNorm...\n");
    
    printf("About to call SimpleRMSNorm...\n");
    fflush(stdout);
    
    // Call a simple version that doesn't take parameters
    SimpleRMSNorm();
    
    printf("SimpleRMSNorm completed.\n");
    
    return 0;
}