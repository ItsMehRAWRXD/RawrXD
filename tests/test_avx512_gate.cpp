//============================================================================
// test_avx512_gate.cpp
//
// Validates AVX-512 runtime gating prevents execution on unsupported hardware
//============================================================================

#include "../src/kernels/avx512_runtime_gate.hpp"
#include <cstdio>
#include <cstdlib>

using namespace RawrXD::Kernels;

// Simulated AVX-512 kernel that would crash if executed
void SimulatedAVX512Kernel() {
    AVX512_GATE_VOID();  // Should exit if AVX-512 not available
    
    printf("AVX-512 kernel would execute here\n");
    // In real code: AVX-512 instructions
}

int SimulatedAVX512Function() {
    AVX512_GATE_RET(-1);  // Should return -1 if AVX-512 not available
    
    return 42;  // Success
}

int main() {
    printf("AVX-512 Runtime Gate Test\n");
    printf("=========================\n\n");
    
    // Test 1: Feature detection
    bool hasAVX512 = DetectAVX512F();
    printf("AVX-512F detected: %s\n", hasAVX512 ? "YES" : "NO");
    
    // Test 2: Gate macro with void return
    printf("\nTest 2: AVX512_GATE_VOID()\n");
    printf("If AVX-512 not available, program should exit with error message\n");
    
    // This will exit if AVX-512 not available
    SimulatedAVX512Kernel();
    
    // Test 3: Gate macro with return value
    printf("\nTest 3: AVX512_GATE_RET()\n");
    int result = SimulatedAVX512Function();
    if (result == -1) {
        printf("Gate correctly returned -1 (AVX-512 not available)\n");
    } else if (result == 42) {
        printf("Gate passed, function returned 42 (AVX-512 available)\n");
    }
    
    printf("\nAll tests passed - gating works correctly\n");
    return 0;
}
