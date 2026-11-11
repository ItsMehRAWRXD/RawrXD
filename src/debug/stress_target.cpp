// ============================================================================
// stress_target.cpp
// High-frequency stepping stress test for debugger
// Validates producer/consumer rate mismatch handling
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Simple test program that executes a tight loop
// When attached to a debugger, this stresses the step/over/resume cycle

volatile uint64_t g_counter = 0;
volatile int g_running = 1;

void StressLoop() {
    // Tight computational loop - generates many instruction steps
    while (g_running) {
        // Mix of operations to exercise different instruction types
        g_counter++;
        
        // Some math to keep the CPU busy
        uint64_t temp = g_counter * 0x9E3779B97F4A7C15ULL;
        temp ^= temp >> 33;
        temp *= 0xBF58476D1CE4E5B9ULL;
        temp ^= temp >> 29;
        
        // Prevent optimization from removing the loop
        if (temp == 0xDEADBEEF) {
            printf("Impossible!\n");
        }
    }
}

void FunctionA() {
    for (int i = 0; i < 100; i++) {
        g_counter += i;
    }
}

void FunctionB() {
    for (int i = 0; i < 100; i++) {
        g_counter -= i;
    }
}

void FunctionC() {
    // Call A and B to create call stack depth
    FunctionA();
    FunctionB();
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD Debugger Stress Target\n");
    printf("========================================\n");
    printf("\nThis program is designed to be debugged.\n");
    printf("It executes a tight loop that stresses:\n");
    printf("  - Breakpoint handling\n");
    printf("  - Single-stepping throughput\n");
    printf("  - Call stack capture\n");
    printf("  - Register capture\n");
    printf("\nUsage:\n");
    printf("  1. Start this program\n");
    printf("  2. Attach RawrXD debugger\n");
    printf("  3. Set breakpoints, step, observe telemetry\n");
    printf("\nPress Ctrl+C to exit.\n\n");
    
    // Main stress loop with function calls
    while (g_running) {
        // Tight inner loop
        for (int i = 0; i < 1000000; i++) {
            g_counter++;
        }
        
        // Periodic function calls to create stack frames
        FunctionC();
        
        // Occasional sleep to allow debugger to catch up
        Sleep(1);
    }
    
    printf("Final counter: %llu\n", (unsigned long long)g_counter);
    return 0;
}
