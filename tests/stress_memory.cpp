// stress_memory.cpp
// Memory/register pressure test for debugger
// Tests large stack frames and register churn

#include <stdint.h>

// Large structure to stress local variable parsing
struct TestObject {
    uint64_t values[1024];      // 8KB of data
    double matrix[16][16];       // 2KB matrix
    char name[256];              // String data
    uint32_t flags;              // Scalar
};

// Function with many locals to stress register allocation
void HeavyFunction(int depth) {
    volatile int a = depth;
    volatile int b = depth * 2;
    volatile int c = depth * 3;
    volatile int d = depth * 4;
    volatile int e = depth * 5;
    volatile int f = depth * 6;
    volatile int g = depth * 7;
    volatile int h = depth * 8;
    
    // BREAKPOINT HERE - inspect locals
    a = b + c + d + e + f + g + h;  // Use all variables
}

int main() {
    TestObject obj{};
    
    // Initialize with recognizable patterns
    for (int i = 0; i < 1024; i++) {
        obj.values[i] = 0xDEADBEEF00000000ULL + i;
    }
    
    // Tight loop with heavy function calls
    // Set breakpoint HERE (line 38)
    for (int i = 0; i < 10000; i++) {
        HeavyFunction(i);  // BREAKPOINT HERE
        obj.flags = i;
    }
    
    return (int)obj.values[0];
}
