// ============================================================================
// stress_memory.cpp
// Memory/register inspection stress test for debugger
// Validates arena stability under repeated inspection operations
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <stdint.h>

// Data structures to stress memory window and variable inspection

struct ComplexStruct {
    uint64_t id;
    char name[64];
    double values[16];
    ComplexStruct* next;
    
    ComplexStruct(uint64_t i) : id(i), next(nullptr) {
        snprintf(name, sizeof(name), "Node_%llu", (unsigned long long)i);
        for (int j = 0; j < 16; j++) {
            values[j] = (double)i * 3.14159 + j;
        }
    }
};

class MemoryStressor {
public:
    static const int ARRAY_SIZE = 1024;
    static const int BUFFER_SIZE = 4096;
    
    uint8_t byteArray[ARRAY_SIZE];
    uint32_t dwordArray[ARRAY_SIZE];
    uint64_t qwordArray[ARRAY_SIZE];
    char stringBuffer[BUFFER_SIZE];
    ComplexStruct* linkedListHead;
    
    MemoryStressor() : linkedListHead(nullptr) {
        // Initialize arrays with patterns
        for (int i = 0; i < ARRAY_SIZE; i++) {
            byteArray[i] = (uint8_t)(i & 0xFF);
            dwordArray[i] = (uint32_t)(i * 0x12345678);
            qwordArray[i] = (uint64_t)(i * 0x9E3779B97F4A7C15ULL);
        }
        
        // Create linked list
        ComplexStruct* prev = nullptr;
        for (int i = 0; i < 100; i++) {
            ComplexStruct* node = new ComplexStruct(i);
            if (prev) {
                prev->next = node;
            } else {
                linkedListHead = node;
            }
            prev = node;
        }
        
        // Initialize string buffer
        snprintf(stringBuffer, BUFFER_SIZE, 
            "This is a test string for memory inspection. "
            "It contains various characters: ABCabc123!@#$%%^\u0026*()\n"
            "The quick brown fox jumps over the lazy dog. "
            "Pack my box with five dozen liquor jugs.");
    }
    
    ~MemoryStressor() {
        // Clean up linked list
        ComplexStruct* current = linkedListHead;
        while (current) {
            ComplexStruct* next = current->next;
            delete current;
            current = next;
        }
    }
    
    void ModifyData() {
        // Modify data to trigger watchpoint detection
        static uint64_t modifier = 1;
        
        for (int i = 0; i < ARRAY_SIZE; i++) {
            byteArray[i] ^= (uint8_t)modifier;
            dwordArray[i] += (uint32_t)modifier;
            qwordArray[i] *= modifier + 1;
        }
        
        // Modify linked list
        ComplexStruct* node = linkedListHead;
        while (node) {
            node->id += modifier;
            for (int i = 0; i < 16; i++) {
                node->values[i] *= 1.0001;
            }
            node = node->next;
        }
        
        modifier++;
    }
    
    void PrintStats() {
        printf("Memory Stats:\n");
        printf("  byteArray[0]: %u\n", (unsigned)byteArray[0]);
        printf("  dwordArray[0]: %u\n", dwordArray[0]);
        printf("  qwordArray[0]: %llu\n", (unsigned long long)qwordArray[0]);
        printf("  Linked list nodes: ");
        
        int count = 0;
        ComplexStruct* node = linkedListHead;
        while (node) {
            count++;
            node = node->next;
        }
        printf("%d\n", count);
    }
};

// Global instance for debugger to inspect
MemoryStressor* g_stressor = nullptr;
volatile int g_running = 1;

void RegisterCaptureStress() {
    // Function that modifies many registers
    // When stepped through, stresses register capture
    
    uint64_t r1 = 0x1111111111111111ULL;
    uint64_t r2 = 0x2222222222222222ULL;
    uint64_t r3 = 0x3333333333333333ULL;
    uint64_t r4 = 0x4444444444444444ULL;
    uint64_t r5 = 0x5555555555555555ULL;
    uint64_t r6 = 0x6666666666666666ULL;
    uint64_t r7 = 0x7777777777777777ULL;
    uint64_t r8 = 0x8888888888888888ULL;
    
    // Volatile operations to prevent optimization
    volatile uint64_t sum = r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
    (void)sum;
}

void StackInspectionStress(int depth) {
    // Recursive function to create deep call stacks
    if (depth > 0) {
        StackInspectionStress(depth - 1);
    } else {
        // At deepest level, trigger register capture
        RegisterCaptureStress();
        
        // Modify memory
        if (g_stressor) {
            g_stressor->ModifyData();
        }
    }
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD Debugger Memory Stress Test\n");
    printf("========================================\n");
    printf("\nThis program stresses:\n");
    printf("  - Memory window refresh\n");
    printf("  - Variable inspection\n");
    printf("  - Register capture\n");
    printf("  - Stack walking\n");
    printf("  - Symbol resolution\n");
    printf("\nPress Ctrl+C to exit.\n\n");
    
    // Create stressor
    g_stressor = new MemoryStressor();
    
    printf("Memory stressor initialized.\n");
    printf("Attach debugger and inspect:\n");
    printf("  - g_stressor (MemoryStressor*)\n");
    printf("  - g_stressor->linkedListHead\n");
    printf("  - Global arrays\n\n");
    
    // Main stress loop
    int iteration = 0;
    while (g_running) {
        // Create deep call stacks
        StackInspectionStress(20);
        
        // Periodic stats
        if (++iteration % 100 == 0) {
            printf("Iteration %d\n", iteration);
            g_stressor->PrintStats();
        }
        
        // Brief pause
        Sleep(10);
    }
    
    // Cleanup
    delete g_stressor;
    g_stressor = nullptr;
    
    printf("Stress test complete.\n");
    return 0;
}
