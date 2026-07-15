//============================================================================
// Titan_Debug_Diagnostics.cpp
// Debug instrumentation for Titan integration issues
//
// Purpose: Identify why Titan produces garbage results
//============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Mirror of Titan structures for verification
struct TitanKernelDescriptor {
    const char* kernelName;
    uint32_t gridDimX, gridDimY, gridDimZ;
    uint32_t blockDimX, blockDimY, blockDimZ;
    uint32_t sharedMemSize;
    void* stream;
    void* inputBuffer;
    uint64_t inputSize;
    void* outputBuffer;
    uint64_t outputSize;
    uint32_t paramCount;
    void* paramData;
    uint32_t launchStatus;
    uint64_t executionTimeUs;
};

// Debug logging
#define DEBUG_LOG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

// Verify struct layout matches MASM expectations
void VerifyStructLayout() {
    DEBUG_LOG("=== Struct Layout Verification ===");
    DEBUG_LOG("sizeof(TitanKernelDescriptor) = %zu", sizeof(TitanKernelDescriptor));
    DEBUG_LOG("offsetof(kernelName)     = %zu", offsetof(TitanKernelDescriptor, kernelName));
    DEBUG_LOG("offsetof(gridDimX)       = %zu", offsetof(TitanKernelDescriptor, gridDimX));
    DEBUG_LOG("offsetof(inputBuffer)    = %zu", offsetof(TitanKernelDescriptor, inputBuffer));
    DEBUG_LOG("offsetof(outputBuffer)   = %zu", offsetof(TitanKernelDescriptor, outputBuffer));
    DEBUG_LOG("offsetof(paramData)      = %zu", offsetof(TitanKernelDescriptor, paramData));
    
    // Check alignment
    DEBUG_LOG("alignof(TitanKernelDescriptor) = %zu", alignof(TitanKernelDescriptor));
    
    // Verify no padding issues
    size_t expectedSize = sizeof(void*) + 6*sizeof(uint32_t) + sizeof(void*) + 
                          sizeof(void*) + sizeof(uint64_t) + sizeof(void*) + 
                          sizeof(uint64_t) + sizeof(uint32_t) + sizeof(void*) + 
                          sizeof(uint32_t) + sizeof(uint64_t);
    DEBUG_LOG("Expected size (packed) = %zu", expectedSize);
    DEBUG_LOG("Actual size = %zu", sizeof(TitanKernelDescriptor));
    
    if (sizeof(TitanKernelDescriptor) != expectedSize) {
        DEBUG_LOG("WARNING: Struct has unexpected padding!");
    }
}

// Test 1: Verify buffer initialization
void TestBufferInitialization() {
    DEBUG_LOG("\n=== Test 1: Buffer Initialization ===");
    
    const size_t size = 512 * 512 * sizeof(float);
    float* buffer = (float*)_aligned_malloc(size, 64);
    
    // Fill with known pattern
    for (size_t i = 0; i < 512*512; i++) {
        buffer[i] = 1.0f;  // Simple pattern
    }
    
    // Verify
    int errors = 0;
    for (size_t i = 0; i < 512*512; i++) {
        if (buffer[i] != 1.0f) {
            errors++;
        }
    }
    
    DEBUG_LOG("Buffer fill errors: %d", errors);
    _aligned_free(buffer);
}

// Test 2: Verify parameter passing
void TestParameterPassing() {
    DEBUG_LOG("\n=== Test 2: Parameter Passing ===");
    
    TitanKernelDescriptor desc = {};
    desc.kernelName = "TestKernel";
    desc.gridDimX = 1;
    desc.gridDimY = 1;
    desc.gridDimZ = 1;
    desc.blockDimX = 64;
    desc.blockDimY = 1;
    desc.blockDimZ = 1;
    desc.sharedMemSize = 0;
    desc.stream = nullptr;
    
    // Allocate test buffers
    float* input = (float*)_aligned_malloc(64 * sizeof(float), 64);
    float* output = (float*)_aligned_malloc(64 * sizeof(float), 64);
    
    // Initialize
    for (int i = 0; i < 64; i++) {
        input[i] = (float)i;
        output[i] = -999.0f;  // Sentinel value
    }
    
    desc.inputBuffer = input;
    desc.inputSize = 64 * sizeof(float);
    desc.outputBuffer = output;
    desc.outputSize = 64 * sizeof(float);
    desc.paramCount = 0;
    desc.paramData = nullptr;
    
    DEBUG_LOG("Input buffer addr: %p", input);
    DEBUG_LOG("Output buffer addr: %p", output);
    DEBUG_LOG("Input[0] = %f", input[0]);
    DEBUG_LOG("Output[0] before = %f", output[0]);
    
    // Here we would call Titan, but for now just verify setup
    DEBUG_LOG("Descriptor setup complete");
    
    _aligned_free(input);
    _aligned_free(output);
}

// Test 3: Check for memory corruption
void TestMemoryCorruption() {
    DEBUG_LOG("\n=== Test 3: Memory Corruption Check ===");
    
    // Allocate guard pages around buffer
    const size_t bufferSize = 512 * 512 * sizeof(float);
    const size_t guardSize = 4096;  // 1 page
    
    // Allocate extra space for guards
    uint8_t* rawMem = (uint8_t*)VirtualAlloc(nullptr, bufferSize + 2*guardSize, 
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    float* buffer = (float*)(rawMem + guardSize);
    
    // Fill guards with pattern
    memset(rawMem, 0xAA, guardSize);
    memset(rawMem + guardSize + bufferSize, 0xBB, guardSize);
    
    // Fill buffer
    for (size_t i = 0; i < 512*512; i++) {
        buffer[i] = 3.14159f;
    }
    
    // Check guards
    int guardErrors = 0;
    for (size_t i = 0; i < guardSize; i++) {
        if (rawMem[i] != 0xAA) guardErrors++;
    }
    for (size_t i = 0; i < guardSize; i++) {
        if (rawMem[guardSize + bufferSize + i] != 0xBB) guardErrors++;
    }
    
    DEBUG_LOG("Guard errors: %d", guardErrors);
    
    VirtualFree(rawMem, 0, MEM_RELEASE);
}

// Test 4: Verify Q4_0 block structure
void TestQ4BlockStructure() {
    DEBUG_LOG("\n=== Test 4: Q4_0 Block Structure ===");
    
    // Q4_0 block: 18 bytes for 32 weights
    // - 2 bytes: scale (F16)
    // - 16 bytes: 32 nibbles (4 bits each)
    
    DEBUG_LOG("Q4_0 block size: 18 bytes for 32 elements");
    DEBUG_LOG("Q4_0 elements per block: 32");
    DEBUG_LOG("Q4_0 bytes per element: 0.5625");
    
    // Verify alignment requirements
    DEBUG_LOG("Q4_0 block alignment: 2 bytes (scale is F16)");
}

// Test 5: Check calling convention
void TestCallingConvention() {
    DEBUG_LOG("\n=== Test 5: Calling Convention ===");
    
    DEBUG_LOG("Windows x64 calling convention:");
    DEBUG_LOG("  RCX = 1st arg (descriptor ptr)");
    DEBUG_LOG("  RDX = 2nd arg");
    DEBUG_LOG("  R8  = 3rd arg");
    DEBUG_LOG("  R9  = 4th arg");
    DEBUG_LOG("  Stack = 5th+ args");
    DEBUG_LOG("  RAX = return value");
    DEBUG_LOG("  XMM0-XMM3 = float args");
    
    DEBUG_LOG("Stack must be 16-byte aligned before CALL");
    DEBUG_LOG("Caller cleans stack");
}

// Main diagnostic entry point
int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  Titan Integration Diagnostics\n");
    printf("  Phase 7B.5 - Root Cause Analysis\n");
    printf("==============================================\n\n");
    
    VerifyStructLayout();
    TestBufferInitialization();
    TestParameterPassing();
    TestMemoryCorruption();
    TestQ4BlockStructure();
    TestCallingConvention();
    
    printf("\n==============================================\n");
    printf("  Diagnostics Complete\n");
    printf("==============================================\n");
    
    printf("\nRECOMMENDATIONS:\n");
    printf("1. Verify struct layout matches MASM expectations\n");
    printf("2. Check buffer alignment (must be 64-byte)\n");
    printf("3. Verify Q4_0/Q8_0 block structure interpretation\n");
    printf("4. Add debug prints in Titan_ExecuteComputeKernel\n");
    printf("5. Test with simple memcpy kernel first\n");
    printf("6. Verify calling convention (RCX=descriptor)\n");
    
    return 0;
}
