//=============================================================================
// Debug Helpers for MASM Kernels
// Provides printf-style debugging from assembly code
//=============================================================================

#include <cstdio>
#include <windows.h>
#include <cstdint.h>

extern "C" {

// Print a string to console
void DebugPrintString(const char* str) {
    if (str) {
        printf("%s", str);
    }
}

// Print a 64-bit integer
void DebugPrintInt64(uint64_t value) {
    printf("%llu", value);
}

// Print a float
void DebugPrintFloat(float value) {
    printf("%f", value);
}

// Print a double
void DebugPrintDouble(double value) {
    printf("%lf", value);
}

// Print hex value
void DebugPrintHex(uint64_t value) {
    printf("0x%016llX", value);
}

// Print binary representation
void DebugPrintBinary(uint64_t value, int bits) {
    printf("0b");
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (value >> i) & 1);
    }
}

// Print memory at address
void DebugPrintMemory(void* addr, size_t len) {
    uint8_t* bytes = (uint8_t*)addr;
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// Print Q4_0 block contents
void DebugPrintQ4Block(void* block_addr) {
    uint16_t* scale = (uint16_t*)block_addr;
    uint8_t* weights = (uint8_t*)block_addr + 2;
    
    printf("Q4_0 Block @ %p:\n", block_addr);
    printf("  Scale: %u (0x%04X)\n", *scale, *scale);
    printf("  Weights (first 8 bytes): ");
    for (int i = 0; i < 8 && i < 16; i++) {
        printf("%02X ", weights[i]);
    }
    printf("\n");
    
    // Decode first few values
    printf("  Decoded values: ");
    for (int i = 0; i < 4; i++) {
        uint8_t byte = weights[i];
        int low = (byte & 0x0F) - 8;
        int high = ((byte >> 4) & 0x0F) - 8;
        printf("[%d,%d] ", low, high);
    }
    printf("\n");
}

// Assertion helper
void DebugAssert(int condition, const char* msg) {
    if (!condition) {
        printf("ASSERTION FAILED: %s\n", msg ? msg : "unknown");
        DebugBreak();
    }
}

// Print matrix info
void DebugPrintMatrixInfo(const char* name, void* data, int rows, int cols) {
    printf("Matrix %s: %dx%d @ %p\n", name, rows, cols, data);
    if (rows <= 4 && cols <= 8) {
        float* fdata = (float*)data;
        for (int r = 0; r < rows; r++) {
            printf("  Row %d: ", r);
            for (int c = 0; c < cols; c++) {
                printf("%8.4f ", fdata[r * cols + c]);
            }
            printf("\n");
        }
    }
}

// Print quantized matrix info
void DebugPrintQuantMatrixInfo(const char* name, void* data, int rows, int cols) {
    printf("Quantized Matrix %s: %dx%d @ %p\n", name, rows, cols, data);
    int blocks_per_row = cols / 32;
    printf("  Blocks per row: %d\n", blocks_per_row);
    printf("  First block:\n");
    DebugPrintQ4Block(data);
}

} // extern "C"
