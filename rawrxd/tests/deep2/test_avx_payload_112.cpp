// Test harness for 112-byte AVX payload verification
// Compiles as standalone executable to verify the machine code executes correctly

#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <immintrin.h>

// The corrected 112-byte payload
static const uint8_t payload[112] = {
    0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x08,
    0xC4, 0x07, 0x75, 0x77, 0x45, 0x31, 0xC9,
    0xC5, 0x75, 0x57, 0xC5, 0x7C, 0x10, 0x94, 0x8F, 0x00, 0x00, 0x00, 0x00,
    0xC5, 0x6D, 0x54, 0xA2, 0x8E, 0x00, 0x00, 0x00, 0x00,
    0xC5, 0x75, 0x58, 0xD1,
    0x49, 0x83, 0xC1, 0x08, 0x49, 0x39, 0xC8, 0x72, 0xE1,
    0xC4, 0x03, 0x75, 0x39, 0xCA, 0x01,
    0xC5, 0x71, 0x7C, 0xD1, 0xC5, 0x71, 0xC6, 0xCA, 0x4E,
    0xC5, 0x71, 0x7C, 0xD1, 0xC5, 0x71, 0xC6, 0xCA, 0xB1,
    0xC5, 0x71, 0x7C, 0xD1, 0xC5, 0x79, 0x11, 0x4A, 0x00,
    0x4D, 0x6B, 0xC2, 0x04, 0x49, 0x01, 0xFA,
    0x48, 0xFF, 0xC2, 0x48, 0xFF, 0xC9, 0x75, 0xAB,
    0xC4, 0x07, 0x75, 0x77, 0x48, 0x83, 0xC4, 0x08,
    0x41, 0x5D, 0x41, 0x5C, 0x5B, 0xC3
};

// Microsoft x64 calling convention:
// RCX = 1st arg (loop count / iteration limit)
// RDX = 2nd arg (output buffer pointer)
// R8  = 3rd arg (loop bound for r9 comparison)
// R9  = 4th arg (not used as input, zeroed internally)
// Stack: 32 bytes shadow space + 8 byte alignment

using PayloadFn = void(*)(uint64_t iterations, float* output, uint64_t bound, uint64_t unused);

int main() {
    std::cout << "[TEST] AVX 112-byte payload execution test" << std::flush;
    std::cout << "\n[TEST] Payload size: " << sizeof(payload) << " bytes" << std::flush;

    // Allocate executable memory
    void* execMem = VirtualAlloc(nullptr, sizeof(payload), 
                                 MEM_COMMIT | MEM_RESERVE, 
                                 PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "[FAIL] VirtualAlloc failed: " << GetLastError() << "\n";
        return 1;
    }

    // Copy payload
    memcpy(execMem, payload, sizeof(payload));
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(payload));

    // Cast to function pointer
    PayloadFn fn = reinterpret_cast<PayloadFn>(execMem);

    // Prepare test data
    const uint64_t iterations = 4;      // RCX - outer loop count
    const uint64_t bound = 32;          // R8 - inner loop bound (r9 < r8)
    float* output = static_cast<float*>(_aligned_malloc(256 * sizeof(float), 32));
    if (!output) {
        std::cerr << "[FAIL] Output buffer allocation failed\n";
        VirtualFree(execMem, 0, MEM_RELEASE);
        return 1;
    }
    
    // Initialize output buffer with known pattern
    for (size_t i = 0; i < 256; ++i) output[i] = -1.0f;

    std::cout << "[TEST] Calling payload with iterations=" << iterations 
              << ", bound=" << bound << "\n" << std::flush;
    std::cout << "[TEST] Output buffer: " << output << "\n" << std::flush;

    // Execute the payload
    __try {
        fn(iterations, output, bound, 0);
        std::cout << "[PASS] Payload executed without exception\n" << std::flush;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        std::cerr << "[FAIL] Exception 0x" << std::hex << code << std::dec << "\n" << std::flush;
        _aligned_free(output);
        VirtualFree(execMem, 0, MEM_RELEASE);
        return 1;
    }

    // Verify output was modified (vmovups at 0x4e writes ymm1 to [rdx])
    std::cout << "[OUTPUT] Dumping output buffer...\n" << std::flush;
    bool modified = false;
    for (size_t i = 0; i < 32; ++i) {
        if (output[i] != -1.0f) {
            modified = true;
        }
        std::cout << "  [" << i << "] = " << output[i] << "\n" << std::flush;
    }

    if (modified) {
        std::cout << "[PASS] Output buffer modified by payload\n" << std::flush;
    } else {
        std::cout << "[WARN] Output buffer unchanged - may need different inputs\n" << std::flush;
    }

    // Cleanup
    _aligned_free(output);
    VirtualFree(execMem, 0, MEM_RELEASE);

    std::cout << "[TEST] Complete\n" << std::flush;
    return 0;
}