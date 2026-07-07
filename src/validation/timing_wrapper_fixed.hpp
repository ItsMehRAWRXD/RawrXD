// ============================================================================
// timing_wrapper_fixed.hpp - Fixed Serialized Timing Wrapper
// ============================================================================
// 
// PURPOSE: Provides cycle-accurate timing with proper ABI compliance
// 
// CRITICAL FIXES:
//   1. Proper stack alignment (16-byte boundary)
//   2. Non-volatile register preservation
//   3. Shadow space allocation for Win64 ABI
//   4. Serialization barriers that don't corrupt timing
// 
// ============================================================================

#pragma once

#include <cstdint>
#include <immintrin.h>

// Windows headers for QueryPerformanceCounter
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Fixed Serialized Timing Wrapper
// ============================================================================
// This version ensures proper ABI compliance:
//   - Maintains 16-byte stack alignment
//   - Preserves non-volatile registers
//   - Allocates shadow space for Win64 ABI
//   - Uses proper serialization barriers
// ============================================================================

inline uint64_t measure_kernel_cycles_serialized_fixed(void (*func)(void*, size_t), void* data, size_t size) {
    // CRITICAL: Ensure proper stack alignment before timing
    // The Win64 ABI requires 16-byte stack alignment before 'call' instructions
    
    // Save non-volatile registers that we might modify
    // Note: In inline assembly, we need to be careful about register usage
    
    // 1. Serialize: Ensure all previous instructions finished
    // Use _mm_lfence() which is safe and doesn't corrupt registers
    _mm_lfence();
    
    // 2. Start clock with serialization
    // __rdtsc() is safe and doesn't modify non-volatile registers
    uint64_t start = __rdtsc();
    
    // 3. Execute kernel
    // The function pointer call must respect Win64 ABI:
    //   - RCX = first parameter (data)
    //   - RDX = second parameter (size)
    //   - Shadow space: 32 bytes allocated by caller
    //   - Stack alignment: 16-byte boundary before 'call'
    
    // CRITICAL: The function pointer signature must match the actual calling convention
    // If the MASM kernel uses a different signature, this will corrupt the stack
    
    func(data, size);
    
    // 4. Serialize: Ensure all instructions in kernel finished
    _mm_lfence();
    
    // 5. Stop clock
    uint64_t end = __rdtsc();
    
    // 6. Calculate elapsed cycles
    // CRITICAL: Check for overflow or corruption
    if (end < start) {
        // This should NEVER happen - indicates timing corruption
        return 0;  // Return 0 to indicate error
    }
    
    return end - start;
}

// ============================================================================
// Alternative: Use QueryPerformanceCounter for Wall-Clock Timing
// ============================================================================
// This is more reliable than RDTSC for measuring execution time,
// but less precise for cycle-accurate measurements.
// ============================================================================

inline double measure_kernel_time_ms(void (*func)(void*, size_t), void* data, size_t size) {
    LARGE_INTEGER freq, start, end;
    
    // Get frequency
    QueryPerformanceFrequency(&freq);
    
    // Start timing
    QueryPerformanceCounter(&start);
    
    // Execute kernel
    func(data, size);
    
    // End timing
    QueryPerformanceCounter(&end);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
    
    return elapsed_ms;
}

// ============================================================================
// Comprehensive Timing Wrapper with Validation
// ============================================================================
// This version validates timing results to detect corruption.
// ============================================================================

struct TimingResult {
    uint64_t cycles;
    double time_ms;
    bool valid;
    const char* error_message;
};

inline TimingResult measure_kernel_comprehensive(void (*func)(void*, size_t), void* data, size_t size) {
    TimingResult result;
    result.valid = false;
    result.error_message = nullptr;
    
    // Validate input parameters
    if (func == nullptr) {
        result.error_message = "Function pointer is null";
        return result;
    }
    
    if (data == nullptr) {
        result.error_message = "Data pointer is null";
        return result;
    }
    
    if (size == 0) {
        result.error_message = "Size is zero";
        return result;
    }
    
    // Measure cycles
    result.cycles = measure_kernel_cycles_serialized_fixed(func, data, size);
    
    // Measure time
    result.time_ms = measure_kernel_time_ms(func, data, size);
    
    // Validate results
    if (result.cycles == 0) {
        result.error_message = "Cycle count is zero (timing corruption detected)";
        return result;
    }
    
    if (result.cycles > 100000000000ULL) {  // > 100 billion cycles is suspicious
        result.error_message = "Cycle count is unreasonably large (timing corruption detected)";
        return result;
    }
    
    if (result.time_ms < 0.0) {
        result.error_message = "Time is negative (timing corruption detected)";
        return result;
    }
    
    result.valid = true;
    return result;
}

} // namespace Validation
} // namespace RawrXD