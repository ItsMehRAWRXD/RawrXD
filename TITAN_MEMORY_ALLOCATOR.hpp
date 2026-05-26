#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <iostream>

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <malloc.h>
#else
#include <stdlib.h>
#endif

// =============================================================================
// TITAN MEMORY ALIGNMENT & ALLOCATION ENGINE
// =============================================================================
// Enforces 64-byte (Cache-Line) boundary alignment for all tensor buffers.
// Prevents L1 cache-line splits which can throttle the Load/Store unit by 20-30%.
// This is strictly required to feed the 8-lane Titan FMA execution pipeline
// without starving the Execution Ports due to memory subsystem fragmentation.
// =============================================================================

namespace Titan {
namespace Memory {

    constexpr size_t L1_CACHE_LINE_SIZE = 64; // x86 standard cache line

    class AlignedAllocator {
    public:
        // Allocates memory aligned to the strict cache-line boundary
        static void* Allocate(size_t size, size_t alignment = L1_CACHE_LINE_SIZE) {
            if (alignment < sizeof(void*)) {
                alignment = sizeof(void*);
            }
            
            void* ptr = nullptr;
#if defined(_MSC_VER) || defined(__MINGW32__)
            ptr = _aligned_malloc(size, alignment);
#else
            if (posix_memalign(&ptr, alignment, size) != 0) {
                ptr = nullptr;
            }
#endif
            if (!ptr) {
                throw std::runtime_error("Titan::Memory - Failed to allocate aligned memory.");
            }
            return ptr;
        }

        // Frees aligned memory
        static void Free(void* ptr) {
            if (!ptr) return;
#if defined(_MSC_VER) || defined(__MINGW32__)
            _aligned_free(ptr);
#else
            free(ptr);
#endif
        }

        // Hard validation to be called in the C++ Orchestrator prior to MASM dispatch
        static bool VerifyAlignment(const void* ptr, size_t alignment = L1_CACHE_LINE_SIZE) {
            return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
        }

        // Orchestrator Enforcement Gate
        static void EnforceCacheLineAlignment(const void* ptr, const std::string& buffer_name) {
            if (!VerifyAlignment(ptr, L1_CACHE_LINE_SIZE)) {
                std::cerr << "[TITAN FATAL] Buffer '" << buffer_name 
                          << "' is unaligned! This will cause L1 cache-line split penalties.\n";
                // In production, we'd throw or force a memmove to an aligned proxy buffer
                throw std::runtime_error("Unaligned tensor memory passed to execution engine.");
            }
        }
    };

} // namespace Memory
} // namespace Titan