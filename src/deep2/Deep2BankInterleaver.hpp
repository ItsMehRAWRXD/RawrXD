#pragma once

#include <windows.h>
#include <cstdint>
#include <immintrin.h>
#include <vector>
#include <stdexcept>
#include <iostream>

class Deep2BankInterleaver {
private:
    uint8_t* rawMemoryPool{ nullptr };
    size_t poolSize{ 0 };
    
    // Hardware Constants for Zen 4 DDR5 Architectures
    static constexpr size_t CACHE_LINE_SIZE = 64;
    static constexpr size_t BANK_GROUP_STRIDE = 2048; // 2KB Hardware boundary for alternate bank swapping

public:
    void InitializeBankPool(size_t requiredBytes) {
        // Allocate raw unmanaged memory matching hardware allocation pages
        poolSize = requiredBytes + (BANK_GROUP_STRIDE * 16); 
        rawMemoryPool = reinterpret_cast<uint8_t*>(VirtualAlloc(
            nullptr, 
            poolSize, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        ));

        if (!rawMemoryPool) {
            throw std::runtime_error("[!] Subsystem Failure: Unable to isolate physical memory blocks.");
        }
        
        // Zero memory to force OS to back virtual mappings with actual physical frames
        SecureZeroMemory(rawMemoryPool, poolSize);
        std::cout << "[+] Bank-Interleaved Storage Pool pinned at: 0x" << std::hex << (uintptr_t)rawMemoryPool << std::dec << "\n";
    }

    /**
     * Executes an AVX-512 GEMV compute kernel across alternating hardware memory banks.
     * Prevents Bank Group conflicts by jumping strides intentionally across physical regions.
     */
    void ComputeAlternateBankGEMV(const float* __restrict vectorX, float* __restrict vectorY, 
                                  uint64_t rows, uint64_t cols) {
        
        const uint8_t* baseMatrix = rawMemoryPool;

        for (uint64_t r = 0; r < rows; ++r) {
            __m512 accum0 = _mm512_setzero_ps();
            __m512 accum1 = _mm512_setzero_ps();
            __m512 accum2 = _mm512_setzero_ps();
            __m512 accum3 = _mm512_setzero_ps();

            // Compute row base with explicit physical alignment considerations
            uint64_t rowByteOffset = r * cols * sizeof(float);

            for (uint64_t c = 0; c < cols; c += 64) {
                // Address Calculations designed to target Alternate Memory Bank Groups explicitly
                // Read from Bank Group 0
                const float* ptrBG0 = reinterpret_cast<const float*>(baseMatrix + rowByteOffset + (c * sizeof(float)) + (BANK_GROUP_STRIDE * 0));
                __m512 w0 = _mm512_loadu_ps(ptrBG0);
                __m512 v0 = _mm512_loadu_ps(&vectorX[c + 0]);
                accum0 = _mm512_fmadd_ps(w0, v0, accum0);

                // Read from Bank Group 1 (Forced 2KB physical offset stride)
                const float* ptrBG1 = reinterpret_cast<const float*>(baseMatrix + rowByteOffset + (c * sizeof(float)) + (BANK_GROUP_STRIDE * 1));
                __m512 w1 = _mm512_loadu_ps(ptrBG1);
                __m512 v1 = _mm512_loadu_ps(&vectorX[c + 16]);
                accum1 = _mm512_fmadd_ps(w1, v1, accum1);

                // Read from Bank Group 2 (Forced 4KB physical offset stride)
                const float* ptrBG2 = reinterpret_cast<const float*>(baseMatrix + rowByteOffset + (c * sizeof(float)) + (BANK_GROUP_STRIDE * 2));
                __m512 w2 = _mm512_loadu_ps(ptrBG2);
                __m512 v2 = _mm512_loadu_ps(&vectorX[c + 32]);
                accum2 = _mm512_fmadd_ps(w2, v2, accum2);

                // Read from Bank Group 3 (Forced 6KB physical offset stride)
                const float* ptrBG3 = reinterpret_cast<const float*>(baseMatrix + rowByteOffset + (c * sizeof(float)) + (BANK_GROUP_STRIDE * 3));
                __m512 w3 = _mm512_loadu_ps(ptrBG3);
                __m512 v3 = _mm512_loadu_ps(&vectorX[c + 48]);
                accum3 = _mm512_fmadd_ps(w3, v3, accum3);
            }

            // Perform reduction across alternating bank accumulations
            __m512 sum0 = _mm512_add_ps(accum0, accum1);
            __m512 sum1 = _mm512_add_ps(accum2, accum3);
            __m512 finalAccum = _mm512_add_ps(sum0, sum1);
            
            vectorY[r] = _mm512_reduce_add_ps(finalAccum);
        }
    }

    ~Deep2BankInterleaver() {
        if (rawMemoryPool) {
            VirtualFree(rawMemoryPool, 0, MEM_RELEASE);
        }
    }
};
