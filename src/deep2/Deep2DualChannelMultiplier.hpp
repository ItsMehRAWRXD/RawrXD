#pragma once

#include <windows.h>
#include <cstdint>
#include <immintrin.h>
#include <stdexcept>
#include <iostream>

class Deep2DualChannelMultiplier {
private:
    uint8_t* physicalBackingBuffer{ nullptr };
    size_t allocationSize{ 0 };

    // Enable SeLockMemoryPrivilege to allow Win32 Large Page Allocations
    bool AssertLargePagePrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValueW(nullptr, LUID_SE_LOCK_MEMORY_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        CloseHandle(hToken);
        return result && (GetLastError() == ERROR_SUCCESS);
    }
public:
    void AllocateInterleavedPool(size_t targetBytes) {
        if (!AssertLargePagePrivilege()) {
            std::cerr << "[!] Privilege Error: Run as Administrator to unlock SeLockMemoryPrivilege.\n";
        }

        size_t largePageSize = GetLargePageMinimum();
        // Round allocation to the nearest 2MB physical page boundary
        allocationSize = (targetBytes + largePageSize - 1) & ~(largePageSize - 1);

        // Allocate physically contiguous memory locked directly to the hardware bus
        physicalBackingBuffer = reinterpret_cast<uint8_t*>(VirtualAlloc(
            nullptr,
            allocationSize,
            MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
            PAGE_READWRITE
        ));

        if (!physicalBackingBuffer) {
            throw std::runtime_error("[!] Memory Subsystem Failure: VirtualAlloc failed to lock contiguous hardware pool.");
        }

        std::cout << "[+] Contiguous Backing Store Pinned: " << (allocationSize / (1024 * 1024)) << " MB allocated via Large Pages.\n";
    }

    /**
     * Executes an 11x unrolled AVX-512 matrix vector multiplication stride loop.
     * Alternates 64-byte cache-line references to hit concurrent sub-channels sequentially.
     */
    void StreamChannelInterleavedGEMV(const float* __restrict vectorX, float* __restrict vectorY, uint64_t rows, uint64_t cols) {
        const float* matrixWeights = reinterpret_cast<const float*>(physicalBackingBuffer);
        
        // Cache line stride offset matching the DDR5 hardware channel cross-over point
        constexpr uint64_t STRIDE_64B = 16; // 16 float elements = 64 bytes

        for (uint64_t r = 0; r < rows; ++r) {
            __m512 accum0 = _mm512_setzero_ps();
            __m512 accum1 = _mm512_setzero_ps();
            
            uint64_t rowOffset = r * cols;

            // 11x Unrolled Memory Channel Saturation Loop
            uint64_t c = 0;
            for (; c + (STRIDE_64B * 11) <= cols; c += (STRIDE_64B * 11)) {
                // Alternating hardware subchannel reads via forced offset strides
                __m512 w0 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 0)]);
                __m512 v0 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 0)]);
                accum0 = _mm512_fmadd_ps(w0, v0, accum0);

                __m512 w1 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 1)]);
                __m512 v1 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 1)]);
                accum1 = _mm512_fmadd_ps(w1, v1, accum1);

                __m512 w2 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 2)]);
                __m512 v2 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 2)]);
                accum0 = _mm512_fmadd_ps(w2, v2, accum0);

                __m512 w3 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 3)]);
                __m512 v3 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 3)]);
                accum1 = _mm512_fmadd_ps(w3, v3, accum1);

                __m512 w4 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 4)]);
                __m512 v4 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 4)]);
                accum0 = _mm512_fmadd_ps(w4, v4, accum0);

                __m512 w5 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 5)]);
                __m512 v5 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 5)]);
                accum1 = _mm512_fmadd_ps(w5, v5, accum1);

                __m512 w6 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 6)]);
                __m512 v6 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 6)]);
                accum0 = _mm512_fmadd_ps(w6, v6, accum0);

                __m512 w7 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 7)]);
                __m512 v7 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 7)]);
                accum1 = _mm512_fmadd_ps(w7, v7, accum1);

                __m512 w8 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 8)]);
                __m512 v8 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 8)]);
                accum0 = _mm512_fmadd_ps(w8, v8, accum0);

                __m512 w9 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 9)]);
                __m512 v9 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 9)]);
                accum1 = _mm512_fmadd_ps(w9, v9, accum1);

                __m512 w10 = _mm512_load_ps(&matrixWeights[rowOffset + c + (STRIDE_64B * 10)]);
                __m512 v10 = _mm512_load_ps(&vectorX[c + (STRIDE_64B * 10)]);
                accum0 = _mm512_fmadd_ps(w10, v10, accum0);
                
                // Explicit Software Prefetch instructions for the upcoming 11-stride segment
                _mm_prefetch(reinterpret_cast<const char*>(&matrixWeights[rowOffset + c + (STRIDE_64B * 11)]), _MM_HINT_T0);
            }

            // Clean up remaining non-strided columns
            for (; c < cols; c += 16) {
                __m512 w = _mm512_load_ps(&matrixWeights[rowOffset + c]);
                __m512 v = _mm512_load_ps(&vectorX[c]);
                accum0 = _mm512_fmadd_ps(w, v, accum0);
            }

            // Horizontal add of the AVX-512 register targets down to vectorY elements
            __m512 finalAccum = _mm512_add_ps(accum0, accum1);
            vectorY[r] = _mm512_reduce_add_ps(finalAccum);
        }
    }

    ~Deep2DualChannelMultiplier() {
        if (physicalBackingBuffer) {
            VirtualFree(physicalBackingBuffer, 0, MEM_RELEASE);
        }
    }
};
