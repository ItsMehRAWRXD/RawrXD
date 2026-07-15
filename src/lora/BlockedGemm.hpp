// ============================================================================
// BlockedGemm.hpp - Cache-Blocked GEMM Implementation
// ============================================================================
// Implements cache blocking for large GEMM operations using the verified
// 8x8 AVX microkernel as the innermost compute primitive.
//
// Blocking parameters:
//   MC = 128  (M cache block - rows of A/C)
//   KC = 256  (K cache block - inner dimension)
//   NC = 128  (N cache block - columns of B/C)
//
// Architecture:
//   for (nc = 0; nc < N; nc += NC)
//     for (kc = 0; kc < K; kc += KC)
//       Pack B panel (KC × NC) -> B_packed
//       for (mc = 0; mc < M; mc += MC)
//         Pack A panel (MC × KC) -> A_packed
//         for (n = 0; n < NC; n += 8)
//           for (m = 0; m < MC; m += 8)
//             Call Gemm_8x8_Microkernel on 8×8 tile
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>

// External MASM microkernel
// Computes C += A × B (accumulates into existing C)
extern "C" int Gemm_8x8_Microkernel(
    const float* A_packed,  // 8×K packed (column-major for 8 rows)
    const float* B,         // K×8 row-major
    float* C,               // 8×8 row-major output (accumulates)
    size_t K,               // Inner dimension
    size_t ldc              // C row stride (typically N)
);

namespace RawrXD {

// Blocking parameters - tuned for L2/L3 cache sizes
constexpr int MC = 128;  // M cache block size
constexpr int KC = 256;  // K cache block size  
constexpr int NC = 128;  // N cache block size
constexpr int MR = 8;    // Microkernel M size
constexpr int NR = 8;    // Microkernel N size

// Aligned allocation for SIMD buffers
template<typename T>
T* aligned_alloc(size_t count, size_t alignment = 32) {
    void* ptr = _aligned_malloc(count * sizeof(T), alignment);
    return static_cast<T*>(ptr);
}

void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// ============================================================================
// Panel Packing Functions
// ============================================================================

// Pack A panel: MC×K row-major -> packed format for microkernel
// Output layout: For each 8-row tile, store as K×8 where each K iteration
// has 8 consecutive floats: A[0,k], A[1,k], ..., A[7,k]
// This is exactly what the microkernel expects
inline void PackAPanel(
    const float* A,      // Source: MC×K row-major
    float* A_packed,     // Dest: packed buffer
    int M,               // Actual M dimension (may be < MC at edge)
    int K,               // Actual K dimension (may be < KC at edge)
    int lda              // Leading dimension of A (full K)
) {
    // Pack in groups of 8 rows (MR)
    for (int m_tile = 0; m_tile < M; m_tile += MR) {
        int m_size = std::min(MR, M - m_tile);
        float* packed_tile = A_packed + (m_tile / MR) * (K * MR);
        
        for (int k = 0; k < K; k++) {
            for (int m = 0; m < m_size; m++) {
                // A[m_tile + m, k] -> packed_tile[k*MR + m]
                packed_tile[k * MR + m] = A[(m_tile + m) * lda + k];
            }
            // Zero padding for incomplete tiles
            for (int m = m_size; m < MR; m++) {
                packed_tile[k * MR + m] = 0.0f;
            }
        }
    }
}

// Pack B panel: K×N row-major -> packed as (N/8) tiles of K×8
// The microkernel expects B[k*8 + n] where n is 0..7 contiguous
// So we pack as: for each 8-column tile, store K×8 contiguous
inline void PackBPanel(
    const float* B,      // Source: K×N row-major
    float* B_packed,     // Dest: packed buffer
    int K,               // Actual K dimension
    int N,               // Actual N dimension (may be < NC at edge)
    int ldb              // Leading dimension of B (full N)
) {
    // Pack in groups of 8 columns (NR)
    for (int n_tile = 0; n_tile < N; n_tile += NR) {
        int n_size = std::min(NR, N - n_tile);
        float* packed_tile = B_packed + (n_tile / NR) * (K * NR);
        
        for (int k = 0; k < K; k++) {
            for (int n = 0; n < n_size; n++) {
                // B[k, n_tile + n] -> packed_tile[k*NR + n]
                packed_tile[k * NR + n] = B[k * ldb + (n_tile + n)];
            }
            // Zero padding for incomplete tiles
            for (int n = n_size; n < NR; n++) {
                packed_tile[k * NR + n] = 0.0f;
            }
        }
    }
}

// ============================================================================
// Blocked GEMM Implementation
// ============================================================================

// Single-threaded blocked GEMM: C = A × B
// A: M×K row-major
// B: K×N row-major
// C: M×N row-major (accumulates into existing C if beta != 0)
inline void BlockedGemm(
    const float* A,
    const float* B,
    float* C,
    int M,
    int N,
    int K,
    float alpha = 1.0f,
    float beta = 0.0f
) {
    // Allocate packed buffers with alignment for SIMD
    // A_packed: MC×KC packed (max size)
    // B_packed: KC×NC packed (max size)
    float* A_packed = aligned_alloc<float>(MC * KC);
    float* B_packed = aligned_alloc<float>(KC * NC);
    
    // Initialize C if beta == 0, else scale existing C
    if (beta == 0.0f) {
        for (int i = 0; i < M * N; i++) {
            C[i] = 0.0f;
        }
    } else if (beta != 1.0f) {
        for (int i = 0; i < M * N; i++) {
            C[i] *= beta;
        }
    }
    
    // Main blocking loops
    // Loop over N blocks
    for (int nc = 0; nc < N; nc += NC) {
        int nc_size = std::min(NC, N - nc);
        
        // Loop over M blocks
        for (int mc = 0; mc < M; mc += MC) {
            int mc_size = std::min(MC, M - mc);
            
            // Loop over K blocks
            for (int kc = 0; kc < K; kc += KC) {
                int kc_size = std::min(KC, K - kc);
                
                // Pack B panel (kc_size × nc_size) -> B_packed
                // B is only read once per (nc, kc) pair
                PackBPanel(
                    B + kc * N + nc,  // B[kc:kc+kc_size, nc:nc+nc_size]
                    B_packed,
                    kc_size,
                    nc_size,
                    N
                );
                
                // Pack A panel (mc_size × kc_size) -> A_packed
                // A is only read once per (mc, kc) pair
                PackAPanel(
                    A + mc * K + kc,  // A[mc:mc+mc_size, kc:kc+kc_size]
                    A_packed,
                    mc_size,
                    kc_size,
                    K
                );
                
                // Microkernel loops over the packed panels
                for (int n = 0; n < nc_size; n += NR) {
                    int nr_size = std::min(NR, nc_size - n);
                    
                    for (int m = 0; m < mc_size; m += MR) {
                        int mr_size = std::min(MR, mc_size - m);
                        
                        // Compute 8×8 tile (or partial tile at edges)
                        // C[mc+m:mc+m+mr_size, nc+n:nc+n+nr_size] += 
                        //   A_packed[m:m+mr_size, :] × B_packed[:, n:n+nr_size]
                        
                        // A_packed layout: (MC/MR) tiles of K×MR each
                        // So tile m is at A_packed + (m/MR) * (kc_size * MR)
                        const float* a_ptr = A_packed + (m / MR) * (kc_size * MR);
                        // B_packed layout: (NC/NR) tiles of K×NR each
                        // So tile n is at B_packed + (n/NR) * (kc_size * NR)
                        const float* b_ptr = B_packed + (n / NR) * (kc_size * NR);
                        float* c_ptr = C + (mc + m) * N + (nc + n);
                        
                        if (mr_size == MR && nr_size == NR) {
                            // Full 8×8 tile - use microkernel directly
                            // Microkernel computes C += A × B (accumulates into existing C)
                            // ldc = N (full row stride of C matrix)
                            Gemm_8x8_Microkernel(a_ptr, b_ptr, c_ptr, kc_size, N);
                        } else {
                            // Partial tile - use reference implementation
                            // This handles edge cases where M or N isn't multiple of 8
                            // B layout for partial tiles: still K×NR but only first nr_size columns valid
                            for (int i = 0; i < mr_size; i++) {
                                for (int j = 0; j < nr_size; j++) {
                                    float acc = 0.0f;
                                    for (int k = 0; k < kc_size; k++) {
                                        // A_packed layout: tile i is at (i/MR) * (kc_size*MR) + k*MR + i%MR
                                        const float* a_tile = A_packed + (i / MR) * (kc_size * MR);
                                        // B layout: tile at (n/NR) * (kc_size*NR) + k*NR + j
                                        acc += a_tile[k * MR + (i % MR)] * b_ptr[k * NR + j];
                                    }
                                    c_ptr[i * N + j] += alpha * acc;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    aligned_free(A_packed);
    aligned_free(B_packed);
}

// ============================================================================
// Performance Measurement Structure
// ============================================================================

struct GemmPerfResult {
    double cycles;
    double gflops;
    double bytes_moved;
    double arithmetic_intensity;
    double roofline_efficiency;
};

// Calculate theoretical memory traffic for blocked GEMM
inline double CalculateBytesMoved(int M, int N, int K) {
    // A: M×K floats read once (ideally stays in L2)
    // B: K×N floats read once (ideally streamed from L3/memory)
    // C: M×N floats read+written (accumulation)
    double bytes_A = static_cast<double>(M) * K * sizeof(float);
    double bytes_B = static_cast<double>(K) * N * sizeof(float);
    double bytes_C = static_cast<double>(M) * N * sizeof(float) * 2;  // read + write
    return bytes_A + bytes_B + bytes_C;
}

// Calculate theoretical GFLOPS for GEMM
inline double CalculateTheoreticalGFLOPS(int M, int N, int K, double seconds) {
    double flops = 2.0 * M * N * K;  // 2 FLOPs per multiply-add
    return flops / seconds / 1e9;
}

} // namespace RawrXD
