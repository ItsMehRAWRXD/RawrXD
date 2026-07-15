// ============================================================================
// BlockedGemm_Single.hpp - C-Callable Entry Point for Blocked GEMM
// ============================================================================
// Provides a clean C-callable interface for the Forward_QKV assembly router.
// Bridges the high-level tensor abstraction to the cache-blocked GEMM kernel.
//
// Windows x64 ABI:
//   RCX = A (float* or Tensor*)
//   RDX = B (float* or Tensor*)
//   R8  = C (float* or Tensor*)
//   R9  = M (rows of A/C) - optional, for raw pointer mode
//   [RSP+40] = N (cols of B/C) - optional
//   [RSP+48] = K (inner dim) - optional
//   [RSP+56] = alpha - optional
//   [RSP+64] = beta - optional
// ============================================================================

#pragma once

#include "BlockedGemm.hpp"

// ============================================================================
// Tensor Structure (matches TensorContext.asm layout)
// ============================================================================
struct TensorDesc {
    uint64_t dims[4];       // Dimensions [d0, d1, d2, d3]
    uint64_t strides[4];    // Strides in elements
    float* data;            // Pointer to float data
    uint64_t elem_count;    // Total element count
    uint32_t flags;         // Ownership/alignment flags
    uint32_t dtype;         // Data type enum
    uint8_t padding[16];    // Pad to 96 bytes
};

// ============================================================================
// BlockedGemm_Single - C-Callable Entry Point (Tensor Mode)
// ============================================================================
// Takes Tensor descriptors and extracts dimensions automatically.
// This is the primary interface for the Forward_QKV assembly router.
//
// Parameters:
//   RCX = TensorDesc* A    (Input tensor: [M, K])
//   RDX = TensorDesc* B    (Weight tensor: [K, N])
//   R8  = TensorDesc* C    (Output tensor: [M, N])
//
// Returns: 0 on success, non-zero on failure
// ============================================================================
extern "C" int BlockedGemm_Single_Tensor(
    const TensorDesc* A,
    const TensorDesc* B,
    TensorDesc* C
);

// ============================================================================
// BlockedGemm_Single - C-Callable Entry Point (Raw Pointer Mode)
// ============================================================================
// Takes raw float pointers with dimensions passed on stack.
// This is the fallback interface for direct pointer manipulation.
//
// Parameters:
//   RCX = float* A         (Input matrix: M×K row-major)
//   RDX = float* B         (Weight matrix: K×N row-major)
//   R8  = float* C         (Output matrix: M×N row-major)
//   R9  = size_t M         (Rows of A/C)
//   [RSP+40] = size_t N    (Columns of B/C)
//   [RSP+48] = size_t K    (Inner dimension)
//   [RSP+56] = float alpha (Scaling factor for A×B, default 1.0)
//   [RSP+64] = float beta  (Scaling factor for C, default 0.0)
//
// Returns: 0 on success, non-zero on failure
// ============================================================================
extern "C" int BlockedGemm_Single(
    const float* A,
    const float* B,
    float* C,
    size_t M,
    size_t N,
    size_t K,
    float alpha,
    float beta
);

// ============================================================================
// Implementation
// ============================================================================

#ifdef BLOCKEDGEMM_SINGLE_IMPLEMENTATION

extern "C" int BlockedGemm_Single_Tensor(
    const TensorDesc* A,
    const TensorDesc* B,
    TensorDesc* C
) {
    // Validate tensor descriptors
    if (!A || !B || !C) {
        return 1; // Invalid pointers
    }
    
    if (!A->data || !B->data || !C->data) {
        return 2; // Null data pointers
    }
    
    // Extract dimensions
    // A: [M, K] - Input tensor
    // B: [K, N] - Weight tensor
    // C: [M, N] - Output tensor
    
    size_t M = A->dims[0];
    size_t K = A->dims[1];
    size_t N = B->dims[1];
    
    // Validate dimension compatibility
    if (A->dims[1] != B->dims[0]) {
        return 3; // Dimension mismatch: A.cols != B.rows
    }
    
    if (C->dims[0] != M || C->dims[1] != N) {
        return 4; // Output dimension mismatch
    }
    
    // Call the blocked GEMM implementation
    RawrXD::BlockedGemm(
        A->data, B->data, C->data,
        static_cast<int>(M),
        static_cast<int>(N),
        static_cast<int>(K),
        1.0f,  // alpha
        0.0f   // beta (overwrite C)
    );
    
    return 0; // Success
}

extern "C" int BlockedGemm_Single(
    const float* A,
    const float* B,
    float* C,
    size_t M,
    size_t N,
    size_t K,
    float alpha,
    float beta
) {
    // Validate pointers
    if (!A || !B || !C) {
        return 1; // Invalid pointers
    }
    
    // Validate dimensions
    if (M == 0 || N == 0 || K == 0) {
        return 2; // Invalid dimensions
    }
    
    // Call the blocked GEMM implementation
    RawrXD::BlockedGemm(
        A, B, C,
        static_cast<int>(M),
        static_cast<int>(N),
        static_cast<int>(K),
        alpha,
        beta
    );
    
    return 0; // Success
}

#endif // BLOCKEDGEMM_SINGLE_IMPLEMENTATION