// =============================================================================
// sovereign_kernel_bridge.h
// C/MASM Kernel Bridge Interface
// Defines the Application Binary Interface (ABI) for C++ scheduler to call
// low-level MASM kernels for 120B inference.
//
// Calling Convention: Windows x64 fastcall (Microsoft x64 calling convention)
//   - First 4 parameters: RCX, RDX, R8, R9
//   - Caller saves: RAX, RCX, RDX, R8, R9, R10, R11
//   - Callee saves: RBX, RBP, RDI, RSI, R12-R15
//   - Return value: RAX
// =============================================================================

#ifndef SOVEREIGN_KERNEL_BRIDGE_H
#define SOVEREIGN_KERNEL_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Plain Old Data (POD) Structures
// These must match MASM struct definitions exactly, no padding/alignment tricks
// =============================================================================

#pragma pack(push, 1)

/// @brief Inference context passed to kernel
/// Must be POD: no pointers to heap, no virtual functions
typedef struct {
    uint32_t token_id;           // Input token ID
    uint32_t sequence_len;       // Current sequence length
    uint32_t batch_size;         // Batch size (typically 1)
    uint32_t reserved0;          // Padding
    
    const float* weights;        // Pointer to quantized weights
    const float* kv_cache;       // Pointer to KV cache
    float* output_logits;        // Output logits buffer (vocabulary size)
    void* scratch_buffer;        // Scratch memory for intermediate activations
    
    uint32_t hidden_size;        // 4096 for 120B
    uint32_t vocab_size;         // Typically 128000
    uint32_t num_layers;         // Typically 80
    uint32_t reserved1;          // Padding
    
} Sovereign_InferenceContext;

/// @brief Kernel execution result
typedef struct {
    uint32_t status;             // 0 = success, non-zero = error
    uint32_t tokens_generated;   // How many tokens were generated
    uint64_t latency_us;         // Execution time in microseconds
    uint32_t reserved[2];        // Padding
    
} Sovereign_KernelResult;

#pragma pack(pop)

// =============================================================================
// Kernel Entry Points (implemented in MASM, called from C++)
// =============================================================================

/// @brief Initialize kernel (allocate tables, etc.)
/// @return 0 on success
extern int Sovereign_Kernel_Initialize(void);

/// @brief Single token inference
/// Process one token through the 120B model
/// Parameters (Windows x64 fastcall):
///   RCX = pointer to Sovereign_InferenceContext
///   RDX = pointer to Sovereign_KernelResult (output)
///   R8 = thread_id (for NUMA awareness)
///   R9 = reserved
/// @return 0 on success
extern int Sovereign_Kernel_ProcessToken(
    const Sovereign_InferenceContext* context,
    Sovereign_KernelResult* result,
    uint32_t thread_id
);

/// @brief Batch token inference
/// Process multiple tokens at once
/// Parameters:
///   RCX = pointer to array of Sovereign_InferenceContext
///   RDX = batch size
///   R8 = pointer to array of Sovereign_KernelResult
///   R9 = thread_id
/// @return 0 on success
extern int Sovereign_Kernel_ProcessBatch(
    const Sovereign_InferenceContext* contexts,
    uint32_t batch_size,
    Sovereign_KernelResult* results,
    uint32_t thread_id
);

/// @brief Shutdown kernel (cleanup)
/// @return 0 on success
extern int Sovereign_Kernel_Shutdown(void);

// =============================================================================
// Kernel Capabilities Query (diagnostics)
// =============================================================================

/// @brief Get kernel feature flags
/// Bit 0: AVX-512 support
/// Bit 1: AMX support
/// Bit 2: GPU offload available
extern uint32_t Sovereign_Kernel_GetCapabilities(void);

/// @brief Get throughput (tokens/sec) for current hardware
extern uint32_t Sovereign_Kernel_GetThroughputEstimate(void);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_KERNEL_BRIDGE_H
