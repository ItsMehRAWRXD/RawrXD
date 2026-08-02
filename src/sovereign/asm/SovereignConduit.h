// ==================================================================================
// Sovereign Engine - Native Silicon Interloop Wrapper Configuration
// Hardware Target: R9700 AI Pro (32GB Uncached Bus Mapping)
// ==================================================================================

#pragma once
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Strict, zero-padding structure layout matching the compiled assembly register offsets
#pragma pack(push, 1)
struct InvariantCore {
    const float* MatrixTable;   // Offset 0x00: Pinned to Uncached VRAM (0x26653EA0000)
    uint32_t     OutputBuffer;  // Offset 0x08: Target Primitive Destination Register
};
#pragma pack(pop)

/**
 * Direct Zero-Branch Assembly Vector Compaction Pipeline.
 * Bypasses all intermediate OS logic loops.
 * 
 * @param corePtr          Pointer to the initialized InvariantCore configuration block.
 * @param activationPtr     Pointer to the active float hidden state activation vector (+theta).
 * @return                 Crystallized TokenId (Structural parity matching 0xAA).
 */
uint32_t RouteViaLinearConduitMASM(InvariantCore* corePtr, const float* activationPtr);

/**
 * Warhammer MoE Token Ring Vector Intercept.
 * Processes 4 expert lanes sequentially via AVX-512 FMA without branching.
 * 
 * @param corePtr          Pointer to the initialized InvariantCore configuration block.
 * @param activationPtr     Pointer to the active float hidden state activation vector (+theta).
 * @param ringBufferPtr     Base address of the rotating Warhammer Expert Ring (256 experts).
 * @return                 Crystallized TokenId (Structural parity matching 0xAA).
 */
uint32_t CycleWarhammerMoERing(InvariantCore* corePtr, const float* activationPtr, const float* ringBufferPtr);

#ifdef __cplusplus
}
#endif
