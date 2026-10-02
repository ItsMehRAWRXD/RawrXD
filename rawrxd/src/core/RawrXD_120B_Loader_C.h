// ============================================================================
// RawrXD_120B_Loader_C.h — C ABI for the 120B assembly model loader
//
// RAWRXD_UNSIMULATE_001 / RAWRXD_END_TO_END_STATE_001
//
// sovereign_model_loader.h has included this header -- originally from
// "../build/120b_loader/", a build-output path that has never existed -- since
// before the tree was assembled, so that translation unit has never compiled.
// The declarations below are recovered from the call sites in
// sovereign_model_loader.cpp, so the C++ wrapper and this ABI now agree.
//
// STATE OF THE BACKING MODULE: the assembly implementation is NOT present.
// There is no RawrXD_120B_Loader.asm anywhere in the tree. These functions are
// therefore DECLARED AND NOT DEFINED here.
//
// That is deliberate and it fails loudly. The alternative -- an inline stub
// returning a fake handle -- is the defect this whole pass exists to remove: it
// would make `RawrXD_LoadModel` return non-null, the wrapper would believe it
// loaded a 120B model, and nothing would ever try to read its weights. The
// linker error when the module is added is the correct outcome, because it says
// "this ABI has no implementation" at the point where someone adds one.
//
// To bring the loader up:
//   1. add RawrXD_120B_Loader.asm exporting exactly these symbols,
//   2. add the .asm to a target's sources,
//   3. delete the RAWRXD_120B_LOADER_ABSENT notes below.
// Nothing else has to change; the wrapper already calls this ABI.
// ============================================================================
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Quantisation of a stored tensor. The three enumerators below are the ones the
// wrapper names; the rest round out the GGUF k-quants this tree uses so that a
// future caller does not have to extend a C ABI from C++.
typedef enum RawrXD_QuantType {
    RAWRXD_Q8_0 = 0,
    RAWRXD_Q4_0 = 1,
    RAWRXD_Q4_1 = 2,
    RAWRXD_Q5_0 = 3,
    RAWRXD_Q5_1 = 4,
    RAWRXD_Q2_K = 10,
    RAWRXD_Q3_K = 11,
    RAWRXD_Q4_K = 12,
    RAWRXD_Q5_K = 13,
    RAWRXD_Q6_K = 14,
    RAWRXD_Q8_K = 15,
    RAWRXD_F16  = 20,
    RAWRXD_F32  = 21
} RawrXD_QuantType;

// Opaque loaded-model handle. `nullptr` is the only invalid value the wrapper
// recognises, so the loader must return NULL rather than a sentinel integer on
// failure -- an int-shaped handle would make failure indistinguishable from
// success at the call site.
typedef void* RawrXD_ModelHandle;

// --- model lifecycle -------------------------------------------------------

// Loads a model file. Returns NULL on any failure. The wrapper treats NULL as
// "not loaded" and does not construct a ModelLoader around it.
RawrXD_ModelHandle RawrXD_LoadModel(const char* path);

// Releases a handle from RawrXD_LoadModel. Passing NULL is a no-op.
void RawrXD_UnloadModel(RawrXD_ModelHandle handle);

// Returns a pointer to layer `layerIndex`'s weight block, owned by the handle,
// or NULL when the index is out of range. The wrapper does not copy it, so the
// pointer is valid only until RawrXD_UnloadModel.
void* RawrXD_GetLayer(RawrXD_ModelHandle handle, uint32_t layerIndex);

// Storage quantisation chosen for layer `layerIndex` of a `nLayers`-layer model.
// The wrapper calls this with the layer count it believes the model has, so the
// loader can fall back to a per-layer default when that count disagrees with
// the file.
RawrXD_QuantType RawrXD_GetQuantTypeForLayer(uint32_t layerIndex, uint32_t nLayers);

// Quantises `nElements` float32 values from `input` into `output`.
//
// CONTRACT: `output` must have room for at least `nElements * 2` bytes, which is
// what the wrapper allocates. A 2-byte-per-element bound is the worst case
// across the k-quants above; Q8_0 needs one and the k-quants need less than
// one, so this is safe for every type in the enum.
//
// Returns 0 on success, non-zero on failure. The wrapper ignores the return
// value today, which is a known gap rather than a hidden one -- see the note in
// QuantizeTensor.
int RawrXD_Quantize(const float* input,
                    uint8_t* output,
                    uint32_t nElements,
                    RawrXD_QuantType type);

// --- KV cache --------------------------------------------------------------

// Allocates the handle's KV cache using the model's own geometry.
// Returns 0 on success, non-zero on failure.
int RawrXD_KVCache_Init(RawrXD_ModelHandle handle);

// Appends one position's K and V for `position`. Returns 0 on success.
int RawrXD_KVCache_Update(RawrXD_ModelHandle handle,
                          uint32_t position,
                          const float* kVector,
                          const float* vVector);

// Drops everything the cache holds, keeping the allocation. Returns 0 on
// success. This is the operation the crashed specKvMirrorReset() corresponds to
// on the speculative path.
int RawrXD_KVCache_Evict(RawrXD_ModelHandle handle);

#ifdef __cplusplus
}  // extern "C"
#endif

// RAWRXD_120B_LOADER_ABSENT
//
// No definition of any symbol above exists in this tree. Declaring an ABI
// without an implementation is honest; providing an inline stub that returns a
// non-null handle would repeat, in C, the "generate plausible-looking
// predictions" defect removed from SpeculativeTreeAttentionBridge.