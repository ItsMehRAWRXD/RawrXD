#ifndef RAWRXD_120B_LOADER_H
#define RAWRXD_120B_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* RawrXD_Handle;
typedef RawrXD_Handle RawrXD_ModelHandle;

enum RawrXD_QuantType {
    RAWRXD_Q8_0 = 8,
    RAWRXD_Q4_K = 12,
    RAWRXD_Q2_K = 10,
};

RawrXD_Handle RawrXD_LoadModel(const char* filePath, void* arena, size_t arenaSize);
void RawrXD_UnloadModel(RawrXD_Handle handle);
void* RawrXD_GetLayer(RawrXD_Handle handle, uint32_t layerIndex);
uint32_t RawrXD_Quantize(const float* src, void* dst, uint32_t nElements, RawrXD_QuantType quantType);
int RawrXD_KVCache_Init(RawrXD_Handle handle);
void RawrXD_KVCache_Update(RawrXD_Handle handle, uint32_t position, const float* kVector, const float* vVector);
void RawrXD_KVCache_Evict(RawrXD_Handle handle);

typedef void* RawrXD_InferenceHandle;

RawrXD_InferenceHandle RawrXD_Inference_Init(RawrXD_Handle modelHandle, void* tokenizerHandle);
uint32_t RawrXD_Inference_Generate(RawrXD_InferenceHandle engine, const uint32_t* promptTokens, uint32_t nPrompt, uint32_t* outTokens, uint32_t maxGen);
void RawrXD_Inference_Free(RawrXD_InferenceHandle engine);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_120B_LOADER_H
