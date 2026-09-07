// K2MLA_GpuGemv.hpp — live MLA GPU GEMV (Q4_K + Q8_0)
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

bool MLA_GpuGemvWanted();
void MLA_GpuGemv_SetPinKey(uint64_t key); // layer<<8|tensorTag; 0=content fp
// GPU attempt primitive ONLY — must not be called from live MLA weights.
bool MLA_TryGpuGemv(int ggmlType, const void* packed, size_t bytes,
                    const float* input, float* output,
                    uint32_t rows, uint32_t cols);
// Authority: GPU → (if wanted+miss) GetGEMV. Live MLA MUST call this.
bool MLA_Gemv(int ggmlType, const void* packed, size_t bytes,
              const float* input, float* output,
              uint32_t rows, uint32_t cols);
bool MLA_GemvQ4K(const void* packed, size_t bytes,
                 const float* input, float* output,
                 uint32_t rows, uint32_t cols);
uint64_t MLA_GpuGemvOps();
uint64_t MLA_GpuGemvFail();
uint64_t MLA_GpuGemvSkip();
uint64_t MLA_GemvEntries();
uint64_t MLA_TryGpuGemvEntries();

// Family attribution from pinKey low byte (1=Qa 2=Qb 3=KVa 4=Kb 5=Vb 6=O).
uint64_t MLA_UploadQ();
uint64_t MLA_UploadK();
uint64_t MLA_UploadV();
uint64_t MLA_UploadO();
uint64_t MLA_HitQ();
uint64_t MLA_HitK();
uint64_t MLA_HitV();
uint64_t MLA_HitO();
uint64_t MLA_CacheKeyNew();
uint64_t MLA_CacheKeyReuse();
uint64_t MLA_SlotEvict();
uint64_t MLA_MetaUpload();   // separate scale/superblock path (0 until split)
uint64_t MLA_WeightUpload(); // packed weight body uploads
uint64_t MLA_PinKeyZero();   // SetPinKey missing before Dispatch

void MLA_GpuGemv_Reset();
void MLA_GpuGemv_Emit(FILE* f);

} // namespace Deep2
