// K2MLA_FusedQ4KT.hpp — fused packed-Q4_K under MLA_Gemv authority
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

bool MLA_FusedQ4KT_Wanted();
bool MLA_FusedQ4KT(const void* packed, size_t bytes, const float* input,
                   float* output, uint32_t rows, uint32_t cols, uint64_t pinKey);

uint64_t MLA_FusedQ4KT_NowUs();
void MLA_NoteGemvCompatUs(uint64_t t0);
void MLA_NoteF32WeightExpand(uint64_t tempBytes);

uint64_t MLA_FusedQ4KT_Calls();
uint64_t MLA_FusedQ4KT_Ops();
uint64_t MLA_FusedQ4KT_Fail();
uint64_t MLA_FusedQ4KT_Us();
uint64_t MLA_GemvCompatUs();
uint64_t MLA_F32WeightExpands();
uint64_t MLA_Q4KTempWeightBytes();

void MLA_FusedQ4KT_Reset();
void MLA_FusedQ4KT_Emit(FILE* f);

} // namespace Deep2
