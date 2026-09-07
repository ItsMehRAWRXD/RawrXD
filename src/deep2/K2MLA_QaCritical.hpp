// K2MLA_QaCritical.hpp — pin-tag-1 (q_a) GEMV path attribution
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

// DEEP2_MLA_QA_PATH: auto | fused | compat (q_a only; q_b untouched)
enum class QaPathForce : uint8_t { Auto = 0, Fused = 1, Compat = 2 };

QaPathForce MLA_QaPathForce();
bool MLA_QaAllowFused(bool braidPreferFused);
bool MLA_QaWantFused();

void MLA_QaCrit_Reset();
void MLA_QaCrit_Begin();
void MLA_QaCrit_NoteSetup(uint64_t us);
void MLA_QaCrit_NoteFused(uint64_t us, bool ok);
void MLA_QaCrit_NoteCompat(uint64_t us, bool ok);
void MLA_QaCrit_NoteFallback();
void MLA_QaCrit_NoteUpload();
void MLA_QaCrit_End(uint64_t totalUs);

uint64_t MLA_QaTotalUs();
uint64_t MLA_QaFusedUs();
uint64_t MLA_QaCompatUs();
uint64_t MLA_QaDispatchUs();
uint64_t MLA_QaKernelUs();
uint64_t MLA_QaOutputUs();
uint64_t MLA_QaCalls();
uint64_t MLA_QaFusedHits();
uint64_t MLA_QaCompatHits();
uint64_t MLA_QaFallbacks();
uint64_t MLA_QaUploads();

void MLA_QaCrit_Emit(FILE* f);

} // namespace Deep2
