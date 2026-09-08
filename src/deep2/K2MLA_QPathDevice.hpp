// K2MLA_QPathDevice.hpp — device-resident Q_A→RMS→Q_B (one fused submit)
#pragma once
#include "TensorView.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

// Upload hidden once; pin Q weights; fuse GEMV+RMSNorm; download q_b (and q_a).
// Returns false → caller keeps host MLA_Gemv path. Opt-out: DEEP2_MLA_Q_DEVICE=0.
bool MLA_QPathDeviceFused(const float* hidden, float* q_a, float* q_b,
                          const RawrXD::TensorView& wQa,
                          const RawrXD::TensorView& wQb,
                          const RawrXD::TensorView& wNorm, bool haveNorm,
                          uint32_t hiddenDim, uint32_t qLora, uint32_t qBCols,
                          float eps, uint32_t layerIdx);

uint64_t MLA_QPathDevice_Ops();
uint64_t MLA_QPathDevice_Fail();
void MLA_QPathDevice_Reset();
void MLA_QPathDevice_Emit(FILE* f);

} // namespace Deep2
