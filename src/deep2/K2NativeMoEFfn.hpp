/* K2NativeMoEFfn — host K2 MoE after MLA; shared placer seam. */
#pragma once
#include "KimiK2Config.hpp"
#include <cstdint>
#include <string>

namespace Deep2 {
class GlobalTensorIndex;

/* decodePhase=true → increments D2_MOE_DECODE_* (32-tok host proof). */
bool K2NativeMoE_AfterMla(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                          uint32_t layer, bool decodePhase, float* hiddenIO,
                          float* scratch, std::string& error);

bool K2MoEPlaceAndExec(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                       uint32_t layer, bool decodePhase, const float* normed,
                       float* accum, std::string& error);

} // namespace Deep2
