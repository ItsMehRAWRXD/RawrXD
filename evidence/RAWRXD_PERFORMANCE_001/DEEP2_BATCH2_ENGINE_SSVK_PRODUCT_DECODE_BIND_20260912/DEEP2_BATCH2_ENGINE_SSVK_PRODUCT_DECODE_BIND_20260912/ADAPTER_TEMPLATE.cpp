/*
  Bound adapter — in-process packed dual from
  DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001 (84-byte SPV + material overlap).
  Implementation: src/deep2/Deep2SsVkPackedDualAdapter.cpp
*/
#include "Deep2SsVkProductBind.hpp"
#include "../../../src/deep2/Deep2SsVkPackedDualAdapter.hpp"

// During engine/session setup (also auto-bound in Deep2Engine::enableVulkan):
//
// Deep2::PackedDualAdapterCtx ctx{};
// Deep2::PackedDualAdapterOpen(&ctx);
// engine.bindSsVkPackedQ2K(&Deep2::PackedDualAdapterGemv, &ctx);
