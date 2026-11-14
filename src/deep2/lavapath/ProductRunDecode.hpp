#pragma once
/* Decode step — declaration only (def in ProductRunDecode.cpp). */
#include "ProductRuntime.hpp"
#include "ProductRequest.hpp"
#include <cstdint>

namespace rawr::product_run {

void RunDecodeStream(ProductRuntime& rt, const char* prompt, uint32_t maxTokens,
                     const TokenFn& onPiece, Result& r, int& userCancel);

} // namespace rawr::product_run
