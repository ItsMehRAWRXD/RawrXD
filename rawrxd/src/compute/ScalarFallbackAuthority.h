// ScalarFallbackAuthority.h — RAWRXD_SCALAR_FALLBACK_AUTHORITY_001
// Records every time a quantized/optimized kernel falls back to scalar
// execution. Any non-zero fallback count is a FAIL — the production
// path must use a real optimized kernel, not scalar.
#pragma once
#include <string>

namespace rawrxd { namespace scalar {

void recordFallback(const char* quantType, const char* reason);

int getFallbackCount();

void writeFallbackReceipt(const std::string& path);

}} // namespace rawrxd::scalar