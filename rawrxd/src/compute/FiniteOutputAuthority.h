// FiniteOutputAuthority.h — RAWRXD_FINITE_OUTPUT_AUTHORITY_001
// Validates that inference outputs (logits, hidden states, etc.) are
// finite. Any NaN/Inf is recorded with the offending index and value
// so that non-finite outputs cannot be silently propagated downstream.
#pragma once
#include <cstddef>
#include <string>

namespace rawrxd { namespace finite {

struct FiniteResult {
    size_t  count     = 0;
    size_t  finite    = 0;
    size_t  nan       = 0;
    size_t  inf       = 0;
    float   minVal    = 0.0f;
    float   maxVal    = 0.0f;
    bool    allFinite = false;
};

FiniteResult check(const float* data, size_t count);

void recordFailure(const char* stage, size_t firstBadIndex, float badValue);

void writeFiniteReceipt(const std::string& path);

}} // namespace rawrxd::finite