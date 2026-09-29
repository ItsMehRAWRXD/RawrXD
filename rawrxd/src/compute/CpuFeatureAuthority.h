// CpuFeatureAuthority.h — RAWRXD_CPU_FEATURE_AUTHORITY_001
// Detects CPU ISA features (AVX-512 F/BW/VNNI, AVX2, FMA, SSE4.2)
// using __cpuid intrinsics on Windows so that kernel dispatch can
// choose the correct optimized path (or record scalar fallback).
#pragma once
#include <string>

namespace rawrxd { namespace cpu {

struct CpuFeatures {
    bool avx512f    = false;
    bool avx512bw  = false;
    bool avx512vnni= false;
    bool avx2      = false;
    bool fma       = false;
    bool sse42     = false;
};

CpuFeatures detectFeatures();

void writeFeatureReceipt(const std::string& path);

}} // namespace rawrxd::cpu