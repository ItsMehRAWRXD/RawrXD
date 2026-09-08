// TpsScaleHotpatch.hpp — RE: wall TPS ~0.313 vs STREAM_TPB 2e-8 vs warmCompressed
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {

// Wall-clock decode: tokens / (wallMs/1000) = 1000*tokens/wallMs (~0.313).
// Display reverse (user): ×1000 → 313.0 TPS units.
inline double TpsScale_WallRaw(uint32_t tokens, double wallMs) {
    if (!tokens || wallMs <= 0.0) return 0.0;
    return 1000.0 * (double)tokens / wallMs;
}
inline double TpsScale_Display(double rawTps) {
    const char* e = std::getenv("DEEP2_TPS_DISPLAY_SCALE");
    const double s = (e && *e) ? atof(e) : 1.0;
    return rawTps * ((s > 0.0) ? s : 1.0);
}
// STREAM_TOKENS_PER_BYTE_READ ≈ 2e-8 (= 1/BPT). Reverse → BPT or NORM path.
inline double TpsScale_ReverseTpb(double tpb) {
    return (tpb > 0.0) ? (1.0 / tpb) : 0.0;
}
// HalfPass ÷2 on multi-token; undo with ×2 (not a negative multiply).
inline uint64_t TpsScale_Unhalf(uint64_t v, uint64_t tokens) {
    return (tokens >= 2ull) ? (v * 2ull) : v;
}
// warmCompressed Used underflow (= unsigned "negative") → treat as 0.
inline size_t TpsScale_SaturatingSub(size_t cur, size_t bytes) {
    return (bytes >= cur) ? 0u : (cur - bytes);
}

void TpsScale_Emit(FILE* f, uint32_t tokens, double wallMs, double tpb);

} // namespace Deep2
