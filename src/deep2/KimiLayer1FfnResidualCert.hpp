/* KimiLayer1FfnResidualCert.hpp — DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT_001 */
#pragma once
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace kimi_l1_ffn {

inline bool CertOn() {
    const char* e = std::getenv("DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT");
    return e && e[0] == '1';
}
inline bool StrictOn() {
    if (CertOn()) return true;
    const char* e = std::getenv("DEEP2_CERT_STRICT");
    return e && e[0] == '1';
}

/* Missing-layer identity memcpy is forbidden under certification. */
inline bool RejectMissingLayerIdentity(size_t layer, size_t loaded,
                                       const char* arch, const char* site) {
    if (!StrictOn()) return false;
    std::fprintf(stderr,
                 "CERT_FAIL site=%s MISSING_LAYER_IDENTITY "
                 "requested_layer=%zu loaded_layers=%zu arch=%s\n"
                 "CERT_GATE=DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT_001\n"
                 "PROMOTE=0\n",
                 site ? site : "?", layer, loaded, arch ? arch : "?");
    std::fflush(stderr);
    return true;
}

/* Deterministic names: <DIR>\<key>.f32  (DIR from env or cwd). */
inline const char* CertOutDir() {
    const char* d = std::getenv("DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT_DIR");
    return (d && d[0]) ? d : ".";
}
inline void DumpVecBin(const char* key, const float* v, size_t n) {
    char path[1024];
    std::snprintf(path, sizeof(path), "%s\\%s.f32", CertOutDir(), key);
    FILE* f = std::fopen(path, "wb");
    if (!f) {
        std::fprintf(stderr, "L1FFN_CKPT_WRITE_FAIL key=%s path=%s\n", key, path);
        std::fflush(stderr);
        return;
    }
    const size_t wr = std::fwrite(v, sizeof(float), n, f);
    std::fclose(f);
    std::fprintf(stderr, "L1FFN_CKPT_FILE key=%s path=%s bytes=%zu ok=%d\n",
                 key, path, wr * sizeof(float), wr == n ? 1 : 0);
    std::fflush(stderr);
}
inline void DumpVec(const char* key, uint32_t layer, uint32_t tok,
                    const float* v, size_t n) {
    if (!CertOn() || !v || !n) return;
    double ss = 0.0;
    size_t nf = 0;
    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(v[i])) ++nf;
        else ss += (double)v[i] * (double)v[i];
    }
    std::fprintf(stderr,
                 "L1FFN_CKPT key=%s layer=%u tok=%u n=%zu l2=%.9g "
                 "h0=%.9g h1=%.9g nonfinite=%zu\n",
                 key, layer, tok, n, std::sqrt(ss),
                 n > 0 ? (double)v[0] : 0.0,
                 n > 1 ? (double)v[1] : 0.0, nf);
    std::fflush(stderr);
    DumpVecBin(key, v, n);
}

/* Invariant: residual == inp + down (elementwise). Returns maxAbs error. */
inline double CheckResidualInvariant(const float* inp, const float* down,
                                     const float* residual, size_t n) {
    double maxAbs = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double expect = (double)inp[i] + (double)down[i];
        const double err = std::fabs(expect - (double)residual[i]);
        if (err > maxAbs) maxAbs = err;
    }
    return maxAbs;
}

inline void EmitInvariant(uint32_t layer, uint32_t tok, double maxAbs,
                          size_t n) {
    const int pass = (maxAbs < 1e-5) ? 1 : 0;
    std::fprintf(stderr,
                 "L1FFN_INVARIANT layer=%u tok=%u n=%zu "
                 "FFN_RESIDUAL_EQ_INP_PLUS_DOWN maxAbs=%.9g PASS=%d\n"
                 "CERT_GATE=DEEP2_KIMI_LAYER1_FFN_RESIDUAL_CERT_001 "
                 "PROMOTE=0\n",
                 layer, tok, n, maxAbs, pass);
    std::fflush(stderr);
}

} // namespace kimi_l1_ffn
} // namespace Deep2
