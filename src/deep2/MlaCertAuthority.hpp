// MlaCertAuthority.hpp — MLA-CERT-001 witnesses earned only on live complete path
#pragma once
#include "K2MLAAttention.hpp"
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace Deep2 {
namespace MlaCertAuthority {

struct Witness {
    std::atomic<int> mlaRequired{0};
    std::atomic<int> mlaCertified{0};
    std::atomic<int> mlaForwardEntered{0};
    std::atomic<int> mlaAttentionCompleteUsed{0};
    std::atomic<int> unsafeMlaUsed{0};
    std::atomic<int> fallbackAttentionUsed{0};
    std::atomic<int> stubAttentionUsed{0};
    std::atomic<int> outputFinite{0};
    std::atomic<int> outputShapeValid{0};
    std::atomic<int> productionDecodePath{0};
};

inline Witness& W() {
    static Witness w;
    return w;
}

inline void Reset() {
    auto& w = W();
    w.mlaRequired = 0;
    w.mlaCertified = 0;
    w.mlaForwardEntered = 0;
    w.mlaAttentionCompleteUsed = 0;
    w.unsafeMlaUsed = 0;
    w.fallbackAttentionUsed = 0;
    w.stubAttentionUsed = 0;
    w.outputFinite = 0;
    w.outputShapeValid = 0;
    w.productionDecodePath = 0;
}

inline void NoteRequired() { W().mlaRequired = 1; }

inline void NoteUnsafeEnv() { W().unsafeMlaUsed = 1; }

inline void NoteForwardEntered() { W().mlaForwardEntered = 1; }

inline void NoteStub() { W().stubAttentionUsed = 1; }

inline void NoteFallback() { W().fallbackAttentionUsed = 1; }

inline void NoteCompleteSuccess(const MlaCompleteStats& st, const float* out,
                                size_t n) {
    W().mlaAttentionCompleteUsed = 1;
    W().mlaForwardEntered = 1;
    int finite = 1;
    if (out && n) {
        for (size_t i = 0; i < n; ++i) {
            if (!std::isfinite(out[i])) {
                finite = 0;
                break;
            }
        }
    } else {
        finite = 0;
    }
    W().outputFinite = finite;
    W().outputShapeValid = (n > 0) ? 1 : 0;
    if (st.ropeApplied && st.softmaxFinite && st.kvCacheWrite && st.kvCacheRead &&
        finite && n > 0 && W().unsafeMlaUsed.load() == 0 &&
        W().stubAttentionUsed.load() == 0 &&
        W().fallbackAttentionUsed.load() == 0) {
        W().mlaCertified = 1;
        W().productionDecodePath = 1;
    }
}

inline bool ProductSealPass() {
    auto& w = W();
    return w.mlaRequired.load() && w.mlaCertified.load() &&
           w.mlaForwardEntered.load() && w.mlaAttentionCompleteUsed.load() &&
           !w.unsafeMlaUsed.load() && !w.fallbackAttentionUsed.load() &&
           !w.stubAttentionUsed.load() && w.outputFinite.load() &&
           w.outputShapeValid.load() && w.productionDecodePath.load();
}

} // namespace MlaCertAuthority
} // namespace Deep2
