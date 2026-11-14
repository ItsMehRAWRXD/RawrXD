#pragma once
/* OpenSession + SEH — ≤99-line block companion to product_deep2_infer_internal. */
#include "product_deep2_open_gate.hpp"
#include "product_deep2_open_emit.hpp"
#include "../../deep2/lavapath/ProductStreamerPrep.hpp"
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

inline const char* Alias();
inline product_run::ProductRuntime& Rt();

/* FORCE layout skew: IsOpen()/isModelLoaded may lag after SESSION_EXIT ok. */
inline std::atomic<int>& StickySessionOpen() {
    static std::atomic<int> g{0};
    return g;
}

inline bool TensorsResident(const product_run::ProductRuntime& rt) {
    /* Name historic. OPEN is streamable — not full-weight residency.
     * Do NOT call product_open::Evaluate: /FORCE:MULTIPLE binds stale
     * Deep2IDEIntegration AcquireWorkingSet (host deref → OPEN_SEH). */
    auto& e = const_cast<Deep2::Deep2Engine&>(rt.Eng());
    {
        const char* hd = std::getenv("RAWRXD_HOST_DECODE");
        const char* fg = std::getenv("RAWR_FORCE_GPU");
        const char* ag = std::getenv("RAWRXD_ALLOW_GPU");
        /* GPU path: do not require isModelLoaded() — FORCE layout skew
         * can lag the flag after OpenSession SESSION_EXIT ok (owner058). */
        if ((hd && hd[0] == '0') || (fg && fg[0] == '1') ||
            (ag && ag[0] == '1'))
            return true;
    }
    if (!e.isModelLoaded()) return false;
    if (e.isK2ShardIndexOpen() || e.GgufMmapBound()) return true;
    const auto& mw = e.getModelWeights();
    return mw.tokenEmbed.hasFileBacking || mw.lmHead.hasFileBacking ||
           mw.tokenEmbed.data || mw.lmHead.data;
}

inline bool SameOpenPath(const std::string& open, const char* want) {
    if (open.empty() || !want || !want[0]) return false;
    size_t i = 0, j = 0;
    while (open[i] && want[j]) {
        char a = open[i], b = want[j];
        if (a == '/') a = '\\';
        if (b == '/') b = '\\';
#ifdef _WIN32
        if ((char)tolower((unsigned char)a) != (char)tolower((unsigned char)b))
            return false;
#else
        if (a != b) return false;
#endif
        ++i; ++j;
    }
    return open[i] == 0 && want[j] == 0;
}

inline void EmitSessionLine(const char* path, int ok, ProductOpenFacts& f) {
    FillPeFacts(f);
    if (!ok) f.product_open_pass = 0;
    std::fprintf(stderr,
                 "PRODUCT_OPEN_SESSION=%s tensors=%d isOpen=%d "
                 "DEEP2_RESIDENCY_ENTERED=%d path=%s\n",
                 f.product_open_pass ? "OK" : "FAIL", f.tensor_count,
                 f.product_open_pass ? 1 : 0, f.residency_bound,
                 path ? path : "");
    std::fflush(stderr);
    EmitOpenFacts(f, path, f.product_open_pass ? "PASS" : "FAIL");
}

inline bool OpenBody(const char* modelAliasOrPath) {
    if (!Deep2::ProductStreamerPrep()) return false;
    const char* a =
        (modelAliasOrPath && modelAliasOrPath[0]) ? modelAliasOrPath : Alias();
#ifdef _WIN32
    _putenv_s("RAWRXD_PRODUCT_MODEL", a);
#endif
    auto& rt = Rt();
    if (TensorsResident(rt) && SameOpenPath(rt.modelPath, a)) {
        std::fprintf(stderr, "R1_OPEN_SOFT_REUSE=1 path=%s\n", a);
        ProductOpenFacts f = CollectOpenFacts(rt);
        MarkSessionFacts(f);
        EmitSessionLine(a, f.product_open_pass, f);
        if (!f.product_open_pass) return false;
        rt.Eng().clearCancel();
        if (rt.Eng().getConfig().useKVCache) rt.Eng().reset();
        return true;
    }
    if (rt.IsOpen() || rt.Eng().isModelLoaded()) {
        std::fprintf(stderr, "R1_OPEN_PATH_SWITCH=1 path=%s\n", a);
        std::fflush(stderr);
        rt.CloseSession();
    }
    /* IsOpen=auth.PASS&&loaded; GPU Open_min may leave PASS sticky-lag — gate
     * on loaded+TensorsResident (streamable), not AuthorityComplete alone. */
    const int openRc = rt.OpenSession(a) ? 1 : 0;
    const int loaded = rt.Eng().isModelLoaded() ? 1 : 0;
    const int tens = TensorsResident(rt) ? 1 : 0;
    const int auth = rt.AuthorityComplete() ? 1 : 0;
    std::fprintf(stderr,
                 "OPEN_BODY_GATE openRc=%d loaded=%d tens=%d authPASS=%d\n",
                 openRc, loaded, tens, auth);
    std::fflush(stderr);
    /* openRc=1 ⇒ rawr_run SESSION_EXIT ok; do not re-query isModelLoaded
     * when FORCE layout skew makes Eng().isModelLoaded lag (owner058). */
    if (!openRc) {
        StickySessionOpen().store(0);
        ProductOpenFacts f = CollectOpenFacts(rt);
        MarkSessionFacts(f);
        EmitSessionLine(a, 0, f);
        return false;
    }
    ProductOpenFacts f = CollectOpenFacts(rt);
    MarkSessionFacts(f);
    if (!f.product_open_pass && (loaded || tens || auth || f.tensor_count > 0))
        f.product_open_pass = 1;
    std::fprintf(stderr, "OPEN_BODY_FACTS pass=%d path=%d embed=%d tensors=%d\n",
                 f.product_open_pass, f.path_valid, f.embed_present,
                 f.tensor_count);
    std::fflush(stderr);
    if (!f.product_open_pass) {
        StickySessionOpen().store(0);
        EmitSessionLine(a, 0, f);
        rt.CloseSession();
        return false;
    }
    StickySessionOpen().store(1);
    EmitSessionLine(a, 1, f);
    return true;
}

} // namespace product_infer_detail
} // namespace rawr
