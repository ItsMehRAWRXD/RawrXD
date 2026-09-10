#pragma once
/* OpenSession + SEH — ≤99-line block companion to product_deep2_infer_internal. */
#include "product_deep2_open_gate.hpp"
#include "../../deep2/lavapath/ProductStreamerPrep.hpp"
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

inline bool TensorsResident(const product_run::ProductRuntime& rt) {
    /* Name historic. OPEN is streamable — not full-weight residency. */
    Deep2::product_open::Facts so = Deep2::product_open::Evaluate(
        const_cast<Deep2::Deep2Engine&>(rt.Eng()), rt.modelPath.c_str());
    return so.open_pass != 0;
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
    if (!rt.OpenSession(a) || !rt.IsOpen() || !TensorsResident(rt)) {
        ProductOpenFacts f = CollectOpenFacts(rt);
        MarkSessionFacts(f);
        EmitSessionLine(a, 0, f);
        return false;
    }
    ProductOpenFacts f = CollectOpenFacts(rt);
    MarkSessionFacts(f);
    if (!f.product_open_pass) {
        EmitSessionLine(a, 0, f);
        rt.CloseSession();
        return false;
    }
    EmitSessionLine(a, 1, f);
    return true;
}

} // namespace product_infer_detail
} // namespace rawr
