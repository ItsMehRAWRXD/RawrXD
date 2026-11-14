#pragma once
/* ProductRuntime — session owner; OpenSession out-of-line (COMDAT-safe). ≤99. */
#include "../RawrRunSession.hpp"
#include "LocalModelAuthority_Bundle.hpp"
#include "ProductOpenStreamable.hpp"
#include "ProductReceipt.hpp"
#include "ProductRequest.hpp"
#include "ProductScoreboardBind.hpp"
#include "SessionControl.hpp"
#include "RxRunStateHooks.hpp"
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <string>

namespace rawr::product_run {

struct ProductRuntime {
    Deep2::Deep2Engine engine;
    Deep2::Deep2Engine* ext = nullptr;
    std::string modelAlias = "llama32";
    std::string modelPath;
    rawr::olma::AuthorityBundle auth{};
    SessionControl control{};
    std::atomic<int> alreadyGenerating{0};
    Result lastReceipt{};
    uint32_t graphNodes = 0;

    /* Decode pin uses this — reject only non-canonical ext before pin. */
    static bool ExtPlausible(const Deep2::Deep2Engine* p) noexcept {
        if (!p) return false;
        const auto u = reinterpret_cast<uintptr_t>(p);
        return u > 0x10000ull && (u & 0x7ull) == 0 &&
               u < (static_cast<uintptr_t>(-1) - 0x1000ull);
    }
    Deep2::Deep2Engine& Eng() {
        if (ext && !ExtPlausible(ext)) {
            std::fprintf(stderr, "PRODUCT_RUNTIME_EXT_WILD=%p CLEAR=1\n",
                         (void*)ext);
            std::fflush(stderr);
            ext = nullptr;
        }
        return ext ? *ext : engine;
    }
    const Deep2::Deep2Engine& Eng() const {
        if (ext && !ExtPlausible(ext)) return engine;
        return ext ? *ext : engine;
    }
    bool AuthorityComplete() const { return auth.PASS != 0; }

    bool BuildExecutionGraph() {
        graphNodes = 0;
        if (!AuthorityComplete() || !auth.geom.LAYERS) return false;
        graphNodes = auth.geom.LAYERS;
        return true;
    }

    void BindExternal(Deep2::Deep2Engine* e, const char* alias, const char* path) {
        ext = e;
        if (alias && alias[0]) modelAlias = alias;
        if (path && path[0]) modelPath = path;
        auth = {};
        control.Clear();
        if (e && e->sessionAuthorityPass()) {
            auth = e->sessionAuthority();
        } else if (path && path[0]) {
            (void)rawr::olma::SealAuthorityBundle(path, auth);
        } else if (alias && alias[0]) {
            (void)rawr::olma::SealAuthorityBundle(alias, auth);
        }
        (void)BuildExecutionGraph();
    }

    /* Out-of-line: beats InferenceEngine.lib stale inline COMDATs. */
    bool OpenSession(const char* aliasOrPath);
    void CloseSession();

    /* GPU Open_min: isModelLoaded may lag FORCE/inline skew after SESSION_EXIT.
     * Session is open when auth+path+layers land (streamable), not RAM-only. */
    bool IsOpen() const {
        if (!AuthorityComplete() || modelPath.empty()) return false;
        if (Eng().isModelLoaded()) return true;
        return auth.geom.LAYERS > 0 || graphNodes > 0;
    }

    bool reloadModel(const char* path) {
        if (alreadyGenerating.load()) return false;
        CloseSession();
        return OpenSession(path);
    }

    bool CancelGeneration() noexcept {
        if (!IsOpen() && !alreadyGenerating.load()) return false;
        control.RequestCancel();
        Eng().requestCancel();
        return true;
    }
};

inline ProductRuntime& SharedProductRuntime() {
    static ProductRuntime rt;
    return rt;
}
} // namespace rawr::product_run
