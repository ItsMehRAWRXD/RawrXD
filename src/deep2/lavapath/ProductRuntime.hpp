#pragma once
/* ProductRuntime — session owner; OpenSession requires AuthorityBundle. <=99. */
#include "../RawrRunSession.hpp"
#include "LocalModelAuthority_Bundle.hpp"
#include "ProductReceipt.hpp"
#include "ProductRequest.hpp"
#include "SessionControl.hpp"
#include <atomic>
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

    Deep2::Deep2Engine& Eng() { return ext ? *ext : engine; }
    const Deep2::Deep2Engine& Eng() const { return ext ? *ext : engine; }
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
        if (path && path[0]) (void)rawr::olma::SealAuthorityBundle(path, auth);
        (void)BuildExecutionGraph();
    }

    bool OpenSession(const char* aliasOrPath) {
        if (!aliasOrPath || !aliasOrPath[0]) return false;
        ext = nullptr;
        auth = {};
        control.Clear();
        if (engine.isModelLoaded()) engine.unloadModel();
        Deep2::rawr_run::RunWitness w{};
        if (!Deep2::rawr_run::OpenSession(engine, aliasOrPath, w)) return false;
        modelAlias = w.modelName.empty() ? aliasOrPath : w.modelName;
        modelPath = w.modelPath;
        // Prefer load-time seal (handles shard dirs); path re-seal is fallback only.
        if (engine.sessionAuthorityPass()) {
            auth = engine.sessionAuthority();
        } else if (!rawr::olma::SealAuthorityBundle(modelPath.c_str(), auth) ||
                   !auth.PASS) {
            engine.unloadModel();
            modelPath.clear();
            return false;
        }
        return BuildExecutionGraph();
    }

    void CloseSession() {
        if (alreadyGenerating.load()) return;
        control.Clear();
        if (ext) {
            ext = nullptr;
            graphNodes = 0;
            auth = {};
            return;
        }
        if (engine.isModelLoaded()) engine.unloadModel();
        modelPath.clear();
        auth = {};
        graphNodes = 0;
    }

    bool IsOpen() const { return Eng().isModelLoaded() && AuthorityComplete(); }

    bool reloadModel(const char* path) {
        if (alreadyGenerating.load()) return false;
        CloseSession();
        return OpenSession(path);
    }

    /* Publish cancel only — no teardown/unload/Vulkan destroy. */
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
