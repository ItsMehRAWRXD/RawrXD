#pragma once
/* ProductRuntime — session owner; OpenSession requires AuthorityBundle. <=99. */
#include "../RawrRunSession.hpp"
#include "LocalModelAuthority_Bundle.hpp"
#include "ProductOpenStreamable.hpp"
#include "ProductReceipt.hpp"
#include "ProductRequest.hpp"
#include "SessionControl.hpp"
#include "RxRunStateHooks.hpp"
#include <atomic>
#include <cstdio>
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
        /* Prefer live session authority — nullptr path must not force reload. */
        if (e && e->sessionAuthorityPass()) {
            auth = e->sessionAuthority();
        } else if (path && path[0]) {
            (void)rawr::olma::SealAuthorityBundle(path, auth);
        } else if (alias && alias[0]) {
            (void)rawr::olma::SealAuthorityBundle(alias, auth);
        }
        (void)BuildExecutionGraph();
    }

    bool OpenSession(const char* aliasOrPath) {
        if (!aliasOrPath || !aliasOrPath[0]) return false;
        ext = nullptr;
        auth = {};
        control.Clear();
        if (engine.isModelLoaded()) engine.unloadModel();
        Deep2::rawr_run::RunWitness w{};
        if (!Deep2::rawr_run::OpenSession(engine, aliasOrPath, w)) {
            rxow::OnOpenFailed("RAW_RUN_OPEN_FAIL");
            return false;
        }
        modelAlias = w.modelName.empty() ? aliasOrPath : w.modelName;
        modelPath = w.modelPath;
        /* OPEN = indexed + storage reachable + bounded working set. */
        const auto& mw = engine.getModelWeights();
        if (!Deep2::product_open::StreamableOk(engine, modelPath.c_str(), stderr)) {
            rxow::OnOpenFailed("NOT_STREAMABLE");
            engine.unloadModel();
            modelPath.clear();
            return false;
        }
        // Prefer load-time seal (handles shard dirs); path re-seal is fallback only.
        if (engine.sessionAuthorityPass()) {
            auth = engine.sessionAuthority();
        } else if (!rawr::olma::SealAuthorityBundle(modelPath.c_str(), auth) ||
                   !auth.PASS) {
            rxow::OnOpenFailed("AUTHORITY_SEAL_FAIL");
            engine.unloadModel();
            modelPath.clear();
            return false;
        }
        const uint32_t layers = static_cast<uint32_t>(mw.numLayers);
        const uint32_t tensors =
            static_cast<uint32_t>((mw.tokenEmbed.data ? 1u : 0u) +
                                  (mw.lmHead.data ? 1u : 0u) +
                                  (mw.finalNorm.data ? 1u : 0u) +
                                  mw.layers.size());
        rxow::OnArmed(layers, tensors);
        if (!BuildExecutionGraph()) {
            rxow::OnPrepared(0, layers, tensors);
            return false;
        }
        rxow::OnPrepared(graphNodes, layers, tensors);
        return true;
    }

    void CloseSession() {
        /* Always clear generate latch — sticky alreadyGenerating=1 made
         * CloseSession a no-op and poisoned multi-GGUF reload_gen. */
        alreadyGenerating.store(0);
        control.Clear();
        if (ext) {
            ext = nullptr;
            graphNodes = 0;
            auth = {};
            modelPath.clear();
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
