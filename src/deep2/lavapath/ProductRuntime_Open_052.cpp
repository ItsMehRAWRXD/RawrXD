/* ProductRuntime_Open — OpenSession + CloseSession (single strong defs). <=99. */
#include "ProductRuntime.hpp"
#include <cstdlib>

namespace rawr::product_run {

bool ProductRuntime::OpenSession(const char* aliasOrPath) {
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
    const auto& mw = engine.getModelWeights();
    /* Never StreamableOk after load — stale FORCE AcquireWorkingSet SEHs. */
    if (!engine.isModelLoaded()) {
        rxow::OnOpenFailed("NOT_LOADED_AFTER_OPEN");
        modelPath.clear();
        return false;
    }
    {
        const char* hd = std::getenv("RAWRXD_HOST_DECODE");
        const char* fg = std::getenv("RAWR_FORCE_GPU");
        const char* ag = std::getenv("RAWRXD_ALLOW_GPU");
        const bool gpuPath = (hd && hd[0] == '0') || (fg && fg[0] == '1') ||
                             (ag && ag[0] == '1');
        if (gpuPath) {
            std::fprintf(stderr, "OPEN_SKIP_STREAMABLE_OK=GPU_PATH\n");
        } else {
            std::fprintf(stderr, "OPEN_SKIP_STREAMABLE_OK=LOADED\n");
        }
        std::fflush(stderr);
    }
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
    const uint32_t tensors = static_cast<uint32_t>(
        ((mw.tokenEmbed.data || mw.tokenEmbed.hasFileBacking) ? 1u : 0u) +
        ((mw.lmHead.data || mw.lmHead.hasFileBacking) ? 1u : 0u) +
        ((mw.finalNorm.data || mw.finalNorm.hasFileBacking) ? 1u : 0u) +
        mw.layers.size());
    rxow::OnArmed(layers, tensors);
    if (!BuildExecutionGraph()) {
        rxow::OnPrepared(0, layers, tensors);
        return false;
    }
    const uint32_t sbLayers = graphNodes ? graphNodes : layers;
    (void)Deep2::scoreboard::BindProductOpen(modelPath.c_str(), sbLayers);
    rxow::OnPrepared(graphNodes, layers, tensors);
    return true;
}

void ProductRuntime::CloseSession() {
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

} // namespace rawr::product_run