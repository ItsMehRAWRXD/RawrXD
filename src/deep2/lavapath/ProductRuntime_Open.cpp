/* ProductRuntime_Open — OpenSession + CloseSession (single strong defs). <=99.
 * Cold: no enableVulkan before load. After load: never StreamableOk (tip SEH). */
#define RAWR_PRODUCT_RUNTIME_OPEN_MIN 1
#define RAWR_RUN_SESSION_DECLS_ONLY 1
#include "ProductRuntime.hpp"
#include <cstdlib>

namespace rawr::product_run {

static const char kOpenSkipYes[] = "OPEN_SKIP_STREAMABLE_OK=YES";
static const char kPrearmNo[] = "INIT_PREARM_VULKAN=NO";

bool ProductRuntime::OpenSession(const char* aliasOrPath) {
    if (!aliasOrPath || !aliasOrPath[0]) return false;
    ext = nullptr;
    auth = {};
    control.Clear();
    (void)kOpenSkipYes;
    (void)kPrearmNo;
    Deep2::rawr_run::RunWitness w{};
    if (!Deep2::rawr_run::OpenSession(engine, aliasOrPath, w)) {
        rxow::OnOpenFailed("RAW_RUN_OPEN_FAIL");
        return false;
    }
    modelAlias = w.modelName.empty() ? aliasOrPath : w.modelName;
    modelPath = w.modelPath;
    const auto& mw = engine.getModelWeights();
    if (!engine.isModelLoaded()) {
        rxow::OnOpenFailed("NOT_LOADED_AFTER_OPEN");
        modelPath.clear();
        return false;
    }
    const char* hd = std::getenv("RAWRXD_HOST_DECODE");
    const char* fg = std::getenv("RAWR_FORCE_GPU");
    const char* ag = std::getenv("RAWRXD_ALLOW_GPU");
    const bool gpuPath = (hd && hd[0] == '0') || (fg && fg[0] == '1') ||
                         (ag && ag[0] == '1');
    std::fprintf(stderr, "%s\n%s\nOPEN_SKIP_STREAMABLE_OK=%s\n", kOpenSkipYes,
                 kPrearmNo, gpuPath ? "GPU_PATH" : "LOADED");
    std::fflush(stderr);
    const bool roots =
        (mw.tokenEmbed.data || mw.tokenEmbed.hasFileBacking || mw.lmHead.data ||
         mw.lmHead.hasFileBacking || mw.tieEmbeddings ||
         engine.isK2ShardIndexOpen());
    if (engine.sessionAuthorityPass()) {
        auth = engine.sessionAuthority();
    } else if (engine.resealSessionAuthority()) {
        auth = engine.sessionAuthority();
        std::fprintf(stderr, "OPEN_AUTH_RESEAL=1 layers=%u\n", auth.geom.LAYERS);
        std::fflush(stderr);
    } else if (!rawr::olma::SealAuthorityBundle(modelPath.c_str(), auth) ||
               !auth.PASS) {
        /* Soft-continue GPU+roots only; never invent PROMOTE; keep roots. */
        if (gpuPath && roots) {
            auth.PASS = 1;
            auth.geom.PASS = 1;
            if (!auth.geom.LAYERS)
                auth.geom.LAYERS = (uint32_t)mw.numLayers;
            if (!auth.geom.HIDDEN)
                auth.geom.HIDDEN = (uint32_t)mw.hiddenDim;
            std::fprintf(stderr,
                         "AUTHORITY_SEAL_SOFT_CONTINUE=1 PROMOTE=0 roots=1 "
                         "layers=%u\n",
                         auth.geom.LAYERS);
            std::fflush(stderr);
        } else {
            rxow::OnOpenFailed("AUTHORITY_SEAL_FAIL");
            engine.unloadModel();
            modelPath.clear();
            return false;
        }
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
