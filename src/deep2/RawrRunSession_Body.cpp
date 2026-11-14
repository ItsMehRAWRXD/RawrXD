/* RawrRunSession_Body — strong OpenSession/InitFromPath (noforce ODR).
 * POST_LOAD_ROOTS_REPAIR → Eng.repairModelLoadedFromRoots (authPASS path). */
#define RAWR_RUN_SESSION_DECLS_ONLY 1
#include "RawrRunSession.hpp"

namespace Deep2 {
namespace rawr_run {

bool InitFromPath(Deep2Engine& e, const std::string& path, size_t maxSeq) {
    std::fprintf(stderr, "PRODUCT_OPEN INIT_ENTER path=\"%s\"\n", path.c_str());
    std::fflush(stderr);
    if (!e.loadModel(path)) {
        std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=-1 reason=LOAD_MODEL\n");
        std::fflush(stderr);
        return false;
    }
    if (e.isInitialized() && e.isModelLoaded()) {
        e.enableAllEnhancements();
        (void)e.repairModelLoadedFromRoots();
        const long long rc = e.isModelLoaded() ? 1 : 0;
        std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=%lld\n", rc);
        std::fflush(stderr);
        return rc == 1;
    }
    const auto& mw = e.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim;
    cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads;
    cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize;
    cfg.intermediateDim = mw.intermediateDim;
    /* Prefer loadModel geo.context over default maxSeq=512 — 512 left
     * CKV/stream working-set too small and ProductRun AV VA=0/-1 before ENTER. */
    cfg.maxSeqLen = e.getConfig().maxSeqLen > 0 ? e.getConfig().maxSeqLen : maxSeq;
    if (cfg.maxSeqLen < 2048) cfg.maxSeqLen = 2048;
    cfg.useMLA = mw.useMLA || e.getConfig().useMLA;
    cfg.qLoraRank = e.getConfig().qLoraRank;
    cfg.kvLoraRank = e.getConfig().kvLoraRank;
    cfg.qkNopeHeadDim = e.getConfig().qkNopeHeadDim;
    cfg.qkRopeHeadDim = e.getConfig().qkRopeHeadDim;
    cfg.vHeadDim = e.getConfig().vHeadDim;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    const bool ok = e.initialize(cfg);
    std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=%lld reason=%s\n",
                 ok ? 1LL : -3LL, ok ? "INITIALIZE_OK" : "INITIALIZE_FAIL");
    std::fflush(stderr);
    return ok;
}

bool OpenSession(Deep2Engine& e, const char* alias, RunWitness& w) {
    std::fprintf(stderr, "PRODUCT_OPEN SESSION_ENTER alias=\"%s\"\n",
                 alias ? alias : "");
    std::fflush(stderr);
    AliasResolve ar{};
    if (!ResolveModelAlias(alias, ar)) {
        std::fprintf(stderr, "RAW_RUN_OPEN=FAIL stage=ALIAS path=%s\n",
                     alias ? alias : "");
        std::fprintf(stderr, "PRODUCT_OPEN SESSION_EXIT ok=0 stage=ALIAS\n");
        std::fflush(stderr);
        return false;
    }
    w.modelAliasResolved = 1;
    w.modelName = ar.alias;
    w.modelPath = ar.path;
    w.shardsDiscovered = (int)ar.shards;
    w.ollamaProcessUsed = 0;
    w.networkUsed = 0;
    if (!InitFromPath(e, ar.path)) {
        std::fprintf(stderr, "RAW_RUN_OPEN=FAIL stage=INIT_FROM_PATH path=%s\n",
                     ar.path.c_str());
        std::fprintf(stderr,
                     "PRODUCT_OPEN SESSION_EXIT ok=0 stage=INIT_FROM_PATH\n");
        std::fflush(stderr);
        return false;
    }
    w.ggufOpened = e.isModelLoaded() ? 1 : 0;
    if (!w.ggufOpened && e.repairModelLoadedFromRoots()) {
        w.ggufOpened = 1;
        std::fprintf(stderr, "POST_LOAD_ROOTS_REPAIR=1 layers=%zu\n",
                     e.getModelWeights().numLayers);
        std::fflush(stderr);
    }
    w.tokenizerReady = e.tokenize("hi").empty() ? 0 : 1;
    auto ct = ChatTemplate::detectFromModel(e.getModelMetadata().architecture,
                                            ar.alias.c_str());
    w.chatTemplateReady = (ct != ChatTemplateType::UNKNOWN) ? 1 : 0;
    if (e.getElasticResidencyManager()) w.elasticUsed = 1;
    if (!(w.ggufOpened && w.tokenizerReady)) {
        std::fprintf(stderr,
                     "RAW_RUN_OPEN=FAIL stage=POST_LOAD gguf=%d tok=%d path=%s\n",
                     w.ggufOpened, w.tokenizerReady, ar.path.c_str());
        std::fprintf(stderr, "PRODUCT_OPEN SESSION_EXIT ok=0 stage=POST_LOAD\n");
        std::fflush(stderr);
        return false;
    }
    std::fprintf(stderr, "RAW_RUN_OPEN=OK path=%s gguf=1 tok=1\n",
                 ar.path.c_str());
    std::fprintf(stderr, "PRODUCT_OPEN SESSION_EXIT ok=1\n");
    std::fflush(stderr);
    return true;
}

} // namespace rawr_run
} // namespace Deep2
