// RawrRunSession.hpp — Deep2 front-door session (load → stream → unload)
#pragma once
#include "Deep2Engine.h"
#include "ChatTemplate.hpp"
#include "RawrModelAlias.hpp"
#include "SemanticSafe.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace Deep2 {
namespace rawr_run {

struct RunWitness {
    int modelAliasResolved = 0;
    int ollamaProcessUsed = 0;
    int networkUsed = 0;
    int ggufOpened = 0;
    int shardsDiscovered = 0;
    int tokenizerReady = 0;
    int chatTemplateReady = 0;
    int chatTemplateApplied = 0;
    int deep2GenerateStream = 0;
    int firstTokenEmitted = 0;
    uint32_t nTokensEmitted = 0;
    int ctrlCCancel = 0;
    int unloadReload = 0;
    int processAliveAfterRun = 1;
    int secondRunPass = 0;
    int deep2Used = 0;
    int vwaUsed = 0;
    int elasticUsed = 0;
    std::string modelName;
    std::string modelPath;
    std::string formattedPrompt;
};

#if defined(RAWR_RUN_SESSION_DECLS_ONLY) || defined(RAWR_PRODUCT_RUNTIME_OPEN_MIN)
/* Decls only — bodies in RawrRunSession_Body.cpp (noforce ODR).
 * Prefer RAWR_RUN_SESSION_DECLS_ONLY so Deep2Engine.h MIN accessors stay inline. */
bool InitFromPath(Deep2Engine& e, const std::string& path, size_t maxSeq = 512);
bool OpenSession(Deep2Engine& e, const char* alias, RunWitness& w);
#else
#ifndef RAWR_RUN_INIT_NAME
#define RAWR_RUN_INIT_NAME InitFromPath
#endif
#ifndef RAWR_RUN_OPEN_NAME
#define RAWR_RUN_OPEN_NAME OpenSession
#endif

inline bool RAWR_RUN_INIT_NAME(Deep2Engine& e, const std::string& path,
                         size_t maxSeq = 512) {
    /* Tip 6754 shape: INIT_ENTER → loadModel → initialize (no vulkan prearm). */
    std::fprintf(stderr, "PRODUCT_OPEN INIT_ENTER path=\"%s\"\n", path.c_str());
    std::fflush(stderr);
    if (!e.loadModel(path)) {
        std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=-1 reason=LOAD_MODEL\n");
        std::fflush(stderr);
        return false;
    }
    if (e.isInitialized() && e.isModelLoaded()) {
        e.enableAllEnhancements();
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
    cfg.maxSeqLen = maxSeq;
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

inline bool RAWR_RUN_OPEN_NAME(Deep2Engine& e, const char* alias, RunWitness& w) {
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
    if (!RAWR_RUN_INIT_NAME(e, ar.path)) {
        std::fprintf(stderr, "RAW_RUN_OPEN=FAIL stage=INIT_FROM_PATH path=%s\n",
                     ar.path.c_str());
        std::fprintf(stderr,
                     "PRODUCT_OPEN SESSION_EXIT ok=0 stage=INIT_FROM_PATH\n");
        std::fflush(stderr);
        return false;
    }
    w.ggufOpened = e.isModelLoaded() ? 1 : 0;
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
#endif /* RAWR_RUN_SESSION_DECLS_ONLY || RAWR_PRODUCT_RUNTIME_OPEN_MIN */

inline std::string FormatChatPrompt(Deep2Engine& e, const std::string& user,
                                    RunWitness* w) {
    ChatTemplate chatTmpl;
    const ModelMetadata& meta = e.getModelMetadata();
    const char* alias = w ? w->modelName.c_str() : "";
    chatTmpl.initFromMetadata(meta.architecture, alias, meta.chatTemplate,
                              meta.bosToken, meta.eosToken);
    if (w) w->chatTemplateReady = 1;
    std::vector<ChatMessage> messages;
    messages.push_back({"user", user, ""});
    std::string formatted = chatTmpl.format(messages);
    if (w) {
        w->chatTemplateApplied = !formatted.empty() ? 1 : 0;
        w->formattedPrompt = formatted;
    }
    return formatted.empty() ? user : formatted;
}

inline uint32_t StreamTokens(Deep2Engine& e, const std::string& prompt,
                             uint32_t maxTokens, uint32_t cancelAfter,
                             RunWitness* w, bool applyChat = true) {
    GenerationOptions opts{};
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 42;
    e.clearCancel();
    // Witness template metadata only; generateStream applies the template once.
    if (applyChat)
        (void)FormatChatPrompt(e, prompt, w);
    uint32_t n = 0;
    e.generateStream(prompt, opts,
                     [&](int32_t, const std::string&) -> bool {
                         ++n;
                         if (w && n == 1) w->firstTokenEmitted = 1;
                         if (cancelAfter && n >= cancelAfter) {
                             e.requestCancel();
                             if (w) w->ctrlCCancel = 1;
                             return false;
                         }
                         return true;
                     });
    if (w) {
        w->deep2GenerateStream = 1;
        w->deep2Used = 1;
        w->nTokensEmitted = n;
    }
    return n;
}

} // namespace rawr_run
} // namespace Deep2
