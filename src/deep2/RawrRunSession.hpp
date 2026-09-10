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

inline bool InitFromPath(Deep2Engine& e, const std::string& path,
                         size_t maxSeq = 512) {
    std::fprintf(stderr, "PRODUCT_OPEN INIT_ENTER path=\"%s\"\n", path.c_str());
    std::fflush(stderr);
    long long rc = 0;
    if (!e.loadModel(path)) {
        rc = -1;
        std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=%lld reason=LOAD_MODEL\n",
                     rc);
        std::fflush(stderr);
        return false;
    }
    /* loadModel already arms ThreadPool/KV/buffers. A second initialize()
     * tear-down/rebuild has caused heap C0000374 (SOLO). Skip when live.
     * Still arm enhancement/Vulkan stack — loadModel alone leaves GPU cold. */
    if (e.isInitialized() && e.isModelLoaded()) {
        e.enableAllEnhancements();
        const char* host = std::getenv("RAWRXD_HOST_DECODE");
        const char* min = std::getenv("DEEP2_MINIMAL_ENHANCE");
        const char* sem = std::getenv("RAWRXD_SEMANTIC_SAFE");
        const bool cpuOpt = (host && host[0] == '1') || (min && min[0] == '1') ||
                            (sem && sem[0] == '1');
        if (!cpuOpt && !e.isVulkanEnabled()) {
            fprintf(stderr,
                    "INIT_FROM_PATH=FAIL reason=GPU_REQUIRED vulkan=0 "
                    "(RAWRXD_HOST_DECODE=1 for CPU opt-in)\n");
            e.unloadModel();
            rc = -2;
            std::fprintf(stderr,
                         "PRODUCT_OPEN INIT_EXIT rc=%lld reason=GPU_REQUIRED\n",
                         rc);
            std::fflush(stderr);
            return false;
        }
        if (maxSeq > 0 && e.getConfig().maxSeqLen != maxSeq) {
            fprintf(stderr, "INIT_FROM_PATH=LOAD_ONLY maxSeq_req=%zu live=%zu\n",
                    maxSeq, e.getConfig().maxSeqLen);
        }
        rc = e.isModelLoaded() ? 1 : 0;
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
    rc = ok ? 1 : -3;
    std::fprintf(stderr, "PRODUCT_OPEN INIT_EXIT rc=%lld reason=%s\n", rc,
                 ok ? "INITIALIZE_OK" : "INITIALIZE_FAIL");
    std::fflush(stderr);
    return ok;
}

inline bool OpenSession(Deep2Engine& e, const char* alias, RunWitness& w) {
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
