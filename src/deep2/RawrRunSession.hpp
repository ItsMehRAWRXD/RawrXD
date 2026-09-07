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
    if (!e.loadModel(path)) return false;
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
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    return e.initialize(cfg);
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
    const std::string usePrompt =
        applyChat ? FormatChatPrompt(e, prompt, w) : prompt;
    uint32_t n = 0;
    e.generateStream(usePrompt, opts,
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

inline bool OpenSession(Deep2Engine& e, const char* alias, RunWitness& w) {
    AliasResolve ar{};
    if (!ResolveModelAlias(alias, ar)) return false;
    w.modelAliasResolved = 1;
    w.modelName = ar.alias;
    w.modelPath = ar.path;
    w.shardsDiscovered = ar.shards > 0 ? 1 : 0;
    w.ollamaProcessUsed = 0;
    w.networkUsed = 0;
    if (!InitFromPath(e, ar.path)) return false;
    w.ggufOpened = e.isModelLoaded() ? 1 : 0;
    w.tokenizerReady = e.tokenize("hi").empty() ? 0 : 1;
    auto ct = ChatTemplate::detectFromModel(e.getModelMetadata().architecture,
                                            ar.alias.c_str());
    w.chatTemplateReady = (ct != ChatTemplateType::UNKNOWN) ? 1 : 0;
    if (e.getElasticResidencyManager()) w.elasticUsed = 1;
    return w.ggufOpened && w.tokenizerReady;
}

} // namespace rawr_run
} // namespace Deep2
