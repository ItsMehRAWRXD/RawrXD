// Deep2OuterEngineBridge.cpp — real Deep2Engine behind OuterEngineApi
#include "Deep2OuterRuntimeABI.h"
#include "Deep2Engine.h"
#include <cstdio>
#include <cstring>
#include <new>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

struct BridgeHandle {
    Deep2::Deep2Engine* eng = nullptr;
    uint32_t kind = OUT_KIND_K2;
    bool realEngine = true;
};

uint32_t g_lastGenTokens = 0;
uint32_t g_lastOutBytes = 0;
int32_t g_lastGenId = -1;
char g_lastText[512]{};
uint32_t g_openEntered = 0, g_genEntered = 0, g_closeEntered = 0;

uint32_t BridgeOpen(const char* dir, void** handle) {
    ++g_openEntered;
    if (!dir || !handle) return 0;
    *handle = nullptr;
    auto* h = new (std::nothrow) BridgeHandle();
    if (!h) return 0;
    h->eng = new (std::nothrow) Deep2::Deep2Engine();
    if (!h->eng) { delete h; return 0; }
    Deep2::EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (strstr(dir, "DeepSeek") || strstr(dir, "deepseek")) {
        h->kind = OUT_KIND_DEEPSEEK;
        cfg.numHeads = 128; cfg.numKVHeads = 128; cfg.vocabSize = 129280;
    } else {
        cfg.numHeads = 64; cfg.numKVHeads = 1; cfg.vocabSize = 163840;
    }
    if (!h->eng->initialize(cfg) || !h->eng->openK2ShardDirectory(dir)) {
        delete h->eng; delete h; return 0;
    }
    *handle = h;
    return 1;
}

uint32_t BridgeGenerate(void* handle, const char* prompt, uint32_t nTok) {
    ++g_genEntered;
    auto* h = static_cast<BridgeHandle*>(handle);
    if (!h || !h->eng || !h->realEngine) return 0;
    if (!prompt) prompt = "hello";
    if (nTok == 0) nTok = 1;
    K2NativeStreamGate::Config kc;
    kc.prompt = prompt; kc.streamTokens = nTok; kc.layerDepth = 4;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto r = h->eng->runK2NativeStreamPartial(kc);
    if (!r.ok || !r.outputNonempty || r.generatedTokenId < 0) {
        fprintf(stderr, "[BRIDGE_GEN_FAIL] ok=%d nonempty=%d id=%d err=%s\n",
                (int)r.ok, (int)r.outputNonempty, r.generatedTokenId, r.error.c_str());
        return 0;
    }
    g_lastGenTokens = nTok;
    g_lastGenId = r.generatedTokenId;
    g_lastOutBytes = (uint32_t)r.generatedText.size();
    std::snprintf(g_lastText, sizeof(g_lastText), "%s", r.generatedText.c_str());
    return 1;
}

void BridgeClose(void* handle) {
    ++g_closeEntered;
    auto* h = static_cast<BridgeHandle*>(handle);
    if (!h) return;
    delete h; // eng leaked — multi-shard dtor aborts
}

} // namespace

extern "C" Deep2OuterEngineApi Deep2Outer_ProductionEngineApi = {
    BridgeOpen, BridgeGenerate, BridgeClose
};
extern "C" uint32_t Deep2Outer_LastGenTokens() { return g_lastGenTokens; }
extern "C" uint32_t Deep2Outer_LastOutBytes() { return g_lastOutBytes; }
extern "C" int32_t Deep2Outer_LastGenId() { return g_lastGenId; }
extern "C" const char* Deep2Outer_LastText() { return g_lastText; }
extern "C" uint32_t Deep2Outer_OpenEntered() { return g_openEntered; }
extern "C" uint32_t Deep2Outer_GenEntered() { return g_genEntered; }
extern "C" uint32_t Deep2Outer_CloseEntered() { return g_closeEntered; }
