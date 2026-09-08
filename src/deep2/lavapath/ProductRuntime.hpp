#pragma once
#include "ProductRun.hpp"
#include <atomic>
#include <string>
namespace rawr::product_run {

struct ProductRuntime {
    Deep2::Deep2Engine engine;
    std::string modelAlias = "llama32";
    std::string modelPath;
    std::atomic<int> alreadyGenerating{0};
    uint32_t graphNodes = 0;
    int LOCAL_ONLY = 1;
    int NO_CLOUD = 1;

    bool BuildExecutionGraph() {
        graphNodes = 0;
        if (!engine.isModelLoaded()) return false;
        graphNodes = (uint32_t)engine.getModelMetadata().numLayers;
        if (!graphNodes) graphNodes = (uint32_t)engine.getConfig().numLayers;
        return graphNodes > 0;
    }

    bool reloadModel(const char* path) {
        if (!path || !path[0]) return false;
        if (alreadyGenerating.load()) return false;
        engine.unloadModel();
        modelPath = path;
        if (!engine.loadModel(path)) return false;
        return BuildExecutionGraph();
    }

    void CancelGeneration() { engine.requestCancel(); }

    Result generate(const char* prompt) {
        Result busy{};
        if (alreadyGenerating.exchange(1) != 0) {
            busy.failedStage = "BUSY";
            busy.failedOwner = "CONCURRENT";
            busy.exitReason = "BUSY";
            return busy;
        }
        Request req{};
        req.modelAlias = modelAlias.c_str();
        req.prompt = prompt;
        req.maxTokens = 256;
        req.engine = &engine;
        req.keepOpen = 1;
        Result r = ProductRun(req);
        alreadyGenerating.store(0);
        return r;
    }
};

} // namespace rawr::product_run
