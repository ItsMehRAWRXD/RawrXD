#include "Deep2Engine.h"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: mars_vulkan_coexistence_test <model.gguf>\n");
        return 2;
    }

    Deep2::Deep2Engine engine;
    if (!engine.loadModel(argv[1])) {
        std::fprintf(stderr, "MARS_TEST=FAIL loadModel\n");
        return 3;
    }

    const auto& weights = engine.getModelWeights();
    Deep2::EngineConfig cfg{};
    cfg.hiddenDim = weights.hiddenDim;
    cfg.numLayers = weights.numLayers;
    cfg.numHeads = weights.numHeads;
    cfg.numKVHeads = weights.numKVHeads;
    cfg.headDim = weights.headDim;
    cfg.vocabSize = weights.vocabSize;
    cfg.maxSeqLen = 1024;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 4;

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "MARS_TEST=FAIL initialize\n");
        return 4;
    }
    engine.enableAllEnhancements();

    const bool vk = engine.isVulkanEnabled();
    const bool mars = engine.isMARSEnabled();
    auto placement = engine.placeAllModelTensorsMARS();
    const bool placementRejected = placement.placed == 0 && placement.oom == 0;

    std::printf("MARS_TEST_VULKAN=%d\n", vk ? 1 : 0);
    std::printf("MARS_TEST_ACTIVE=%d\n", mars ? 1 : 0);
    std::printf("MARS_TEST_PLACEMENT_REJECTED=%d\n", placementRejected ? 1 : 0);
    std::printf("MARS_TEST_RESULT=%s\n", (vk && mars && placementRejected) ? "PASS" : "FAIL");
    return (vk && mars && placementRejected) ? 0 : 5;
}
