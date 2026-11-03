#include "cpu_inference_engine.h"
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: qwen_cpu_probe <model.gguf> [token]\n";
        return 2;
    }
    const int32_t token = argc >= 3 ? static_cast<int32_t>(std::stol(argv[2])) : 1;
    RawrXD::CPUInferenceEngine engine;
    std::cout << "LOAD_BEGIN\n" << std::flush;
    if (!engine.LoadModel(argv[1])) {
        std::cout << "LOAD_FAIL\n";
        return 3;
    }
    std::cout << "LOAD_OK vocab=" << engine.GetVocabSize()
              << " dim=" << engine.GetEmbeddingDim()
              << " layers=" << engine.GetNumLayers()
              << " heads=" << engine.GetNumHeads() << "\n" << std::flush;
    std::cout << "EVAL_BEGIN\n" << std::flush;
    const auto logits = engine.Eval({token});
    if (logits.empty()) {
        std::cout << "EVAL_FAIL empty\n";
        return 4;
    }
    size_t finite = 0;
    size_t best = 0;
    float maxv = -std::numeric_limits<float>::infinity();
    for (size_t i = 0; i < logits.size(); ++i) {
        if (std::isfinite(logits[i])) ++finite;
        if (logits[i] > maxv) { maxv = logits[i]; best = i; }
    }
    std::cout << "EVAL_OK logits=" << logits.size()
              << " finite=" << finite
              << " best=" << best
              << " max=" << maxv
              << " memory=" << engine.GetMemoryUsage() << "\n";
    return finite == logits.size() ? 0 : 5;
}
