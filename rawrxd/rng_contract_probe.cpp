#include "src/deep2/Deep2Engine.h"
#include <cstdio>
int main() {
    Deep2::Deep2Engine e;

    Deep2::GenerationOptions go{};
    go.temperature = 0.8f;
    go.topK = 40;
    go.seed = 0;
    e.configureGeneration(go);
    std::printf("seed0=%llu greedy=%d\n", (unsigned long long)e.effectiveGenerationSeed(), e.isDeterministicGreedy());

    Deep2::GenerationOptions go2 = go;
    go2.seed = 42;
    e.configureGeneration(go2);
    std::printf("seed42=%llu greedy=%d\n", (unsigned long long)e.effectiveGenerationSeed(), e.isDeterministicGreedy());

    Deep2::GenerationOptions go3{};
    go3.temperature = 0.0f;
    go3.topK = 1;
    go3.seed = 42;
    e.configureGeneration(go3);
    std::printf("greedy_seed42=%llu greedy=%d\n", (unsigned long long)e.effectiveGenerationSeed(), e.isDeterministicGreedy());
    return 0;
}
