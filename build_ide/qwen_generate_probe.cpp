#include "cpu_inference_engine.h"
#include <cmath>
#include <cstdint>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    const int32_t seed = argc > 2 ? static_cast<int32_t>(std::stol(argv[2])) : 1;
    const int max_tokens = argc > 3 ? std::stoi(argv[3]) : 4;
    RawrXD::CPUInferenceEngine engine;
    if (!engine.LoadModel(argv[1])) {
        std::cout << "LOAD_FAIL\n";
        return 3;
    }
    size_t emitted = 0;
    engine.GenerateStreaming({seed}, max_tokens,
        [&](const std::string&) { ++emitted; },
        [&]() {},
        [&](int32_t) {});
    std::cout << "GENERATE_OK emitted=" << emitted
              << " memory=" << engine.GetMemoryUsage() << "\n";
    return emitted > 0 ? 0 : 4;
}
