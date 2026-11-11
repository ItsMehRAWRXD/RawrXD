#include "ReverseModelLoader.hpp"
#include "ReverseEngine.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <fstream>
#include <iostream>

static std::vector<uint8_t> ReadBinary(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Cannot open binary: " << path << "\n";
        std::exit(1);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: reverse_cli <model.json> <binary>\n";
        return 1;
    }

    auto model = rxd::reverse::ReverseModelLoader::LoadFromFile(argv[1]);
    auto data = ReadBinary(argv[2]);

    rxd::reverse::ReverseEngine engine(model);
    auto rc = engine.Reconstruct(data.data(), data.size());

    std::printf("Model: %s v%s\n", model.name.c_str(), model.version.c_str());
    std::printf("Loaded %zu patterns, %zu samples\n", model.patterns.size(), model.samples.size());
    std::printf("Binary size: %zu bytes\n", data.size());
    std::printf("Matches: %zu\n", rc.matches.size());
    std::printf("Overall confidence: %.4f\n", rc.overallConfidence);

    for (const auto& m : rc.matches) {
        std::printf("  [%04zX] %-20s len=%zu conf=%.4f\n", m.offset, m.patternId.c_str(), m.length, m.confidence);
    }

    return 0;
}
