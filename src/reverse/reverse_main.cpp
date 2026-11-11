/**
 * @file reverse_main.cpp
 * @brief Reverse compatibility harness entry point
 *
 * Usage:
 *   reverse_main --probe-tensor
 *   reverse_main --compare-logits <ref.bin> <rxd.bin>
 *   reverse_main --probe-gguf <model.gguf>
 *   reverse_main --probe-block <layer> <model.gguf>
 */

#include "ComponentProbe.hpp"
#include <iostream>
#include <cstring>
#include <cstdlib>

static void PrintUsage() {
    std::cout << "RawrXD Reverse Compatibility Harness\n"
              << "Usage:\n"
              << "  reverse_main --probe-tensor              Run tensor probe self-test\n"
              << "  reverse_main --compare-logits <ref> <rxd> Compare two logit files\n"
              << "  reverse_main --probe-gguf <path>          Probe GGUF model metadata\n"
              << "  reverse_main --probe-block <layer> <path>  Execute one transformer block\n"
              << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    using namespace RawrXD::Reverse;

    if (std::strcmp(argv[1], "--probe-tensor") == 0) {
        // Self-test: create a tensor and probe it
        std::vector<float> data(1024);
        for (size_t i = 0; i < 1024; ++i) data[i] = static_cast<float>(i) / 1024.0f;

        RawrXD::TensorView tv{data.data(), data.size(), 1, {32, 32}};
        auto info = TensorProbe::Probe(tv, "self-test");
        TensorProbe::PrintReport(info);
        return 0;
    }

    if (std::strcmp(argv[1], "--compare-logits") == 0) {
        if (argc < 4) { std::cerr << "Need ref and rxd paths" << std::endl; return 1; }
        // Stub: load binary files and compare
        std::cout << "[compare-logits] stub — will compare " << argv[2] << " vs " << argv[3] << std::endl;
        return 0;
    }

    if (std::strcmp(argv[1], "--probe-gguf") == 0) {
        if (argc < 3) { std::cerr << "Need GGUF path" << std::endl; return 1; }
        auto info = GGUFProbe::ProbeFile(argv[2]);
        return 0;
    }

    if (std::strcmp(argv[1], "--probe-block") == 0) {
        if (argc < 4) { std::cerr << "Need layer and GGUF path" << std::endl; return 1; }
        uint32_t layer = static_cast<uint32_t>(std::atoi(argv[2]));
        std::vector<float> dummy(4096);
        RawrXD::TensorView input{dummy.data(), dummy.size(), 1, {1, 4096}};
        auto t = TransformerBlockProbe::ExecuteBlock(layer, input);
        return 0;
    }

    PrintUsage();
    return 1;
}
