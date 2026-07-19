// ============================================================================
// test_moe_probe_only.cpp — Simple PrometheusMoE Probe Test
// ============================================================================

#include "inference/PrometheusMoE.h"
#include <iostream>
#include <fstream>
#include <cstdint>

using namespace RawrXD::Inference;

int main(int argc, char* argv[]) {
    std::cout << "============================================================" << std::endl;
    std::cout << "  PrometheusMoE Probe Test" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    std::string modelPath;
    if (argc > 1) {
        modelPath = argv[1];
    } else {
        std::cerr << "Usage: " << argv[0] << " <path_to_gguf>" << std::endl;
        return 1;
    }

    std::cout << "Testing file: " << modelPath << std::endl;
    std::cout << std::endl;

    // First, let's manually check the GGUF header
    std::cout << "[Manual GGUF Check]" << std::endl;
    std::ifstream file(modelPath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Cannot open file!" << std::endl;
        return 1;
    }

    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != 0x46554747) {
        std::cerr << "[ERROR] Invalid GGUF magic: 0x" << std::hex << magic << std::dec << std::endl;
        return 1;
    }
    std::cout << "  Magic: GGUF (valid)" << std::endl;

    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version), 4);
    std::cout << "  Version: " << version << std::endl;

    uint64_t tensorCount = 0, metadataCount = 0;
    file.read(reinterpret_cast<char*>(&tensorCount), 8);
    file.read(reinterpret_cast<char*>(&metadataCount), 8);
    std::cout << "  Tensor count: " << tensorCount << std::endl;
    std::cout << "  Metadata count: " << metadataCount << std::endl;
    std::cout << std::endl;

    file.close();

    // Now test PrometheusMoE::Probe
    std::cout << "[PrometheusMoE::Probe]" << std::endl;
    
    MoEConfig config = PrometheusMoE::Probe(modelPath);
    
    std::cout << "  isMoE: " << (config.isMoE ? "true" : "false") << std::endl;
    std::cout << "  numLayers: " << config.numLayers << std::endl;
    std::cout << "  numExperts: " << config.numExperts << std::endl;
    std::cout << "  expertsPerToken: " << config.expertsPerToken << std::endl;
    std::cout << "  numSharedExperts: " << config.numSharedExperts << std::endl;
    std::cout << "  hiddenDim: " << config.hiddenDim << std::endl;
    std::cout << "  intermediateDim: " << config.intermediateDim << std::endl;
    std::cout << "  numHeads: " << config.numHeads << std::endl;
    std::cout << "  numKVHeads: " << config.numKVHeads << std::endl;
    std::cout << "  headDim: " << config.headDim << std::endl;
    std::cout << "  vocabSize: " << config.vocabSize << std::endl;
    std::cout << "  topK: " << config.topK << std::endl;
    std::cout << std::endl;

    if (config.IsValid()) {
        std::cout << "[RESULT] Valid MoE configuration detected!" << std::endl;
        std::cout << "  Total params: " << config.totalParams << std::endl;
        std::cout << "  Active params: " << config.activeParams << std::endl;
        std::cout << "  Model size: " << config.modelSizeBytes << " bytes" << std::endl;
        std::cout << "  KV cache: " << config.kvCacheBytes << " bytes" << std::endl;
    } else {
        std::cout << "[RESULT] Not a valid MoE model (or missing MoE metadata)" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "  Test Complete" << std::endl;
    std::cout << "============================================================" << std::endl;

    return 0;
}
