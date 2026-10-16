#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantTypeTable.hpp"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: test_gguf_load <model.gguf>\n";
        return 1;
    }
    
    std::string modelPath = argv[1];
    std::cout << "[TEST] Loading model: " << modelPath << "\n";
    
    Deep2::GGUFLoader loader;
    ::GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = true;
    opts.mmap = true;
    
    auto result = loader.Load(modelPath.c_str(), opts);
    
    if (!result.success) {
        std::cerr << "FAIL: " << result.error << "\n";
        return 1;
    }
    
    std::cout << "PASS: Model loaded successfully\n";
    std::cout << "Architecture: " << result.metadata.architecture << "\n";
    std::cout << "Layers: " << result.metadata.numLayers << "\n";
    std::cout << "Hidden dim: " << result.metadata.hiddenSize << "\n";
    std::cout << "Tensors: " << result.tensors.size() << "\n";
    
    // Check for NVFP4 tensors
    int nvfp4Count = 0;
    int iq2xxsCount = 0;
    int q8_0Count = 0;
    int f32Count = 0;
    
    for (const auto& t : result.tensors) {
        if (t.type == 40) nvfp4Count++;
        else if (t.type == 16) iq2xxsCount++;
        else if (t.type == 8) q8_0Count++;
        else if (t.type == 0) f32Count++;
    }
    
    std::cout << "\nTensor type breakdown:\n";
    std::cout << "  NVFP4 (type 40): " << nvfp4Count << "\n";
    std::cout << "  IQ2_XXS (type 16): " << iq2xxsCount << "\n";
    std::cout << "  Q8_0 (type 8): " << q8_0Count << "\n";
    std::cout << "  F32 (type 0): " << f32Count << "\n";
    
    // Print first few tensors
    std::cout << "\nFirst 10 tensors:\n";
    for (size_t i = 0; i < std::min<size_t>(10, result.tensors.size()); ++i) {
        const auto& t = result.tensors[i];
        std::cout << "  " << t.name << " type=" << t.type 
                  << " shape=[";
        for (size_t j = 0; j < t.dimensions.size(); ++j) {
            if (j > 0) std::cout << ",";
            std::cout << t.dimensions[j];
        }
        std::cout << "] size=" << t.size << "\n";
    }
    
    std::cout << "\n[TEST] COMPLETE\n";
    return 0;
}