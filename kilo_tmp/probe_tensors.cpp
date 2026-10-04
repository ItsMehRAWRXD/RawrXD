#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include "deep2/GGUFLoader.hpp"

int main() {
    std::string path = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::cerr << "Failed to load: " << loader.error() << std::endl;
        return 1;
    }
    
    std::cout << "Architecture: " << loader.getMetaString("general.architecture") << std::endl;
    std::cout << "Tensor count: " << loader.tensorCount() << std::endl;
    
    auto tensors = loader.listTensors();
    for (const auto& name : tensors) {
        const auto* t = loader.getTensor(name);
        if (t) {
            if (name.find("attn_k") != std::string::npos || 
                name.find("attn_v") != std::string::npos ||
                name.find("attn_q") != std::string::npos ||
                name.find("attn_output") != std::string::npos) {
                std::cout << "  " << name << " type=" << (int)t->type << " shape=[" 
                          << t->shape[0] << "," << t->shape[1] << "]" << std::endl;
            }
        }
    }
    return 0;
}