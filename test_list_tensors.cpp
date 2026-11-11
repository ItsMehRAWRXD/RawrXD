#include "deep2/GGUFLoader.hpp"
#include <iostream>

int main() {
    std::cout << "[TEST] List all tensors\n";
    
    Deep2::GGUFLoader loader;
    ::GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = true;
    opts.mmap = true;
    
    auto result = loader.Load("F:\\rawrxd\\nemotron-bolt.gguf", opts);
    if (!result.success) {
        std::cerr << "FAIL: " << result.error << "\n";
        return 1;
    }
    
    auto tensorNames = loader.listTensors();
    for (const auto& name : tensorNames) {
        const auto* t = loader.getTensor(name.c_str());
        if (t) {
            std::cout << name << " type=" << static_cast<int>(t->type) 
                      << " shape=["; 
            for (size_t i = 0; i < t->shape.size(); ++i) {
                if (i > 0) std::cout << ",";
                std::cout << t->shape[i];
            }
            std::cout << "] size=" << t->sizeBytes << "\n";
        }
    }
    
    return 0;
}