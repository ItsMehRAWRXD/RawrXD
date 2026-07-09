// Simple test for streaming loader
#include "streaming_gguf_loader.hpp"
#include <iostream>

using namespace RawrXD::Runtime;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: test_loader_simple <gguf_file>" << std::endl;
        return 1;
    }
    
    std::string filepath = argv[1];
    
    std::cout << "Opening: " << filepath << std::endl;
    
    StreamingGGUFLoader loader;
    if (!loader.Open(filepath)) {
        std::cerr << "Failed to open" << std::endl;
        return 1;
    }
    
    std::cout << "Opened successfully!" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    std::cout << "  Metadata: " << loader.GetMetadataCount() << std::endl;
    std::cout << "  File size: " << loader.GetFileSize() << std::endl;
    std::cout << "  Data offset: " << loader.GetTensorDataOffset() << std::endl;
    
    // Try to read first tensor
    std::cout << "\nReading first tensor..." << std::endl;
    TensorInfo info;
    if (loader.NextTensor(info)) {
        std::cout << "  Name: " << info.name << std::endl;
        std::cout << "  Shape: [";
        for (size_t i = 0; i < info.shape.size(); i++) {
            if (i > 0) std::cout << ", ";
            std::cout << info.shape[i];
        }
        std::cout << "]" << std::endl;
        std::cout << "  Type: " << info.type << std::endl;
        std::cout << "  Size: " << info.size << std::endl;
    } else {
        std::cerr << "Failed to read first tensor" << std::endl;
    }
    
    return 0;
}
