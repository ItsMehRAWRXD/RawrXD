// Test for Streaming GGUF Loader v2
#include "streaming_gguf_loader_v2.hpp"
#include <iostream>

using namespace RawrXD::Runtime;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: test_loader_v2 <gguf_file>" << std::endl;
        return 1;
    }

    std::string filepath = argv[1];

    std::cout << "=== Streaming GGUF Loader v2 Test ===" << std::endl;
    std::cout << "File: " << filepath << std::endl << std::endl;

    StreamingGGUFLoader loader;
    if (!loader.Open(filepath)) {
        std::cerr << "Failed to open GGUF file" << std::endl;
        return 1;
    }

    std::cout << "[PASS] File opened successfully!" << std::endl;
    std::cout << "  Tensors: " << loader.GetTensorCount() << std::endl;
    std::cout << "  Metadata: " << loader.GetMetadataCount() << std::endl;
    std::cout << "  File size: " << loader.GetFileSize() << " bytes" << std::endl;
    std::cout << "  Data offset: " << loader.GetTensorDataOffset() << std::endl;

    // List all tensors
    std::cout << "\n[Tensors]" << std::endl;
    auto names = loader.GetTensorNames();
    for (const auto& name : names) {
        TensorInfo info;
        if (loader.GetTensor(name, info)) {
            std::cout << "  " << info.name << std::endl;
            std::cout << "    Shape: [";
            for (size_t i = 0; i < info.shape.size(); i++) {
                if (i > 0) std::cout << ", ";
                std::cout << info.shape[i];
            }
            std::cout << "]" << std::endl;
            std::cout << "    Type: " << info.type << std::endl;
            std::cout << "    Size: " << info.size << " bytes" << std::endl;
            std::cout << "    Offset: 0x" << std::hex << info.offset << std::dec << std::endl;

            // Get data pointer
            const uint8_t* data = loader.GetTensorData(info);
            if (data) {
                std::cout << "    Data: available at " << (void*)data << std::endl;
            }
        }
    }

    std::cout << "\n[PASS] All tests completed!" << std::endl;
    return 0;
}
