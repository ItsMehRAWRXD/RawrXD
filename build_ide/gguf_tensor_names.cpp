#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: gguf_tensor_names <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto idx = loader.GetTensorIndex();
    std::cout << "Total tensors: " << idx.size() << "\n\n";
    
    // Show all tensor names
    for (size_t i = 0; i < idx.size(); ++i) {
        const auto& ref = idx[i];
        std::string shapeStr;
        for (size_t d = 0; d < ref.shape.size(); ++d) {
            if (d) shapeStr += "x";
            shapeStr += std::to_string(ref.shape[d]);
        }
        std::cout << "[" << std::setw(3) << i << "] " << std::left << std::setw(50) << ref.name
                  << " type=" << static_cast<uint32_t>(ref.type)
                  << " shape=[" << shapeStr << "]"
                  << " offset=" << ref.offset << " size=" << ref.size << "\n";
    }
    return 0;
}
