// Check model architecture
#include "src/model/model_context.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>\n";
        return 1;
    }
    
    auto model = rawrxd::model::ModelContextFactory::FromGGUF(argv[1]);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    std::cout << "Architecture:\n";
    auto arch = model->GetArchitecture();
    std::cout << "  Type: " << arch.type << "\n";
    std::cout << "  Vocab size: " << arch.vocab_size << "\n";
    
    return 0;
}
