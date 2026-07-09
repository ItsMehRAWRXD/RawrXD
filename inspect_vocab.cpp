// Inspect vocabulary
#include "src/model/model_context.h"
#include <iostream>
#include <iomanip>

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
    
    const auto& vocab = model->GetVocabulary();
    std::cout << "Vocabulary size: " << vocab.size() << "\n\n";
    
    std::cout << "First 20 tokens:\n";
    for (size_t i = 0; i < std::min(vocab.size(), size_t(20)); ++i) {
        std::cout << "  [" << std::setw(5) << i << "] = \"";
        for (char c : vocab[i]) {
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                          << (static_cast<unsigned char>(c) & 0xFF) << std::dec << std::setfill(' ');
            } else {
                std::cout << c;
            }
        }
        std::cout << "\" (len=" << vocab[i].size() << ")\n";
    }
    
    // Look for space-related tokens
    std::cout << "\nSearching for space-related tokens...\n";
    for (size_t i = 0; i < vocab.size() && i < 1000; ++i) {
        if (vocab[i] == " " || vocab[i] == "▁" || vocab[i].find(' ') != std::string::npos) {
            std::cout << "  [" << i << "] = \"" << vocab[i] << "\"\n";
        }
    }
    
    return 0;
}
