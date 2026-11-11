// Quick tokenizer round-trip test
#include "src/runtime/tokenizer_runtime.h"
#include "src/model/model_context.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> [text]\n";
        return 1;
    }
    
    std::string model_path = argv[1];
    std::string text = (argc > 2) ? argv[2] : "Hello world";
    
    std::cout << "Loading model: " << model_path << "\n";
    auto model = rawrxd::model::ModelContextFactory::FromGGUF(model_path);
    
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    std::cout << "Vocab size: " << model->GetVocabulary().size() << "\n";
    std::cout << "Has vocab: " << (model->HasVocabulary() ? "yes" : "no") << "\n\n";
    
    // Create tokenizer
    auto tokenizer = rawrxd::runtime::TokenizerFactory::FromModel(*model);
    if (!tokenizer) {
        std::cerr << "Failed to create tokenizer\n";
        return 1;
    }
    
    std::cout << "Original: \"" << text << "\"\n\n";
    
    // Encode
    auto tokens = tokenizer->Encode(text);
    std::cout << "Tokens (" << tokens.size() << "): [";
    for (size_t i = 0; i < tokens.size() && i < 20; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    if (tokens.size() > 20) std::cout << "...";
    std::cout << "]\n\n";
    
    // Show token strings
    std::cout << "Token strings:\n";
    for (size_t i = 0; i < tokens.size() && i < 10; ++i) {
        auto token_str = tokenizer->IdToToken(tokens[i]);
        std::cout << "  [" << tokens[i] << "] = \"";
        for (char c : token_str) {
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                std::cout << "\\x" << std::hex << (static_cast<unsigned char>(c) & 0xFF) << std::dec;
            } else {
                std::cout << c;
            }
        }
        std::cout << "\"\n";
    }
    std::cout << "\n";
    
    // Decode
    auto decoded = tokenizer->Decode(tokens);
    std::cout << "Decoded: \"" << decoded << "\"\n\n";
    
    // Check round-trip
    if (decoded == text) {
        std::cout << "✓ Round-trip SUCCESS\n";
        return 0;
    } else {
        std::cout << "✗ Round-trip FAILED\n";
        std::cout << "  Expected: \"" << text << "\"\n";
        std::cout << "  Got:      \"" << decoded << "\"\n";
        return 1;
    }
}
