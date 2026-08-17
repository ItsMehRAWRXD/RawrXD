#include "Tokenizer.hpp"

// Real tokenizer from ai_inference_real
#include "../ai/ai_inference_real.h"

#include <fstream>
#include <cstring>

namespace Deep2 {

//==============================================================================
// Tokenizer Implementation
//==============================================================================
class Tokenizer::Impl {
public:
    size_t vocabSize = 32000;
    bool loaded = false;

    bool LoadFromFile(const std::string& modelPath) {
        // Verify file exists and is a valid GGUF
        std::ifstream file(modelPath, std::ios::binary);
        if (!file) {
            return false;
        }

        uint32_t magic = 0;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (magic != 0x46554747) {  // 'GGUF'
            return false;
        }

        loaded = true;
        return true;
    }
};

Tokenizer::Tokenizer() : pImpl(std::make_unique<Impl>()) {}
Tokenizer::~Tokenizer() = default;

bool Tokenizer::LoadFromGGUF(const std::string& modelPath) {
    return pImpl->LoadFromFile(modelPath);
}

std::vector<int> Tokenizer::Encode(const std::string& text) {
    // Delegate to real MASM-accelerated tokenizer
    return RawrXD::TokenizeReal(text);
}

std::string Tokenizer::Decode(const std::vector<int>& tokens) {
    // Delegate to real detokenizer
    return RawrXD::DetokenizeReal(tokens);
}

size_t Tokenizer::GetVocabSize() const {
    return pImpl->vocabSize;
}

} // namespace Deep2
