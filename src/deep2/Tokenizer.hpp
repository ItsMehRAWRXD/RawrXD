#pragma once

//==============================================================================
// Tokenizer.hpp - Deep2 Tokenizer Wrapper
// Phase 15B: Real Executable Build
//
// Wraps the RawrXD tokenizer infrastructure for Deep2
//==============================================================================

#include <string>
#include <vector>
#include <memory>

namespace Deep2 {

//==============================================================================
// Tokenizer - Text tokenization for Deep2
//==============================================================================
class Tokenizer {
public:
    Tokenizer();
    ~Tokenizer();
    
    // Load tokenizer from GGUF model
    bool LoadFromGGUF(const std::string& modelPath);
    
    // Encode/decode
    std::vector<int> Encode(const std::string& text);
    std::string Decode(const std::vector<int>& tokens);
    
    // Vocabulary info
    size_t GetVocabSize() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Deep2
