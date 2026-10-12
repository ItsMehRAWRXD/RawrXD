// GGUFTokenizerLoad.hpp - GGUF tokenizer loading for Deep2
// Forward declaration and loading utilities for GGUF tokenizer
#pragma once

#include "CanonicalTokenizer.hpp"

namespace Deep2 {

// GGUF tokenizer loading interface
// This header provides the tokenizer loading functionality for Deep2 models
// It acts as a bridge between GGUF tokenizer data and the CanonicalTokenizer

// Forward declarations
class CanonicalTokenizer;

// Load tokenizer from GGUF model file
// Returns true on success, false on failure with error in tokenizer
bool LoadTokenizerFromGGUF(const char* modelPath, void* tokenizer);

// Tokenizer bundle structure for loading from GGUF
struct TokenizerBundle {
    // Tokenizer data will be populated here
    void* tokenizerData = nullptr;
    size_t tokenizerSize = 0;
    uint32_t vocabSize = 0;
    int modelType = 0;  // GGML model type
};

// Load tokenizer from GGUF file into bundle
bool LoadTokenizerFromGGUF(const char* modelPath, TokenizerBundle& bundle);

// Apply tokenizer bundle to canonical tokenizer
bool ApplyTokenizerBundle(void* tokenizer, const void* bundle);

// Create tokenizer from GGUF file
void* LoadTokenizerFromGGUF(const char* modelPath);

} // namespace Deep2
} // namespace Deep2

// No #endif needed - #pragma once handles include guards