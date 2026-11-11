// ============================================================================
// C3 Test: Embedding Lookup
// ============================================================================
// Tests token -> embedding lookup from token_embd.weight
// ============================================================================

#include "src/runtime/embedding_lookup.hpp"
#include "src/runtime/tokenizer_runtime.h"
#include "src/model/model_context.h"
#include <iostream>
#include <iomanip>
#include <numeric>
#include <cmath>
#include <cstdint>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> [text]\n";
        return 1;
    }
    
    std::string model_path = argv[1];
    std::string text = (argc > 2) ? argv[2] : "Hello world";
    
    std::cout << "=== C3: Embedding Lookup Test ===\n\n";
    
    // Step 1: Load model
    std::cout << "[1/4] Loading model...\n";
    auto model = rawrxd::model::ModelContextFactory::FromGGUF(model_path);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    std::cout << "      ✓ Model loaded\n";
    
    // Step 2: Create tokenizer (C2)
    std::cout << "[2/4] Creating tokenizer...\n";
    auto tokenizer = rawrxd::runtime::TokenizerFactory::FromModel(*model);
    if (!tokenizer) {
        std::cerr << "Failed to create tokenizer\n";
        return 1;
    }
    std::cout << "      ✓ Tokenizer ready\n";
    
    // Step 3: Tokenize
    std::cout << "[3/4] Tokenizing...\n";
    auto tokens = tokenizer->Encode(text);
    std::cout << "      Input: \"" << text << "\"\n";
    std::cout << "      Tokens: " << tokens.size() << " [";
    for (size_t i = 0; i < tokens.size() && i < 10; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    if (tokens.size() > 10) std::cout << "...";
    std::cout << "]\n";
    
    // Step 4: Embedding lookup (C3)
    std::cout << "[4/4] Looking up embeddings...\n";
    rawrxd::runtime::EmbeddingLookup lookup;
    if (!lookup.Initialize(*model)) {
        std::cerr << "Failed to initialize embedding lookup: " << lookup.GetLastError() << "\n";
        return 1;
    }
    
    std::cout << "      ✓ Embedding lookup initialized\n";
    std::cout << "      Vocab size: " << lookup.GetVocabSize() << "\n";
    std::cout << "      Embedding dim: " << lookup.GetEmbeddingDim() << "\n";
    
    // Get embeddings for tokens
    std::vector<uint32_t> token_ids(tokens.begin(), tokens.end());
    auto embeddings = lookup.GetEmbeddings(token_ids);
    if (!embeddings.IsValid()) {
        std::cerr << "Failed to get embeddings\n";
        return 1;
    }
    
    std::cout << "      ✓ Embeddings retrieved\n";
    std::cout << "      Shape: [" << embeddings.num_tokens << " x " 
              << embeddings.embedding_dim << "]\n";
    
    // Show first few values of first token's embedding
    std::cout << "\nFirst token embedding (first 10 values):\n";
    const float* emb0 = embeddings.GetEmbedding(0);
    std::cout << "  [";
    for (uint32_t i = 0; i < std::min(10u, embeddings.embedding_dim); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << std::fixed << std::setprecision(4) << emb0[i];
    }
    std::cout << "]\n";
    
    // Calculate L2 norm as sanity check
    double l2_norm = 0.0;
    for (uint32_t i = 0; i < embeddings.embedding_dim; ++i) {
        l2_norm += emb0[i] * emb0[i];
    }
    l2_norm = std::sqrt(l2_norm);
    std::cout << "\nL2 norm of first embedding: " << std::fixed << std::setprecision(4) 
              << l2_norm << "\n";
    
    // Check if values are reasonable (not all zeros, not NaN)
    bool valid = true;
    for (uint32_t i = 0; i < embeddings.embedding_dim && i < 100; ++i) {
        if (std::isnan(emb0[i]) || std::isinf(emb0[i])) {
            valid = false;
            break;
        }
    }
    
    if (valid && l2_norm > 0.1 && l2_norm < 1000.0) {
        std::cout << "\n✓ C3 EMBEDDING LOOKUP SUCCESS\n";
        std::cout << "  Token -> Embedding pipeline working\n";
        return 0;
    } else {
        std::cerr << "\n✗ C3 FAILED: Invalid embedding values\n";
        return 1;
    }
}
