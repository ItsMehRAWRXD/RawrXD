// ============================================================================
// C4 Test: Transformer Forward Pass
// ============================================================================
// Tests the full transformer: Embeddings → Layers → Logits
//
// Pipeline:
//   Embeddings → RMSNorm → Attention → FFN → RMSNorm → Output Projection → Logits
// ============================================================================

#include "src/runtime/embedding_lookup.hpp"
#include "src/runtime/tokenizer_runtime.h"
#include "src/model/model_context.h"
#include "src/gateway/seg_gateway.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <algorithm>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> [text]\n";
        return 1;
    }
    
    std::string model_path = argv[1];
    std::string text = (argc > 2) ? argv[2] : "Hello";
    
    std::cout << "=== C4: Transformer Forward Pass Test ===\n\n";
    
    // Step 1: Load model
    std::cout << "[1/5] Loading model...\n";
    auto model = rawrxd::model::ModelContextFactory::FromGGUF(model_path);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    auto arch = model->GetArchitecture();
    std::cout << "      ✓ Model loaded\n";
    std::cout << "      Architecture: " << arch.type << "\n";
    std::cout << "      Layers: " << arch.layer_count << "\n";
    std::cout << "      Hidden size: " << arch.embedding_dim << "\n";
    std::cout << "      Heads: " << arch.head_count << "\n";
    std::cout << "      Vocab size: " << arch.vocab_size << "\n";
    
    // Step 2: Tokenize
    std::cout << "\n[2/5] Tokenizing...\n";
    auto tokenizer = rawrxd::runtime::TokenizerFactory::FromModel(*model);
    if (!tokenizer) {
        std::cerr << "Failed to create tokenizer\n";
        return 1;
    }
    auto tokens = tokenizer->Encode(text);
    std::cout << "      Input: \"" << text << "\"\n";
    std::cout << "      Tokens: " << tokens.size() << " [";
    for (size_t i = 0; i < tokens.size() && i < 8; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    if (tokens.size() > 8) std::cout << "...";
    std::cout << "]\n";
    
    // Step 3: Embedding lookup (C3)
    std::cout << "\n[3/5] Looking up embeddings...\n";
    rawrxd::runtime::EmbeddingLookup lookup;
    if (!lookup.Initialize(*model)) {
        std::cerr << "Failed to initialize embedding lookup\n";
        return 1;
    }
    std::vector<uint32_t> token_ids(tokens.begin(), tokens.end());
    auto embeddings = lookup.GetEmbeddings(token_ids);
    if (!embeddings.IsValid()) {
        std::cerr << "Failed to get embeddings\n";
        return 1;
    }
    std::cout << "      ✓ Embeddings: [" << embeddings.num_tokens << " x " 
              << embeddings.embedding_dim << "]\n";
    
    // Step 4: Transformer forward pass through SEG
    std::cout << "\n[4/5] Running transformer forward pass...\n";
    
    rawrxd::gateway::SegGateway seg_gateway;
    if (!seg_gateway.Initialize(model_path)) {
        std::cerr << "Failed to initialize SEG gateway\n";
        return 1;
    }
    
    // Create execution request
    rawrxd::execution::ExecutionRequest req;
    req.model_path = model_path;
    req.prompt = text;
    req.max_tokens = 1;  // Just generate 1 token for test
    req.dump_telemetry = true;
    req.verbose = false;
    
    std::cout << "      Running SEG inference...\n";
    auto seg_result = seg_gateway.Run(req);
    
    if (seg_result.status != rawrxd::execution::Status::SUCCESS) {
        std::cerr << "      SEG inference failed: " << seg_result.status_message << "\n";
        return 1;
    }
    
    std::cout << "      ✓ Transformer forward pass complete\n";
    std::cout << "      Tokens generated: " << seg_result.tokens_generated.size() << "\n";
    std::cout << "      Telemetry events: " << seg_result.telemetry.events_logged << "\n";
    
    // Step 5: Validate output
    std::cout << "\n[5/5] Validating output...\n";
    
    bool has_logits = !seg_result.logits_first_token.empty();
    bool has_tokens = !seg_result.tokens_generated.empty();
    bool telemetry_ok = seg_result.telemetry.events_logged > 0 && 
                        seg_result.telemetry.events_dropped == 0;
    
    if (has_logits) {
        std::cout << "      ✓ Logits available (" << seg_result.logits_first_token.size() << " values)\n";
        
        // Find max logit (predicted token)
        auto max_it = std::max_element(seg_result.logits_first_token.begin(), 
                                        seg_result.logits_first_token.end());
        int predicted_token = std::distance(seg_result.logits_first_token.begin(), max_it);
        float max_logit = *max_it;
        
        std::cout << "      Predicted token: " << predicted_token << " (logit=" 
                  << std::fixed << std::setprecision(4) << max_logit << ")\n";
        
        // Show top 5
        std::cout << "      Top 5 predictions:\n";
        std::vector<std::pair<float, int>> logits_with_idx;
        for (size_t i = 0; i < seg_result.logits_first_token.size() && i < 100; ++i) {
            logits_with_idx.push_back({seg_result.logits_first_token[i], static_cast<int>(i)});
        }
        std::partial_sort(logits_with_idx.begin(), logits_with_idx.begin() + 5, 
                          logits_with_idx.end(), std::greater<>());
        
        for (int i = 0; i < 5 && i < static_cast<int>(logits_with_idx.size()); ++i) {
            std::cout << "        [" << logits_with_idx[i].second << "] " 
                      << std::fixed << std::setprecision(4) << logits_with_idx[i].first << "\n";
        }
    }
    
    if (has_tokens) {
        std::cout << "      ✓ Tokens generated\n";
    }
    
    if (telemetry_ok) {
        std::cout << "      ✓ Telemetry captured (" << seg_result.telemetry.events_logged 
                  << " events, 0 dropped)\n";
    }
    
    // Summary
    std::cout << "\n" << std::string(60, '=') << "\n";
    if (has_tokens && telemetry_ok) {
        std::cout << "✓ C4 TRANSFORMER FORWARD PASS SUCCESS\n";
        std::cout << "  Embeddings → Transformer → Logits → Tokens\n";
        std::cout << "  Pipeline working end-to-end\n";
        
        std::cout << "\nTelemetry Summary:\n";
        std::cout << seg_result.telemetry.Summary() << "\n";
        
        return 0;
    } else {
        std::cerr << "✗ C4 FAILED\n";
        return 1;
    }
}
