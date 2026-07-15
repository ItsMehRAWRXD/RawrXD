// ============================================================================
// Sovereign Tokenizer Integration Test
// ============================================================================
// Validates end-to-end: Text → Tokens → Detokenize → Text
// With telemetry hooks ready for SEG integration
// ============================================================================

#include <iostream>
#include <memory>
#include <chrono>
#include <vector>
#include <string>

// Sovereign Tokenizer
#include "../src/tokenizer/bpe_tokenizer.hpp"
#include "../src/tokenizer/tokenizer_factory.hpp"

// Runtime telemetry (from our previous work)
#include "../runtime/q4k_decoder_optimized.hpp"

using namespace rawrxd::runtime;

std::unique_ptr<tokenizer::TokenizerBase> g_tokenizer;

bool InitializeTokenizer(const std::string& model_path) {
    // Try to load using tokenizer factory
    g_tokenizer = tokenizer::TokenizerFactory::load(model_path);
    if (g_tokenizer) {
        return true;
    }
    
    // Fallback: try vocab.json + merges.txt
    std::string vocab_path = model_path + ".vocab.json";
    std::string merges_path = model_path + ".merges.txt";
    
    auto bpe = std::make_unique<tokenizer::BPETokenizer>();
    if (bpe->load_from_file(vocab_path, merges_path)) {
        g_tokenizer = std::move(bpe);
        return true;
    }
    
    return false;
}

std::vector<uint32_t> Tokenize(const std::string& text) {
    if (!g_tokenizer) {
        // Fallback: use ASCII codes if no tokenizer loaded
        std::vector<uint32_t> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<uint32_t>(c));
        }
        return tokens;
    }
    
    auto encoding = g_tokenizer->encode(text, true);
    std::vector<uint32_t> tokens;
    tokens.reserve(encoding.token_ids.size());
    for (auto id : encoding.token_ids) {
        tokens.push_back(static_cast<uint32_t>(id));
    }
    return tokens;
}

std::string Detokenize(const std::vector<uint32_t>& tokens) {
    if (!g_tokenizer) {
        // Fallback: ASCII decode
        std::string text;
        for (auto id : tokens) {
            if (id < 256) text += static_cast<char>(id);
        }
        return text;
    }
    
    std::vector<tokenizer::TokenId> token_ids;
    token_ids.reserve(tokens.size());
    for (auto id : tokens) {
        token_ids.push_back(static_cast<tokenizer::TokenId>(id));
    }
    
    tokenizer::DecodeOptions options;
    options.skip_special_tokens = true;
    options.clean_up_tokenization = true;
    return g_tokenizer->decode(token_ids, options);
}

void PrintUsage() {
    std::cout << "Sovereign Tokenizer Integration Test\n"
              << "Usage: test_tokenizer_integration [options]\n"
              << "\nOptions:\n"
              << "  --model <path>       Path to model (for vocab loading)\n"
              << "  --text <text>        Text to tokenize (default: \"Hello world\")\n"
              << "  --roundtrip          Test roundtrip: text -> tokens -> text\n"
              << "\nExample:\n"
              << "  test_tokenizer_integration --text \"The quick brown fox\" --roundtrip\n";
}

struct TestConfig {
    std::string model_path;
    std::string text = "Hello world";
    bool roundtrip = false;
};

TestConfig ParseArgs(int argc, char* argv[]) {
    TestConfig cfg;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--model" && i + 1 < argc) {
            cfg.model_path = argv[++i];
        } else if (arg == "--text" && i + 1 < argc) {
            cfg.text = argv[++i];
        } else if (arg == "--roundtrip") {
            cfg.roundtrip = true;
        }
    }
    
    return cfg;
}

int main(int argc, char* argv[]) {
    auto cfg = ParseArgs(argc, argv);
    
    std::cout << "=== Sovereign Tokenizer Integration Test ===\n\n";
    
    // ------------------------------------------------------------------------
    // Step 1: Initialize tokenizer
    // ------------------------------------------------------------------------
    std::cout << "[1/4] Initializing sovereign tokenizer...\n";
    
    if (!cfg.model_path.empty()) {
        if (InitializeTokenizer(cfg.model_path)) {
            std::cout << "      ✓ Sovereign BPE tokenizer loaded\n";
            std::cout << "      Vocab size: " << g_tokenizer->vocab_size() << "\n";
            std::cout << "      BOS token: " << g_tokenizer->bos_token_id() << "\n";
            std::cout << "      EOS token: " << g_tokenizer->eos_token_id() << "\n";
        } else {
            std::cout << "      ⚠ Tokenizer not found, using ASCII fallback\n";
        }
    } else {
        std::cout << "      ℹ No model path provided, using ASCII fallback\n";
    }
    std::cout << "\n";
    
    // ------------------------------------------------------------------------
    // Step 2: Tokenize
    // ------------------------------------------------------------------------
    std::cout << "[2/4] Tokenizing input...\n";
    std::cout << "      Input: \"" << cfg.text << "\"\n\n";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    auto tokens = Tokenize(cfg.text);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "      ✓ Tokenized to " << tokens.size() << " tokens\n";
    std::cout << "      Time: " << duration.count() << " μs\n";
    std::cout << "      Tokens: [";
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    std::cout << "]\n\n";
    
    // Show token details if using BPE
    if (g_tokenizer) {
        std::cout << "      Token breakdown:\n";
        for (size_t i = 0; i < tokens.size() && i < 10; ++i) {
            auto token_text = g_tokenizer->id_to_token(static_cast<tokenizer::TokenId>(tokens[i]));
            std::cout << "        [" << tokens[i] << "] = \"" << token_text << "\"\n";
        }
        if (tokens.size() > 10) {
            std::cout << "        ... (" << (tokens.size() - 10) << " more)\n";
        }
        std::cout << "\n";
    }
    
    // ------------------------------------------------------------------------
    // Step 3: Detokenize (roundtrip test)
    // ------------------------------------------------------------------------
    if (cfg.roundtrip) {
        std::cout << "[3/4] Testing roundtrip (detokenize)...\n";
        
        start_time = std::chrono::high_resolution_clock::now();
        std::string output = Detokenize(tokens);
        end_time = std::chrono::high_resolution_clock::now();
        
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        std::cout << "      ✓ Detokenized in " << duration.count() << " μs\n";
        std::cout << "      Output: \"" << output << "\"\n\n";
        
        // ------------------------------------------------------------------------
        // Step 4: Validate
        // ------------------------------------------------------------------------
        std::cout << "[4/4] Validating roundtrip...\n";
        
        // Normalize for comparison (remove special tokens, etc.)
        std::string input_normalized = cfg.text;
        std::string output_normalized = output;
        
        // Trim whitespace for comparison
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t\n\r");
            size_t end = s.find_last_not_of(" \t\n\r");
            if (start == std::string::npos) s = "";
            else s = s.substr(start, end - start + 1);
        };
        
        trim(input_normalized);
        trim(output_normalized);
        
        if (input_normalized == output_normalized) {
            std::cout << "      ✓ Roundtrip VALID - input matches output\n";
        } else {
            std::cout << "      ⚠ Roundtrip DIFFERS:\n";
            std::cout << "        Input:  \"" << input_normalized << "\"\n";
            std::cout << "        Output: \"" << output_normalized << "\"\n";
        }
        std::cout << "\n";
    }
    
    // ------------------------------------------------------------------------
    // Telemetry Summary
    // ------------------------------------------------------------------------
    std::cout << "=== Telemetry Summary ===\n";
    std::cout << "Tokenizer type: " << (g_tokenizer ? "Sovereign BPE" : "ASCII fallback") << "\n";
    std::cout << "Input length:   " << cfg.text.length() << " chars\n";
    std::cout << "Token count:    " << tokens.size() << " tokens\n";
    std::cout << "Chars/token:    " << (cfg.text.length() / (double)tokens.size()) << "\n";
    
    // Show Q4K telemetry (from our previous work)
    std::cout << "\nQ4K Decoder Telemetry:\n";
    std::cout << "  MASM calls:   " << g_q4k_telemetry.masm_calls << "\n";
    std::cout << "  AVX2 calls:   " << g_q4k_telemetry.avx2_calls << "\n";
    std::cout << "  Scalar calls: " << g_q4k_telemetry.scalar_calls << "\n";
    
    std::cout << "\n=== Test Complete ===\n";
    
    return 0;
}
