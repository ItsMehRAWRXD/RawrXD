// Test tokenizer parity between GGUFEmbeddedTokenizer and llama.cpp reference
#include "src/tokenizer/gguf_embedded_tokenizer.hpp"
#include <iostream>
#include <vector>
#include <string>

int main() {
    RawrXD::GGUFEmbeddedTokenizer tokenizer;
    if (!tokenizer.LoadFromGGUF("DeepSeek-V2-Lite-Chat.Q4_K_M.gguf")) {
        std::cerr << "Failed to load tokenizer\n";
        return 1;
    }
    
    std::cout << "Vocab size: " << tokenizer.VocabSize() << "\n";
    std::cout << "BOS token: " << tokenizer.BosToken() << "\n";
    std::cout << "EOS token: " << tokenizer.EosToken() << "\n";
    
    // Test prompts from DEEP2_PARITY_PROBE_001
    const std::vector<std::string> test_prompts = {
        "Hello world",
        "The quick brown fox",
        "<|im_start|>user\nHello<|im_end|>\n<|im_start|>assistant\n",
        "def hello():\n    print('world')"
    };
    
    for (const auto& prompt : test_prompts) {
        std::vector<uint32_t> tokens;
        if (tokenizer.EncodeLongestMatch(prompt, tokens)) {
            std::cout << "\nPrompt: " << prompt << "\n";
            std::cout << "Tokens (" << tokens.size() << "): ";
            for (size_t i = 0; i < tokens.size(); ++i) {
                std::cout << tokens[i] << (i + 1 < tokens.size() ? ", " : "");
            }
            std::cout << "\n";
            
            // Decode back
            std::string decoded;
            for (uint32_t t : tokens) {
                decoded += tokenizer.Token(t);
            }
            std::cout << "Decoded: " << decoded << "\n";
        } else {
            std::cerr << "Failed to tokenize: " << prompt << "\n";
        }
    }
    
    // Specific test: llama.cpp reference had [1, 21521, 9312] with BOS
    // and [21521, 9312] without BOS for some input
    std::vector<uint32_t> tokens_with_bos, tokens_no_bos;
    tokenizer.EncodeLongestMatch("Hello", tokens_with_bos);
    tokenizer.EncodeLongestMatch("Hello", tokens_no_bos);
    
    std::cout << "\n=== Specific test for 'Hello' ===\n";
    std::cout << "With BOS path: ";
    for (auto t : tokens_with_bos) std::cout << t << " ";
    std::cout << "\n";
    
    return 0;
}