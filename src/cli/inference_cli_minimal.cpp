// ============================================================================
// inference_cli_minimal.cpp - Minimal working CLI with integrated inference
// ============================================================================
// Build: g++ -std=c++17 -O2 -I../../src -I../../include inference_cli_minimal.cpp 
//        ../../src/ai/fast_spec.cpp ../../src/ai/fast_spec_inference_bridge.cpp
//        -o inference_cli.exe
// ============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <fstream>
#include <sstream>
#include <unordered_map>

// FastSpec integration
#include "ai/fast_spec_inference_bridge.h"

// Minimal tokenizer (same as test)
class MinimalTokenizer {
public:
    std::vector<uint32_t> Encode(const std::string& text) {
        std::vector<uint32_t> tokens;
        std::string current;
        
        for (char c : text) {
            if (c == ' ' || c == '\n' || c == '\t') {
                if (!current.empty()) {
                    tokens.push_back(GetOrCreateToken(current));
                    current.clear();
                }
                if (c == '\n') tokens.push_back(2);
                else if (c == ' ') tokens.push_back(3);
            } else {
                current += c;
            }
        }
        
        if (!current.empty()) {
            tokens.push_back(GetOrCreateToken(current));
        }
        
        return tokens;
    }
    
    std::string Decode(const std::vector<uint32_t>& tokens) {
        std::string result;
        for (uint32_t tok : tokens) {
            if (tok == 2) result += "\n";
            else if (tok == 3) result += " ";
            else if (tok < vocab_.size()) {
                result += vocab_[tok];
            }
        }
        return result;
    }
    
    size_t VocabSize() const { return vocab_.size(); }
    
private:
    std::vector<std::string> vocab_ = {"<pad>", "<unk>", "\n", " "};
    std::unordered_map<std::string, uint32_t> token_to_id_;
    
    uint32_t GetOrCreateToken(const std::string& word) {
        auto it = token_to_id_.find(word);
        if (it != token_to_id_.end()) return it->second;
        uint32_t id = vocab_.size();
        vocab_.push_back(word);
        token_to_id_[word] = id;
        return id;
    }
};

// Simple inference engine that uses FastSpec for speculative decoding
class MinimalInferenceEngine {
public:
    struct Config {
        uint32_t vocab_size = 32000;
        uint32_t draft_width = 4;
        float temperature = 0.8f;
    };
    
    bool Initialize(const Config& cfg) {
        config_ = cfg;
        tokenizer_ = std::make_unique<MinimalTokenizer>();
        
        // Initialize FastSpec bridge
        RawrXD::FastSpecInferenceBridge::Config fastcfg;
        fastcfg.vocab_size = cfg.vocab_size;
        fastcfg.draft_width = cfg.draft_width;
        fastspec_bridge_ = std::make_unique<RawrXD::FastSpecInferenceBridge>(fastcfg);
        
        return true;
    }
    
    // Generate tokens from prompt
    std::vector<uint32_t> Generate(const std::string& prompt, uint32_t max_tokens = 50) {
        auto tokens = tokenizer_->Encode(prompt);
        if (tokens.empty()) return {};
        
        // Prefill context for FastSpec
        fastspec_bridge_->PrefillContext(tokens);
        
        std::vector<uint32_t> generated = tokens;
        uint32_t last_token = tokens.back();
        uint64_t rng = 0xDEADBEEFCAFEBABEULL;
        
        for (uint32_t i = 0; i < max_tokens; i++) {
            // Generate dummy logits (in real implementation, this comes from model forward pass)
            std::vector<float> logits(config_.vocab_size, -10.0f);
            
            // Make one token slightly hotter based on last_token
            uint32_t hot_token = (last_token + 1) % config_.vocab_size;
            logits[hot_token] = 10.0f;
            
            // Use FastSpec for speculative sampling
            auto step = fastspec_bridge_->GenerateTokenSampled(last_token, logits, &rng);
            uint32_t next_token = step.accepted_token;
            
            if (next_token == 2 || next_token >= config_.vocab_size) break; // EOS
            
            generated.push_back(next_token);
            last_token = next_token;
        }
        
        return generated;
    }
    
    std::string GenerateText(const std::string& prompt, uint32_t max_tokens = 50) {
        auto tokens = Generate(prompt, max_tokens);
        return tokenizer_->Decode(tokens);
    }
    
    MinimalTokenizer* GetTokenizer() { return tokenizer_.get(); }
    
private:
    Config config_;
    std::unique_ptr<MinimalTokenizer> tokenizer_;
    std::unique_ptr<RawrXD::FastSpecInferenceBridge> fastspec_bridge_;
};

void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <command> [args...]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  tokenize <text>     - Tokenize text and show token IDs\n";
    std::cout << "  generate <prompt>     - Generate text from prompt\n";
    std::cout << "  benchmark           - Run performance benchmark\n";
    std::cout << "  interactive         - Interactive generation mode\n";
    std::cout << "\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    // Initialize inference engine
    MinimalInferenceEngine engine;
    MinimalInferenceEngine::Config cfg;
    cfg.vocab_size = 32000;
    cfg.draft_width = 4;
    
    auto t0 = std::chrono::high_resolution_clock::now();
    if (!engine.Initialize(cfg)) {
        std::cerr << "Failed to initialize inference engine\n";
        return 1;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double init_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
    
    if (command == "tokenize") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " tokenize <text>\n";
            return 1;
        }
        
        std::string text = argv[2];
        for (int i = 3; i < argc; i++) {
            text += " ";
            text += argv[i];
        }
        
        auto tokens = engine.GetTokenizer()->Encode(text);
        
        std::cout << "Text: \"" << text << "\"\n";
        std::cout << "Tokens: ";
        for (auto tok : tokens) {
            std::cout << tok << " ";
        }
        std::cout << "\n";
        std::cout << "Token count: " << tokens.size() << "\n";
        std::cout << "Vocab size: " << engine.GetTokenizer()->VocabSize() << "\n";
        
    } else if (command == "generate") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " generate <prompt>\n";
            return 1;
        }
        
        std::string prompt = argv[2];
        for (int i = 3; i < argc; i++) {
            prompt += " ";
            prompt += argv[i];
        }
        
        std::cout << "Prompt: \"" << prompt << "\"\n";
        std::cout << "Generating...\n\n";
        
        t0 = std::chrono::high_resolution_clock::now();
        auto result = engine.GenerateText(prompt, 20);
        t1 = std::chrono::high_resolution_clock::now();
        double gen_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
        
        std::cout << "Result: \"" << result << "\"\n\n";
        std::cout << "Generation time: " << gen_ms << " ms\n";
        std::cout << "Tokens generated: " << 20 << "\n";
        std::cout << "Speed: " << (20.0 / (gen_ms / 1000.0)) << " tokens/sec\n";
        
    } else if (command == "benchmark") {
        std::cout << "Running inference benchmark...\n\n";
        
        // Benchmark 1: Tokenization speed
        t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; i++) {
            engine.GetTokenizer()->Encode("the quick brown fox jumps over the lazy dog");
        }
        t1 = std::chrono::high_resolution_clock::now();
        double tok_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
        double tok_per_sec = 10000.0 / (tok_ms / 1000.0);
        
        std::cout << "Tokenization: " << tok_per_sec << " encodes/sec\n";
        
        // Benchmark 2: Generation speed
        t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; i++) {
            engine.GenerateText("Hello", 10);
        }
        t1 = std::chrono::high_resolution_clock::now();
        double gen_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
        double gen_per_sec = (100 * 10) / (gen_ms / 1000.0);
        
        std::cout << "Generation: " << gen_per_sec << " tokens/sec\n";
        std::cout << "Init time: " << init_ms << " ms\n";
        
        std::cout << "\n[OK] Benchmark complete\n";
        
    } else if (command == "interactive") {
        std::cout << "Interactive mode (type 'quit' to exit)\n";
        std::cout << "Initialization took " << init_ms << " ms\n\n";
        
        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            
            if (line == "quit" || line == "exit") break;
            if (line.empty()) continue;
            
            t0 = std::chrono::high_resolution_clock::now();
            auto result = engine.GenerateText(line, 20);
            t1 = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
            
            std::cout << result << "\n";
            std::cout << "[" << ms << " ms]\n\n";
        }
        
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        PrintUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
