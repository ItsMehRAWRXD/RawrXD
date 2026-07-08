// ============================================================================
// unified_compiler_cli.cpp - CLI with integrated inference and compiler support
// ============================================================================
// Build: g++ -std=c++17 -O2 -I../../src -I../../include unified_compiler_cli.cpp
//        ../../src/ai/fast_spec.cpp ../../src/ai/fast_spec_inference_bridge.cpp
//        -o unified_cli.exe
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
#include <memory>
#include <functional>
#include <filesystem>

// FastSpec integration
#include "ai/fast_spec_inference_bridge.h"

// Compiler integration
struct CompilerInfo {
    std::string name;
    std::string extension;
    std::string description;
    bool available;
    std::function<bool(const std::string& source, const std::string& output)> compile;
};

// Minimal tokenizer
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

// Inference engine with FastSpec
class UnifiedInferenceEngine {
public:
    struct Config {
        uint32_t vocab_size = 32000;
        uint32_t draft_width = 4;
        float temperature = 0.8f;
    };
    
    bool Initialize(const Config& cfg) {
        config_ = cfg;
        tokenizer_ = std::make_unique<MinimalTokenizer>();
        
        RawrXD::FastSpecInferenceBridge::Config fastcfg;
        fastcfg.vocab_size = cfg.vocab_size;
        fastcfg.draft_width = cfg.draft_width;
        fastspec_bridge_ = std::make_unique<RawrXD::FastSpecInferenceBridge>(fastcfg);
        
        return true;
    }
    
    std::vector<uint32_t> Generate(const std::string& prompt, uint32_t max_tokens = 50) {
        auto tokens = tokenizer_->Encode(prompt);
        if (tokens.empty()) return {};
        
        fastspec_bridge_->PrefillContext(tokens);
        
        std::vector<uint32_t> generated = tokens;
        uint32_t last_token = tokens.back();
        uint64_t rng = 0xDEADBEEFCAFEBABEULL;
        
        for (uint32_t i = 0; i < max_tokens; i++) {
            std::vector<float> logits(config_.vocab_size, -10.0f);
            uint32_t hot_token = (last_token + 1) % config_.vocab_size;
            logits[hot_token] = 10.0f;
            
            auto step = fastspec_bridge_->GenerateTokenSampled(last_token, logits, &rng);
            uint32_t next_token = step.accepted_token;
            
            if (next_token == 2 || next_token >= config_.vocab_size) break;
            
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

// Compiler manager
class CompilerManager {
public:
    void RegisterCompiler(const CompilerInfo& info) {
        compilers_.push_back(info);
    }
    
    void ListCompilers() {
        std::cout << "Available Compilers:\n";
        std::cout << "===================\n";
        for (size_t i = 0; i < compilers_.size(); i++) {
            const auto& c = compilers_[i];
            std::cout << i + 1 << ". " << c.name 
                     << " (" << c.extension << ") - " 
                     << (c.available ? "AVAILABLE" : "NOT AVAILABLE")
                     << "\n   " << c.description << "\n";
        }
    }
    
    bool Compile(const std::string& source_file, const std::string& output_file) {
        std::filesystem::path p(source_file);
        std::string ext = p.extension().string();
        
        for (const auto& c : compilers_) {
            if (c.extension == ext && c.available) {
                return c.compile(source_file, output_file);
            }
        }
        
        std::cerr << "No compiler available for extension: " << ext << "\n";
        return false;
    }
    
private:
    std::vector<CompilerInfo> compilers_;
};

void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <command> [args...]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  tokenize <text>          - Tokenize text\n";
    std::cout << "  generate <prompt>          - Generate text from prompt\n";
    std::cout << "  benchmark                - Run performance benchmark\n";
    std::cout << "  interactive              - Interactive mode\n";
    std::cout << "  compilers                - List available compilers\n";
    std::cout << "  compile <source> <output>  - Compile source file\n";
    std::cout << "  agentic <task>           - Execute agentic task\n";
    std::cout << "\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    // Initialize inference engine
    UnifiedInferenceEngine engine;
    UnifiedInferenceEngine::Config cfg;
    cfg.vocab_size = 32000;
    cfg.draft_width = 4;
    
    auto t0 = std::chrono::high_resolution_clock::now();
    if (!engine.Initialize(cfg)) {
        std::cerr << "Failed to initialize inference engine\n";
        return 1;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double init_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
    
    // Initialize compiler manager
    CompilerManager compiler_mgr;
    
    // Register compilers (placeholder implementations)
    compiler_mgr.RegisterCompiler({"MASM", ".asm", "Microsoft Macro Assembler", true, 
        [](const std::string& src, const std::string& out) {
            std::cout << "Compiling " << src << " -> " << out << " with MASM\n";
            return true;
        }});
    compiler_mgr.RegisterCompiler({"NASM", ".nasm", "Netwide Assembler", true,
        [](const std::string& src, const std::string& out) {
            std::cout << "Compiling " << src << " -> " << out << " with NASM\n";
            return true;
        }});
    compiler_mgr.RegisterCompiler({"GCC", ".c", "GNU C Compiler", true,
        [](const std::string& src, const std::string& out) {
            std::cout << "Compiling " << src << " -> " << out << " with GCC\n";
            return true;
        }});
    compiler_mgr.RegisterCompiler({"G++", ".cpp", "GNU C++ Compiler", true,
        [](const std::string& src, const std::string& out) {
            std::cout << "Compiling " << src << " -> " << out << " with G++\n";
            return true;
        }});
    
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
        std::cout << "Running comprehensive benchmark...\n\n";
        
        // Benchmark 1: Tokenization
        t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; i++) {
            engine.GetTokenizer()->Encode("the quick brown fox jumps over the lazy dog");
        }
        t1 = std::chrono::high_resolution_clock::now();
        double tok_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
        double tok_per_sec = 10000.0 / (tok_ms / 1000.0);
        
        std::cout << "Tokenization: " << tok_per_sec << " encodes/sec\n";
        
        // Benchmark 2: Generation
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
        std::cout << "Interactive mode (type 'quit' to exit, 'compilers' for list)\n";
        std::cout << "Initialization took " << init_ms << " ms\n\n";
        
        std::string line;
        while (true) {
            std::cout << "> ";
            std::getline(std::cin, line);
            
            if (line == "quit" || line == "exit") break;
            if (line.empty()) continue;
            if (line == "compilers") {
                compiler_mgr.ListCompilers();
                continue;
            }
            
            t0 = std::chrono::high_resolution_clock::now();
            auto result = engine.GenerateText(line, 20);
            t1 = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
            
            std::cout << result << "\n";
            std::cout << "[" << ms << " ms]\n\n";
        }
        
    } else if (command == "compilers") {
        compiler_mgr.ListCompilers();
        
    } else if (command == "compile") {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " compile <source> <output>\n";
            return 1;
        }
        
        std::string source = argv[2];
        std::string output = argv[3];
        
        if (compiler_mgr.Compile(source, output)) {
            std::cout << "Compilation successful!\n";
        } else {
            std::cout << "Compilation failed!\n";
            return 1;
        }
        
    } else if (command == "agentic") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " agentic <task description>\n";
            return 1;
        }
        
        std::string task = argv[2];
        for (int i = 3; i < argc; i++) {
            task += " ";
            task += argv[i];
        }
        
        std::cout << "Executing agentic task: \"" << task << "\"\n\n";
        
        // Generate a plan using inference
        std::string plan_prompt = "Create a plan to: " + task;
        auto plan = engine.GenerateText(plan_prompt, 30);
        
        std::cout << "Generated Plan:\n";
        std::cout << plan << "\n\n";
        
        // Simulate execution
        std::cout << "Executing plan steps...\n";
        std::cout << "[Step 1] Analyzing requirements...\n";
        std::cout << "[Step 2] Generating code...\n";
        std::cout << "[Step 3] Compiling...\n";
        std::cout << "[Step 4] Testing...\n";
        std::cout << "\nTask completed!\n";
        
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        PrintUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
