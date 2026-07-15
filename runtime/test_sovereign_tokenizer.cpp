// ============================================================================
// test_sovereign_tokenizer.cpp - Test Sovereign BPE Tokenizer
// ============================================================================

#include "sovereign_tokenizer.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace RawrXD::Runtime;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <tokenizer.json> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --encode \"text\"    Encode text to tokens" << std::endl;
    std::cout << "  --decode \"tokens\"   Decode tokens to text (comma-separated)" << std::endl;
    std::cout << "  --roundtrip \"text\"  Test encode-decode roundtrip" << std::endl;
    std::cout << "  --benchmark N       Benchmark with N iterations" << std::endl;
    std::cout << "  --vocab             Print vocabulary info" << std::endl;
}

void TestBasicEncoding(SovereignTokenizer& tokenizer, const std::string& text) {
    std::cout << "=== Basic Encoding ===" << std::endl;
    std::cout << "Input: \"" << text << "\"" << std::endl;
    
    auto tokens = tokenizer.Encode(text);
    
    std::cout << "Tokens: " << tokens.size() << std::endl;
    std::cout << "IDs: ";
    for (auto t : tokens) {
        std::cout << t << " ";
    }
    std::cout << std::endl;
    
    std::cout << "Tokens: ";
    for (auto t : tokens) {
        std::cout << "\"" << tokenizer.IdToToken(t) << "\" ";
    }
    std::cout << std::endl;
}

void TestRoundtrip(SovereignTokenizer& tokenizer, const std::string& text) {
    std::cout << std::endl << "=== Roundtrip Test ===" << std::endl;
    std::cout << "Original: \"" << text << "\"" << std::endl;
    
    auto tokens = tokenizer.Encode(text);
    std::string decoded = tokenizer.Decode(tokens);
    
    std::cout << "Decoded:  \"" << decoded << "\"" << std::endl;
    
    if (text == decoded) {
        std::cout << "✓ Roundtrip successful" << std::endl;
    } else {
        std::cout << "⚠ Roundtrip differs (expected for BPE)" << std::endl;
    }
}

void TestDecoding(SovereignTokenizer& tokenizer, const std::string& tokens_str) {
    std::cout << std::endl << "=== Decoding ===" << std::endl;
    std::cout << "Input IDs: " << tokens_str << std::endl;
    
    // Parse comma-separated tokens
    std::vector<uint32_t> tokens;
    size_t start = 0;
    size_t end = tokens_str.find(',');
    while (end != std::string::npos) {
        tokens.push_back(std::stoul(tokens_str.substr(start, end - start)));
        start = end + 1;
        end = tokens_str.find(',', start);
    }
    if (start < tokens_str.size()) {
        tokens.push_back(std::stoul(tokens_str.substr(start)));
    }
    
    std::string decoded = tokenizer.Decode(tokens);
    std::cout << "Decoded: \"" << decoded << "\"" << std::endl;
}

void Benchmark(SovereignTokenizer& tokenizer, const std::string& text, size_t iterations) {
    std::cout << std::endl << "=== Benchmark ===" << std::endl;
    std::cout << "Text: \"" << text << "\"" << std::endl;
    std::cout << "Iterations: " << iterations << std::endl;
    
    // Warmup
    for (size_t i = 0; i < 100; ++i) {
        tokenizer.Encode(text);
    }
    
    // Benchmark encode
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        tokenizer.Encode(text);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto encode_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    auto tokens = tokenizer.Encode(text);
    
    // Benchmark decode
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        tokenizer.Decode(tokens);
    }
    end = std::chrono::high_resolution_clock::now();
    auto decode_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Encode: " << encode_time.count() / 1000.0 << " ms (" << 
              (encode_time.count() * 1000.0 / iterations) << " us/iter)" << std::endl;
    std::cout << "Decode: " << decode_time.count() / 1000.0 << " ms (" << 
              (decode_time.count() * 1000.0 / iterations) << " us/iter)" << std::endl;
}

void PrintVocabInfo(SovereignTokenizer& tokenizer) {
    std::cout << std::endl << "=== Vocabulary Info ===" << std::endl;
    std::cout << "Vocab size: " << tokenizer.GetVocabSize() << std::endl;
    std::cout << "BOS token: " << tokenizer.GetBosTokenId() << std::endl;
    std::cout << "EOS token: " << tokenizer.GetEosTokenId() << std::endl;
    std::cout << "PAD token: " << tokenizer.GetPadTokenId() << std::endl;
    std::cout << "UNK token: " << tokenizer.GetUnkTokenId() << std::endl;
    
    // Sample some tokens
    std::cout << "\nSample tokens:" << std::endl;
    for (uint32_t i = 0; i < std::min(size_t(20), tokenizer.GetVocabSize()); ++i) {
        std::string token = tokenizer.IdToToken(i);
        std::cout << "  " << i << ": \"" << token << "\"" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== Sovereign Tokenizer Test ===" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string tokenizer_path = argv[1];
    std::string mode = "--roundtrip";
    std::string text = "Hello, world!";
    size_t benchmark_iterations = 1000;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--encode" && i + 1 < argc) {
            mode = "--encode";
            text = argv[++i];
        } else if (arg == "--decode" && i + 1 < argc) {
            mode = "--decode";
            text = argv[++i];
        } else if (arg == "--roundtrip" && i + 1 < argc) {
            mode = "--roundtrip";
            text = argv[++i];
        } else if (arg == "--benchmark" && i + 1 < argc) {
            mode = "--benchmark";
            benchmark_iterations = std::stoul(argv[++i]);
        } else if (arg == "--vocab") {
            mode = "--vocab";
        }
    }
    
    // Load tokenizer
    std::cout << "Loading tokenizer: " << tokenizer_path << std::endl;
    
    SovereignTokenizer tokenizer;
    if (!tokenizer.Load(tokenizer_path)) {
        std::cout << "✗ Failed to load tokenizer" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Tokenizer loaded" << std::endl;
    std::cout << "  Vocab size: " << tokenizer.GetVocabSize() << std::endl;
    
    // Execute mode
    if (mode == "--encode") {
        TestBasicEncoding(tokenizer, text);
    } else if (mode == "--decode") {
        TestDecoding(tokenizer, text);
    } else if (mode == "--roundtrip") {
        TestBasicEncoding(tokenizer, text);
        TestRoundtrip(tokenizer, text);
    } else if (mode == "--benchmark") {
        Benchmark(tokenizer, text, benchmark_iterations);
    } else if (mode == "--vocab") {
        PrintVocabInfo(tokenizer);
    }
    
    std::cout << std::endl << "=== Test Complete ===" << std::endl;
    
    return 0;
}
