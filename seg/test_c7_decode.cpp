// ============================================================================
// C7: Decode Output Test Suite
// ============================================================================
// Tests token-to-text conversion
// ============================================================================

#include "decode_output.hpp"
#include <iostream>
#include <cassert>

using namespace seg;

// Test 1: Basic token decoding
bool TestBasicDecoding() {
    std::cout << "\n=== Test 1: Basic Token Decoding ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    
    // Decode "Hello world"
    std::vector<uint32_t> tokens = {321, 323};  // "ĠHello", "Ġworld"
    
    DecodeConfig config;
    config.merge_continuation_spaces = true;
    
    std::string text = decoder.Decode(tokens, config);
    
    std::cout << "Tokens: [321, 323]" << std::endl;
    std::cout << "Decoded: \"" << text << "\"" << std::endl;
    
    // Should produce " Hello world" (with leading space from Ġ)
    return text.find("Hello") != std::string::npos && 
           text.find("world") != std::string::npos;
}

// Test 2: Special token handling
bool TestSpecialTokens() {
    std::cout << "\n=== Test 2: Special Token Handling ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    
    // Tokens with special tokens
    std::vector<uint32_t> tokens = {1, 321, 323, 2};  // BOS, "ĠHello", "Ġworld", EOS
    
    DecodeConfig config;
    config.strip_special_tokens = true;
    
    std::string text = decoder.Decode(tokens, config);
    
    std::cout << "Tokens: [1 (BOS), 321, 323, 2 (EOS)]" << std::endl;
    std::cout << "Decoded: \"" << text << "\"" << std::endl;
    
    // Should not contain special token markers
    return text.find("<|begin_of_text|>") == std::string::npos &&
           text.find("<|end_of_text|>") == std::string::npos;
}

// Test 3: Byte fallback tokens
bool TestByteFallback() {
    std::cout << "\n=== Test 3: Byte Fallback Tokens ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    
    // Byte tokens for "Hi" (H=72, i=105)
    std::vector<uint32_t> tokens = {3 + 72, 3 + 105};  // 'H', 'i'
    
    DecodeConfig config;
    config.handle_byte_fallback = true;
    
    std::string text = decoder.Decode(tokens, config);
    
    std::cout << "Tokens: [75, 108] (byte fallback for 'H', 'i')" << std::endl;
    std::cout << "Decoded: \"" << text << "\"" << std::endl;
    
    return text == "Hi";
}

// Test 4: Whitespace normalization
bool TestWhitespaceNormalization() {
    std::cout << "\n=== Test 4: Whitespace Normalization ===" << std::endl;
    
    std::string text = "  Hello    world  ";
    std::string normalized = NormalizeWhitespace(text);
    
    std::cout << "Input: \"" << text << "\"" << std::endl;
    std::cout << "Normalized: \"" << normalized << "\"" << std::endl;
    
    return normalized == "Hello world";
}

// Test 5: Strip special tokens from text
bool TestStripSpecialTokens() {
    std::cout << "\n=== Test 5: Strip Special Tokens ===" << std::endl;
    
    std::string text = "<|begin_of_text|>Hello world<|end_of_text|>";
    std::string stripped = StripSpecialTokens(text);
    
    std::cout << "Input: \"" << text << "\"" << std::endl;
    std::cout << "Stripped: \"" << stripped << "\"" << std::endl;
    
    return stripped == "Hello world";
}

// Test 6: Unknown token handling
bool TestUnknownTokens() {
    std::cout << "\n=== Test 6: Unknown Token Handling ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    
    // Token not in vocabulary
    std::vector<uint32_t> tokens = {321, 99999, 323};  // 99999 doesn't exist
    
    DecodeConfig config;
    config.skip_unknown_tokens = true;
    
    std::string text = decoder.Decode(tokens, config);
    
    std::cout << "Tokens: [321, 99999 (unknown), 323]" << std::endl;
    std::cout << "Decoded (skip unknown): \"" << text << "\"" << std::endl;
    
    // Should skip unknown token
    return text.find("Hello") != std::string::npos && 
           text.find("world") != std::string::npos;
}

// Test 7: Full pipeline simulation
bool TestFullPipeline() {
    std::cout << "\n=== Test 7: Full Pipeline Simulation ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    
    // Simulate generated tokens: "Hello, how are you?"
    std::vector<uint32_t> tokens = {
        321,    // "ĠHello"
        303,    // ","
        324,    // "Ġhow"
        326,    // "Ġare"
        329,    // "Ġyou"
        307     // "?"
    };
    
    DecodeConfig config;
    config.strip_special_tokens = true;
    config.merge_continuation_spaces = true;
    config.trim_leading_whitespace = true;
    
    std::string text = decoder.Decode(tokens, config);
    
    std::cout << "Generated tokens: [321, 303, 324, 326, 329, 307]" << std::endl;
    std::cout << "Decoded text: \"" << text << "\"" << std::endl;
    
    return !text.empty() && 
           text.find("Hello") != std::string::npos &&
           text.find("how") != std::string::npos;
}

// Test 8: Convenience function
bool TestConvenienceFunction() {
    std::cout << "\n=== Test 8: Convenience Function ===" << std::endl;
    
    auto vocab = CreateLlama3Vocab();
    std::vector<uint32_t> tokens = {321, 323};  // "ĠHello", "Ġworld"
    
    std::string text = DecodeTokens(tokens, vocab);
    
    std::cout << "Using DecodeTokens() convenience function" << std::endl;
    std::cout << "Decoded: \"" << text << "\"" << std::endl;
    
    return !text.empty();
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "C7: Decode Output Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int total = 0;
    
    if (TestBasicDecoding()) ++passed; ++total;
    if (TestSpecialTokens()) ++passed; ++total;
    if (TestByteFallback()) ++passed; ++total;
    if (TestWhitespaceNormalization()) ++passed; ++total;
    if (TestStripSpecialTokens()) ++passed; ++total;
    if (TestUnknownTokens()) ++passed; ++total;
    if (TestFullPipeline()) ++passed; ++total;
    if (TestConvenienceFunction()) ++passed; ++total;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return (passed == total) ? 0 : 1;
}
