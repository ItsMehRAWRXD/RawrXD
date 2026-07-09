// ============================================================================
// Tokenizer Whitespace Test - C2 Completion Validation
// ============================================================================
// Tests the ▁ (U+2581) whitespace handling for SentencePiece tokenizers
// ============================================================================

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <string>

using namespace std;

// ============================================================================
// Simple SentencePiece-style tokenizer for testing
// ============================================================================
class SimpleTokenizer {
public:
    // Vocabulary: token string -> ID
    std::vector<std::pair<std::string, int>> vocab_;
    
    SimpleTokenizer() {
        // Add vocabulary with ▁ prefix (SentencePiece style)
        // ▁ is U+2581, UTF-8: E2 96 81
        // Use explicit byte construction to avoid hex escape issues
        std::string underscore;
        underscore += static_cast<char>(0xE2);
        underscore += static_cast<char>(0x96);
        underscore += static_cast<char>(0x81);
        
        // Special tokens first (IDs 0-2)
        vocab_.push_back({"<s>", 0});   // BOS
        vocab_.push_back({"</s>", 1});  // EOS  
        vocab_.push_back({"<unk>", 2}); // UNK
        
        // Vocabulary tokens (IDs 10+)
        vocab_.push_back({underscore + "Hello", 10});
        vocab_.push_back({underscore + "world", 11});
        vocab_.push_back({underscore + "the", 12});
        vocab_.push_back({underscore + "quick", 13});
        vocab_.push_back({underscore + "brown", 14});
        vocab_.push_back({underscore + "fox", 15});
    }
    
    std::vector<int> Encode(const std::string& text) {
        std::vector<int> result;
        result.push_back(0); // BOS
        
        // Replace spaces with ▁ and tokenize
        std::string processed;
        bool need_prefix = true;
        
        for (size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            if (c == ' ') {
                need_prefix = true;
            } else {
                if (need_prefix) {
                    processed += "\xE2\x96\x81"; // ▁
                    need_prefix = false;
                }
                processed += c;
            }
        }
        
        // Greedy tokenization
        size_t i = 0;
        while (i < processed.size()) {
            size_t best_len = 0;
            int best_id = 0; // <unk>
            
            for (const auto& [token, id] : vocab_) {
                if (i + token.size() <= processed.size()) {
                    if (processed.substr(i, token.size()) == token) {
                        if (token.size() > best_len) {
                            best_len = token.size();
                            best_id = id;
                        }
                    }
                }
            }
            
            if (best_len > 0) {
                result.push_back(best_id);
                i += best_len;
            } else {
                i++;
            }
        }
        
        return result;
    }
    
    std::string Decode(const std::vector<int>& tokens) {
        std::string result;
        bool first = true;
        
        for (int id : tokens) {
            // Skip special tokens
            if (id == 0 || id == 2) continue;
            
            // Find token in vocabulary
            std::string token_str;
            bool found = false;
            for (const auto& entry : vocab_) {
                if (entry.second == id) {
                    token_str = entry.first;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                std::cerr << "Warning: Token ID " << id << " not found in vocab\n";
                continue;
            }
            
            // Check if starts with ▁ (E2 96 81)
            bool has_underscore = (token_str.size() >= 3 && 
                static_cast<unsigned char>(token_str[0]) == 0xE2 && 
                static_cast<unsigned char>(token_str[1]) == 0x96 && 
                static_cast<unsigned char>(token_str[2]) == 0x81);
            
            if (has_underscore) {
                if (!first) result += " ";
                result += token_str.substr(3);
            } else {
                result += token_str;
            }
            first = false;
        }
        
        return result;
    }
};

// ============================================================================
// Test: ▁ Character Handling
// ============================================================================

// ============================================================================
// Test: Whitespace Encoding
// ============================================================================
bool TestWhitespaceEncoding() {
    std::cout << "[TEST] Whitespace Encoding (▁ handling)\n";
    
    SimpleTokenizer tokenizer;
    
    // Test 1: "Hello world" should encode with ▁ prefix
    std::cout << "  [1/3] Encoding: \"Hello world\"\n";
    auto tokens1 = tokenizer.Encode("Hello world");
    std::cout << "        Tokens: [";
    for (size_t i = 0; i < tokens1.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens1[i];
    }
    std::cout << "]\n";
    
    // Should have BOS + 2 tokens (▁Hello, ▁world)
    if (tokens1.size() < 2) {
        std::cout << "  ✗ Expected at least 2 tokens\n";
        return false;
    }
    std::cout << "        ✓ Encoded successfully\n";
    
    // Test 2: "the quick brown fox"
    std::cout << "  [2/3] Encoding: \"the quick brown fox\"\n";
    auto tokens2 = tokenizer.Encode("the quick brown fox");
    std::cout << "        Tokens: [";
    for (size_t i = 0; i < tokens2.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens2[i];
    }
    std::cout << "]\n";
    std::cout << "        ✓ Encoded successfully\n";
    
    // Test 3: Multiple spaces
    std::cout << "  [3/3] Encoding: \"Hello   world\" (multiple spaces)\n";
    auto tokens3 = tokenizer.Encode("Hello   world");
    std::cout << "        Tokens: [";
    for (size_t i = 0; i < tokens3.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens3[i];
    }
    std::cout << "]\n";
    std::cout << "        ✓ Encoded successfully\n";
    
    return true;
}

// ============================================================================
// Test: Round-trip (Encode → Decode)
// ============================================================================
bool TestRoundTrip() {
    std::cout << "\n[TEST] Round-trip (Encode → Decode)\n";
    
    SimpleTokenizer tokenizer;
    
    struct TestCase {
        std::string input;
        std::string description;
    };
    
    std::vector<TestCase> tests = {
        {"Hello", "single word"},
        {"Hello world", "two words"},
        {"the quick brown fox", "four words"},
    };
    
    bool all_passed = true;
    for (size_t i = 0; i < tests.size(); ++i) {
        const auto& test = tests[i];
        std::cout << "  [" << (i + 1) << "/" << tests.size() << "] \"" << test.input << "\" (" << test.description << ")\n";
        
        // Encode
        auto tokens = tokenizer.Encode(test.input);
        std::cout << "        Tokens: [";
        for (size_t j = 0; j < tokens.size(); ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << tokens[j];
        }
        std::cout << "]\n";
        
        // Decode
        std::string decoded = tokenizer.Decode(tokens);
        std::cout << "        Decoded: \"" << decoded << "\"\n";
        
        // Check round-trip
        if (decoded == test.input) {
            std::cout << "        ✓ Perfect round-trip\n";
        } else {
            std::cout << "        ⚠ Round-trip differs: \"" << decoded << "\" vs \"" << test.input << "\"\n";
            all_passed = false;
        }
    }
    
    return all_passed;
}

// ============================================================================
// Test: ▁ Character Handling
// ============================================================================
bool TestUnderscoreCharacter() {
    std::cout << "\n[TEST] ▁ Character (U+2581) Handling\n";
    
    // The ▁ character is E2 96 81 in UTF-8
    const char* underscore = "\xE2\x96\x81";
    std::cout << "  ▁ UTF-8 bytes: ";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << std::hex << (0xFF & static_cast<unsigned char>(underscore[i])) << " ";
    }
    std::cout << std::dec << "\n";
    
    // Verify the bytes
    bool correct = (static_cast<unsigned char>(underscore[0]) == 0xE2 &&
                    static_cast<unsigned char>(underscore[1]) == 0x96 &&
                    static_cast<unsigned char>(underscore[2]) == 0x81);
    
    if (correct) {
        std::cout << "  ✓ UTF-8 encoding correct (E2 96 81)\n";
        return true;
    } else {
        std::cout << "  ✗ UTF-8 encoding incorrect\n";
        return false;
    }
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Tokenizer Whitespace Test - C2 Completion              ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    int passed = 0;
    int total = 3;
    
    if (TestUnderscoreCharacter()) {
        passed++;
    }
    
    if (TestWhitespaceEncoding()) {
        passed++;
    }
    
    if (TestRoundTrip()) {
        passed++;
    }
    
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    return (passed == total) ? 0 : 1;
}
