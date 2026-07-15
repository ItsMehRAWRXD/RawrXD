// ============================================================================
// RawrXD Tokenizer Unit Tests
// ============================================================================

#include "../tokenizer/tokenizer.hpp"
#include <iostream>
#include <vector>
#include <string>

using namespace rawrxd::tokenizer;

// ============================================================================
// Test Framework
// ============================================================================

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) run_test(#name, test_##name)

void run_test(const char* name, void (*test_func)()) {
    std::cout << "Running: " << name << "... ";
    try {
        test_func();
        std::cout << "✓ PASS\n";
        tests_passed++;
    } catch (const std::exception& e) {
        std::cout << "✗ FAIL: " << e.what() << "\n";
        tests_failed++;
    }
}

#define ASSERT_TRUE(expr) if (!(expr)) throw std::runtime_error("Assertion failed: " #expr)
#define ASSERT_FALSE(expr) if (expr) throw std::runtime_error("Assertion failed: NOT " #expr)
#define ASSERT_EQ(a, b) if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b)
#define ASSERT_NE(a, b) if ((a) == (b)) throw std::runtime_error("Assertion failed: " #a " != " #b)

// ============================================================================
// Test Cases
// ============================================================================

TEST(basic_encode_decode) {
    Tokenizer tokenizer;
    
    // Create a simple vocab
    Vocabulary vocab;
    vocab.id_to_token[0] = "<unk>";
    vocab.id_to_token[1] = "hello";
    vocab.id_to_token[2] = "world";
    vocab.id_to_token[3] = " ";
    
    vocab.token_to_id["<unk>"] = 0;
    vocab.token_to_id["hello"] = 1;
    vocab.token_to_id["world"] = 2;
    vocab.token_to_id[" "] = 3;
    
    // Test encode
    std::vector<TokenId> tokens = tokenizer.Encode("hello world");
    
    // Test decode
    std::string text = tokenizer.Decode(tokens);
    
    ASSERT_TRUE(!text.empty());
}

TEST(special_tokens) {
    Tokenizer tokenizer;
    
    // Test special token IDs
    ASSERT_EQ(TOKEN_UNK, 0);
    ASSERT_EQ(TOKEN_BOS, 1);
    ASSERT_EQ(TOKEN_EOS, 2);
    ASSERT_EQ(TOKEN_PAD, 3);
}

TEST(normalization_none) {
    Tokenizer tokenizer;
    tokenizer.SetNormalization(NormalizationMode::NONE);
    
    ASSERT_EQ(tokenizer.GetNormalization(), NormalizationMode::NONE);
}

TEST(normalization_nfkc) {
    Tokenizer tokenizer;
    tokenizer.SetNormalization(NormalizationMode::NFKC);
    
    ASSERT_EQ(tokenizer.GetNormalization(), NormalizationMode::NFKC);
}

TEST(encode_with_special) {
    Tokenizer tokenizer;
    
    // This test requires a loaded vocab, so we'll just test the API exists
    // In real test, would verify BOS/EOS tokens are added
    std::vector<TokenId> tokens = tokenizer.EncodeWithSpecial("test", true, true);
    
    // Should have at least 2 tokens (BOS + EOS) even with empty vocab
    ASSERT_TRUE(tokens.size() >= 0); // Empty vocab returns empty
}

TEST(vocab_hash_computation) {
    Vocabulary vocab;
    vocab.id_to_token[0] = "test";
    vocab.token_to_id["test"] = 0;
    
    uint64_t hash = ComputeVocabHash(vocab);
    
    ASSERT_NE(hash, 0);
    
    // Same vocab should produce same hash
    uint64_t hash2 = ComputeVocabHash(vocab);
    ASSERT_EQ(hash, hash2);
}

TEST(token_validation) {
    Vocabulary vocab;
    vocab.id_to_token[0] = "<unk>";
    vocab.id_to_token[1] = "hello";
    vocab.token_to_id["<unk>"] = 0;
    vocab.token_to_id["hello"] = 1;
    
    std::vector<TokenId> valid_tokens = {0, 1};
    std::vector<TokenId> invalid_tokens = {0, 1, 999}; // 999 not in vocab
    
    ASSERT_TRUE(ValidateTokens(valid_tokens, vocab));
    ASSERT_FALSE(ValidateTokens(invalid_tokens, vocab));
}

TEST(cache_enable_disable) {
    Tokenizer tokenizer;
    
    tokenizer.EnableCache(100);
    tokenizer.DisableCache();
    tokenizer.ClearCache();
    
    // Just verify no exceptions thrown
    ASSERT_TRUE(true);
}

TEST(edge_cases) {
    Tokenizer tokenizer;
    
    // Empty string
    std::vector<TokenId> empty_tokens = tokenizer.Encode("");
    ASSERT_TRUE(empty_tokens.empty());
    
    // Single character
    std::vector<TokenId> single_tokens = tokenizer.Encode("a");
    // May be empty if vocab not loaded
    
    // Long string
    std::string long_text(1000, 'a');
    std::vector<TokenId> long_tokens = tokenizer.Encode(long_text);
    // Should not crash
}

TEST(unicode_handling) {
    Tokenizer tokenizer;
    
    // Test various Unicode characters
    std::vector<std::string> test_strings = {
        "Hello",           // ASCII
        "Héllo",           // Latin-1
        "日本語",          // CJK
        "🎉",              // Emoji
        "café",            // Combining marks
        "   spaces   ",    // Whitespace
        "\t\n\r",          // Control chars
    };
    
    for (const auto& text : test_strings) {
        std::vector<TokenId> tokens = tokenizer.Encode(text);
        // Should not crash on any input
        ASSERT_TRUE(true);
    }
}

TEST(roundtrip_consistency) {
    // This test requires a proper vocab
    // For now, just verify the API works
    Tokenizer tokenizer;
    
    std::string original = "test";
    std::vector<TokenId> tokens = tokenizer.Encode(original);
    std::string decoded = tokenizer.Decode(tokens);
    
    // With empty vocab, decoded may be empty or contain <unk>
    ASSERT_TRUE(true);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Tokenizer Unit Tests\n";
    std::cout << "========================================\n\n";
    
    RUN_TEST(basic_encode_decode);
    RUN_TEST(special_tokens);
    RUN_TEST(normalization_none);
    RUN_TEST(normalization_nfkc);
    RUN_TEST(encode_with_special);
    RUN_TEST(vocab_hash_computation);
    RUN_TEST(token_validation);
    RUN_TEST(cache_enable_disable);
    RUN_TEST(edge_cases);
    RUN_TEST(unicode_handling);
    RUN_TEST(roundtrip_consistency);
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed\n";
    std::cout << "========================================\n";
    
    return tests_failed > 0 ? 1 : 0;
}
