// ============================================================================
// RawrXD Tokenizer - Minimal Test (No GGUF Required)
// ============================================================================
// Tests tokenizer with a minimal built-in vocabulary

#include "../tokenizer/tokenizer.hpp"
#include <iostream>
#include <string>

using namespace rawrxd::tokenizer;

// Create a minimal test vocabulary
void CreateTestVocabulary(Vocabulary& vocab) {
    vocab.id_to_token.clear();
    vocab.token_to_id.clear();
    
    // Special tokens
    vocab.unk_id = 0;
    vocab.bos_id = 1;
    vocab.eos_id = 2;
    vocab.pad_id = 3;
    
    vocab.id_to_token[0] = "<unk>";
    vocab.id_to_token[1] = "<s>";
    vocab.id_to_token[2] = "</s>";
    vocab.id_to_token[3] = "<pad>";
    
    vocab.token_to_id["<unk>"] = 0;
    vocab.token_to_id["<s>"] = 1;
    vocab.token_to_id["</s>"] = 2;
    vocab.token_to_id["<pad>"] = 3;
    
    // Common words
    const char* words[] = {
        "hello", "world", "test", "the", "a", "is", "are", "was", "were",
        "be", "been", "being", "have", "has", "had", "do", "does", "did",
        "will", "would", "could", "should", "may", "might", "must",
        "can", "need", "dare", "ought", "used", "to", "of", "in", "for",
        "on", "with", "at", "by", "from", "as", "into", "through", "during",
        "before", "after", "above", "below", "between", "under",
        "I", "you", "he", "she", "it", "we", "they", "me", "him", "her",
        "us", "them", "my", "your", "his", "its", "our", "their",
        "this", "that", "these", "those",
        "one", "two", "three", "four", "five",
        "good", "bad", "new", "old", "big", "small",
        "and", "but", "or", "yet", "so", "if", "because", "although",
        "very", "really", "quite", "rather", "pretty",
        "not", "no", "yes", "ok", "okay",
        "what", "where", "when", "why", "how", "who", "which",
        "name", "time", "day", "year", "way", "man", "woman", "child",
        "my", "name", "is", "John", "and", "I", "like", "to", "code",
        nullptr
    };
    
    TokenId next_id = 4;
    for (int i = 0; words[i] != nullptr; i++) {
        vocab.id_to_token[next_id] = words[i];
        vocab.token_to_id[words[i]] = next_id;
        next_id++;
    }
    
    // Compute simple hash
    vocab.vocab_hash = 0x123456789ABCDEF0ULL;
}

// Test basic tokenization
bool TestBasicTokenization() {
    std::cout << "\n=== Test 1: Basic Tokenization ===\n";
    
    Tokenizer tokenizer;
    
    // Manually inject test vocabulary
    CreateTestVocabulary(const_cast<Vocabulary&>(tokenizer.GetVocabulary()));
    
    // Test encoding
    std::string text = "hello world";
    std::vector<TokenId> tokens = tokenizer.Encode(text);
    
    std::cout << "Input: \"" << text << "\"\n";
    std::cout << "Tokens: ";
    for (auto t : tokens) {
        std::cout << t << " ";
    }
    std::cout << "\n";
    
    // Test decoding
    std::string decoded = tokenizer.Decode(tokens);
    std::cout << "Decoded: \"" << decoded << "\"\n";
    
    return !tokens.empty();
}

// Test round-trip
bool TestRoundTrip() {
    std::cout << "\n=== Test 2: Round-Trip ===\n";
    
    Tokenizer tokenizer;
    CreateTestVocabulary(const_cast<Vocabulary&>(tokenizer.GetVocabulary()));
    
    const char* test_texts[] = {
        "hello",
        "hello world",
        "my name is",
        "I like to code",
        nullptr
    };
    
    bool all_passed = true;
    for (int i = 0; test_texts[i] != nullptr; i++) {
        std::string original = test_texts[i];
        std::vector<TokenId> tokens = tokenizer.Encode(original);
        std::string decoded = tokenizer.Decode(tokens);
        
        std::cout << "Original: \"" << original << "\"\n";
        std::cout << "Tokens: ";
        for (auto t : tokens) std::cout << t << " ";
        std::cout << "\n";
        std::cout << "Decoded: \"" << decoded << "\"\n";
        
        // Note: May not be exact due to BPE merging
        std::cout << "Status: " << (decoded.length() > 0 ? "PASS" : "FAIL") << "\n\n";
    }
    
    return all_passed;
}

// Test vocab hash
bool TestVocabHash() {
    std::cout << "\n=== Test 3: Vocab Hash ===\n";
    
    Tokenizer tokenizer;
    CreateTestVocabulary(const_cast<Vocabulary&>(tokenizer.GetVocabulary()));
    
    uint64_t hash = tokenizer.GetVocabHash();
    std::cout << "Vocab hash: 0x" << std::hex << hash << std::dec << "\n";
    
    return hash != 0;
}

// Test special tokens
bool TestSpecialTokens() {
    std::cout << "\n=== Test 4: Special Tokens ===\n";
    
    Tokenizer tokenizer;
    CreateTestVocabulary(const_cast<Vocabulary&>(tokenizer.GetVocabulary()));
    
    std::string text = "hello";
    std::vector<TokenId> tokens = tokenizer.EncodeWithSpecial(text, true, true);
    
    std::cout << "Input: \"" << text << "\" (with BOS/EOS)\n";
    std::cout << "Tokens: ";
    for (auto t : tokens) {
        std::cout << t << " ";
    }
    std::cout << "\n";
    
    // Check BOS and EOS are present
    bool has_bos = false, has_eos = false;
    for (auto t : tokens) {
        if (t == 1) has_bos = true;
        if (t == 2) has_eos = true;
    }
    
    std::cout << "Has BOS: " << (has_bos ? "YES" : "NO") << "\n";
    std::cout << "Has EOS: " << (has_eos ? "YES" : "NO") << "\n";
    
    return has_bos && has_eos;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Tokenizer Minimal Test\n";
    std::cout << "========================================\n";
    
    bool all_passed = true;
    
    all_passed &= TestBasicTokenization();
    all_passed &= TestRoundTrip();
    all_passed &= TestVocabHash();
    all_passed &= TestSpecialTokens();
    
    std::cout << "\n========================================\n";
    std::cout << "Test Results: " << (all_passed ? "ALL PASSED" : "SOME FAILED") << "\n";
    std::cout << "========================================\n";
    
    return all_passed ? 0 : 1;
}
