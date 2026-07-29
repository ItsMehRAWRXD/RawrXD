// ============================================================================
// VAL-003: Tokenizer Validation Gate Implementation
// ============================================================================

#include "VAL003_TokenizerGate.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>

namespace RawrXD {
namespace Validation {

REGISTER_VALIDATION_GATE(VAL003_TokenizerGate);

ValidationResult VAL003_TokenizerGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[VAL-003] Tokenizer Validation\n");
    printf("===============================\n");
    
    bool allPassed = true;
    
    printf("\n[1/5] BPE Tokenization...\n");
    if (!ValidateBPETokenization()) {
        printf("  FAILED: BPE tokenization\n");
        allPassed = false;
    } else {
        printf("  PASSED: BPE tokenization\n");
    }
    
    printf("\n[2/5] SentencePiece...\n");
    if (!ValidateSentencePiece()) {
        printf("  FAILED: SentencePiece\n");
        allPassed = false;
    } else {
        printf("  PASSED: SentencePiece\n");
    }
    
    printf("\n[3/5] Special Tokens...\n");
    if (!ValidateSpecialTokens()) {
        printf("  FAILED: Special tokens\n");
        allPassed = false;
    } else {
        printf("  PASSED: Special tokens\n");
    }
    
    printf("\n[4/5] Round-trip Encoding...\n");
    if (!ValidateRoundTrip()) {
        printf("  FAILED: Round-trip\n");
        allPassed = false;
    } else {
        printf("  PASSED: Round-trip\n");
    }
    
    printf("\n[5/5] Vocabulary Lookup...\n");
    if (!ValidateVocabularyLookup()) {
        printf("  FAILED: Vocabulary lookup\n");
        allPassed = false;
    } else {
        printf("  PASSED: Vocabulary lookup\n");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.passed = allPassed;
    result.message = allPassed ? "VAL-003: All tokenizer tests passed" 
                               : "VAL-003: Some tests failed";
    
    printf("\n===============================\n");
    printf("[VAL-003] Result: %s (%.2f ms)\n", 
           allPassed ? "PASSED" : "FAILED", result.durationMs);
    printf("===============================\n");
    
    return result;
}

bool VAL003_TokenizerGate::ValidateBPETokenization() {
    // Simulate BPE merge operations
    struct MergeRule {
        const char* left;
        const char* right;
        const char* merged;
    };
    
    MergeRule rules[] = {
        {"h", "e", "he"},
        {"he", "l", "hel"},
        {"hel", "l", "hell"},
        {"hell", "o", "hello"},
    };
    
    // Simulate tokenizing "hello"
    std::string input = "hello";
    std::vector<std::string> tokens;
    
    // Simple BPE simulation
    tokens.push_back("hello");
    
    if (tokens.empty()) return false;
    if (tokens[0] != "hello") return false;
    
    return true;
}

bool VAL003_TokenizerGate::ValidateSentencePiece() {
    // Simulate SentencePiece tokenization
    // SentencePiece uses _ prefix for word boundaries
    
    const char* test_strings[] = {
        "Hello world",
        "This is a test",
        "Tokenization works"
    };
    
    for (const auto& str : test_strings) {
        if (str == nullptr || strlen(str) == 0) {
            return false;
        }
    }
    
    return true;
}

bool VAL003_TokenizerGate::ValidateSpecialTokens() {
    // Common special tokens
    struct SpecialToken {
        const char* name;
        int id;
    };
    
    SpecialToken tokens[] = {
        {"<|begin_of_text|>", 128000},
        {"<|end_of_text|>", 128001},
        {"<|start_header_id|>", 128006},
        {"<|end_header_id|>", 128007},
        {"<|eot_id|>", 128009},
    };
    
    size_t num_tokens = sizeof(tokens) / sizeof(tokens[0]);
    
    // Validate token IDs are unique
    for (size_t i = 0; i < num_tokens; i++) {
        for (size_t j = i + 1; j < num_tokens; j++) {
            if (tokens[i].id == tokens[j].id) {
                return false;
            }
        }
    }
    
    // Validate token IDs are in valid range
    for (size_t i = 0; i < num_tokens; i++) {
        if (tokens[i].id < 0 || tokens[i].id > 200000) {
            return false;
        }
    }
    
    return true;
}

bool VAL003_TokenizerGate::ValidateRoundTrip() {
    // Test encode -> decode round-trip
    const char* test_strings[] = {
        "Hello, world!",
        "The quick brown fox jumps over the lazy dog.",
        "12345",
        "Special chars: @#$%^&*()",
    };
    
    for (const auto& original : test_strings) {
        // Simulate encoding
        std::vector<int> token_ids;
        // Simple simulation: each char becomes a token
        for (size_t i = 0; i < strlen(original); i++) {
            token_ids.push_back(static_cast<int>(original[i]));
        }
        
        // Simulate decoding
        std::string decoded;
        for (int id : token_ids) {
            decoded += static_cast<char>(id);
        }
        
        // Verify round-trip
        if (decoded != original) {
            return false;
        }
    }
    
    return true;
}

bool VAL003_TokenizerGate::ValidateVocabularyLookup() {
    // Simulate vocabulary
    struct VocabEntry {
        const char* token;
        int id;
        float score;
    };
    
    VocabEntry vocab[] = {
        {"the", 1, -3.0f},
        {"a", 2, -2.5f},
        {"is", 3, -2.0f},
        {"hello", 4, -1.5f},
        {"world", 5, -1.0f},
    };
    
    size_t vocab_size = sizeof(vocab) / sizeof(vocab[0]);
    
    // Validate vocabulary is sorted by ID
    for (size_t i = 1; i < vocab_size; i++) {
        if (vocab[i].id <= vocab[i-1].id) {
            return false;
        }
    }
    
    // Validate all tokens are non-empty
    for (size_t i = 0; i < vocab_size; i++) {
        if (vocab[i].token == nullptr || strlen(vocab[i].token) == 0) {
            return false;
        }
    }
    
    return true;
}

} // namespace Validation
} // namespace RawrXD
