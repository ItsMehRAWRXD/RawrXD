// ============================================================================
// Sovereign Tokenizer Simple Test
// ============================================================================
// Standalone test of BPE tokenizer without SEG dependencies
// ============================================================================

#include <iostream>
#include <memory>
#include <chrono>
#include <vector>
#include <cstring>
#include <unordered_map>
#include <cctype>
#include <cstring>

// Minimal tokenizer interface
using TokenId = int32_t;
constexpr TokenId INVALID_TOKEN = -1;

// Simple BPE tokenizer stub for testing
class SimpleTokenizer {
public:
    virtual ~SimpleTokenizer() = default;
    virtual std::vector<TokenId> encode(const std::string& text) const = 0;
    virtual std::string decode(const std::vector<TokenId>& tokens) const = 0;
};

// ASCII fallback tokenizer
class ASCIITokenizer : public SimpleTokenizer {
public:
    std::vector<TokenId> encode(const std::string& text) const override {
        std::vector<TokenId> tokens;
        tokens.reserve(text.length());
        for (char c : text) {
            tokens.push_back(static_cast<TokenId>(static_cast<unsigned char>(c)));
        }
        return tokens;
    }
    
    std::string decode(const std::vector<TokenId>& tokens) const override {
        std::string text;
        text.reserve(tokens.size());
        for (TokenId id : tokens) {
            if (id >= 0 && id < 256) {
                text += static_cast<char>(id);
            }
        }
        return text;
    }
};

// Simple BPE-like tokenizer (word-level for demo)
class BPETokenizerSimple : public SimpleTokenizer {
public:
    std::vector<TokenId> encode(const std::string& text) const override {
        std::vector<TokenId> tokens;
        
        // Simple word-level tokenization
        std::string current;
        for (char c : text) {
            if (std::isspace(c)) {
                if (!current.empty()) {
                    tokens.push_back(get_word_id(current));
                    current.clear();
                }
                tokens.push_back(256 + c); // Space tokens
            } else {
                current += c;
            }
        }
        if (!current.empty()) {
            tokens.push_back(get_word_id(current));
        }
        
        return tokens;
    }
    
    std::string decode(const std::vector<TokenId>& tokens) const override {
        std::string text;
        for (TokenId id : tokens) {
            if (id >= 256) {
                text += static_cast<char>(id - 256);
            } else {
                text += id_to_word(id);
            }
        }
        return text;
    }
    
private:
    mutable std::unordered_map<std::string, TokenId> word_to_id_;
    mutable std::unordered_map<TokenId, std::string> id_to_word_;
    mutable TokenId next_id_ = 0;
    
    TokenId get_word_id(const std::string& word) const {
        auto it = word_to_id_.find(word);
        if (it != word_to_id_.end()) {
            return it->second;
        }
        TokenId id = next_id_++;
        word_to_id_[word] = id;
        id_to_word_[id] = word;
        return id;
    }
    
    std::string id_to_word(TokenId id) const {
        auto it = id_to_word_.find(id);
        if (it != id_to_word_.end()) {
            return it->second;
        }
        return "<?>";
    }
};

void PrintUsage() {
    std::cout << "Sovereign Tokenizer Simple Test\n"
              << "Usage: test_tokenizer_simple [options]\n"
              << "\nOptions:\n"
              << "  --text <text>        Text to tokenize (default: \"Hello world\")\n"
              << "  --bpe                Use BPE tokenizer (default: ASCII)\n"
              << "  --roundtrip          Test roundtrip\n";
}

int main(int argc, char* argv[]) {
    std::string text = "Hello world";
    bool use_bpe = false;
    bool roundtrip = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--text" && i + 1 < argc) {
            text = argv[++i];
        } else if (arg == "--bpe") {
            use_bpe = true;
        } else if (arg == "--roundtrip") {
            roundtrip = true;
        }
    }
    
    std::cout << "=== Sovereign Tokenizer Simple Test ===\n\n";
    
    // Create tokenizer
    std::unique_ptr<SimpleTokenizer> tokenizer;
    if (use_bpe) {
        tokenizer = std::make_unique<BPETokenizerSimple>();
        std::cout << "Tokenizer: BPE (word-level)\n";
    } else {
        tokenizer = std::make_unique<ASCIITokenizer>();
        std::cout << "Tokenizer: ASCII fallback\n";
    }
    
    std::cout << "Input: \"" << text << "\"\n\n";
    
    // Tokenize
    auto start = std::chrono::high_resolution_clock::now();
    auto tokens = tokenizer->encode(text);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Tokenized to " << tokens.size() << " tokens in " << duration.count() << " us\n";
    std::cout << "Tokens: [";
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << tokens[i];
    }
    std::cout << "]\n\n";
    
    // Roundtrip
    if (roundtrip) {
        start = std::chrono::high_resolution_clock::now();
        std::string output = tokenizer->decode(tokens);
        end = std::chrono::high_resolution_clock::now();
        
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        std::cout << "Detokenized in " << duration.count() << " us\n";
        std::cout << "Output: \"" << output << "\"\n";
        
        if (text == output) {
            std::cout << "✓ Roundtrip VALID\n";
        } else {
            std::cout << "⚠ Roundtrip DIFFERS\n";
        }
    }
    
    std::cout << "\n=== Test Complete ===\n";
    return 0;
}
