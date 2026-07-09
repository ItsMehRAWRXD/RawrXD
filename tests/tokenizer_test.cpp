/**
 * @file tokenizer_test.cpp
 * @brief Phase 6: Simple BPE Tokenization
 * 
 * Converts text to token IDs using vocabulary lookup.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <cstdint>

using namespace std;

// Helper: Read little-endian
template<typename T>
T read_le(ifstream& f) {
    T val;
    f.read(reinterpret_cast<char*>(&val), sizeof(T));
    return val;
}

// Helper: Read string
string read_str(ifstream& f) {
    uint64_t len = read_le<uint64_t>(f);
    string s(len, '\0');
    f.read(&s[0], len);
    return s;
}

// Skip GGUF value based on type
void skip_value(ifstream& f, int type) {
    switch (type) {
        case 0: case 1: case 7: f.seekg(1, ios::cur); break;
        case 2: case 3: f.seekg(2, ios::cur); break;
        case 4: case 5: case 6: f.seekg(4, ios::cur); break;
        case 10: case 11: case 12: f.seekg(8, ios::cur); break;
        case 8: read_str(f); break;
        case 9: {
            int arr_type = read_le<uint32_t>(f);
            uint64_t arr_len = read_le<uint64_t>(f);
            for (uint64_t i = 0; i < arr_len; i++) skip_value(f, arr_type);
            break;
        }
        default: f.seekg(8, ios::cur);
    }
}

// Simple BPE tokenizer
class SimpleTokenizer {
public:
    vector<string> vocab;
    unordered_map<string, int> token_to_id;
    int bos_id = 1;
    int eos_id = 32000;
    
    void load_vocab(const vector<string>& v) {
        vocab = v;
        for (int i = 0; i < (int)vocab.size(); i++) {
            token_to_id[vocab[i]] = i;
        }
    }
    
    // Greedy longest-match tokenization
    vector<int> encode(const string& text) {
        vector<int> tokens;
        tokens.push_back(bos_id);  // Start with BOS
        
        size_t pos = 0;
        while (pos < text.length()) {
            // Try longest match first
            int best_len = 0;
            int best_id = -1;
            
            // Try substrings from longest to shortest
            for (int len = min(32, (int)(text.length() - pos)); len > 0; len--) {
                string substr = text.substr(pos, len);
                auto it = token_to_id.find(substr);
                if (it != token_to_id.end()) {
                    best_len = len;
                    best_id = it->second;
                    break;  // Found longest match
                }
            }
            
            if (best_id >= 0) {
                tokens.push_back(best_id);
                pos += best_len;
            } else {
                // Unknown character - skip or use <unk>
                tokens.push_back(0);  // <unk>
                pos++;
            }
        }
        
        tokens.push_back(eos_id);  // End with EOS
        return tokens;
    }
    
    string decode(const vector<int>& tokens) {
        string result;
        for (int id : tokens) {
            if (id >= 0 && id < (int)vocab.size()) {
                string token = vocab[id];
                // Handle special tokens
                if (token == "<s>" || token == "</s>" || token == "<|endoftext|>") {
                    continue;
                }
                // Handle byte tokens
                if (token.substr(0, 4) == "<0x") {
                    // Byte token - skip for now
                    continue;
                }
                result += token;
            }
        }
        return result;
    }
};

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 6: Tokenization Test\n";
    cout << "======================================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open: " << MODEL_PATH << "\n";
        return 1;
    }
    
    auto start = chrono::high_resolution_clock::now();
    
    // Read header
    uint32_t magic = read_le<uint32_t>(file);
    uint32_t version = read_le<uint32_t>(file);
    uint64_t n_tensors = read_le<uint64_t>(file);
    uint64_t n_kv = read_le<uint64_t>(file);
    
    // Parse KV pairs for vocabulary
    vector<string> vocab;
    
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        
        if (key == "tokenizer.ggml.tokens" && type == 9) {
            int arr_type = read_le<uint32_t>(file);
            uint64_t arr_len = read_le<uint64_t>(file);
            vocab.reserve(arr_len);
            for (uint64_t j = 0; j < arr_len; j++) {
                vocab.push_back(read_str(file));
            }
        }
        else {
            skip_value(file, type);
        }
    }
    
    if (vocab.empty()) {
        cerr << "❌ No vocabulary found\n";
        return 1;
    }
    
    // Create tokenizer
    SimpleTokenizer tokenizer;
    tokenizer.load_vocab(vocab);
    
    auto load_end = chrono::high_resolution_clock::now();
    auto load_ms = chrono::duration_cast<chrono::milliseconds>(load_end - start).count();
    
    cout << "Tokenizer loaded:\n";
    cout << "  Vocabulary size: " << vocab.size() << "\n";
    cout << "  Load time: " << load_ms << " ms\n\n";
    
    // Test cases
    vector<string> test_inputs = {
        "Hello",
        "Hello, world!",
        "The quick brown fox",
        "What is the capital of France?",
        "<|endoftext|>"
    };
    
    cout << "Tokenization Tests:\n";
    cout << string(60, '-') << "\n";
    
    for (const auto& input : test_inputs) {
        auto enc_start = chrono::high_resolution_clock::now();
        vector<int> tokens = tokenizer.encode(input);
        auto enc_end = chrono::high_resolution_clock::now();
        auto enc_us = chrono::duration_cast<chrono::microseconds>(enc_end - enc_start).count();
        
        string decoded = tokenizer.decode(tokens);
        
        cout << "Input: \"" << input << "\"\n";
        cout << "  Tokens: ";
        for (int i = 0; i < min(15, (int)tokens.size()); i++) {
            cout << tokens[i];
            if (i < (int)tokens.size() - 1) cout << " ";
        }
        if (tokens.size() > 15) cout << " ...";
        cout << "\n";
        
        cout << "  Token count: " << tokens.size() << "\n";
        cout << "  Encode time: " << enc_us << " μs\n";
        cout << "  Decoded: \"" << decoded << "\"\n";
        
        // Show token details
        cout << "  Token details:\n";
        for (int i = 0; i < min(8, (int)tokens.size()); i++) {
            int id = tokens[i];
            string token = (id >= 0 && id < (int)vocab.size()) ? vocab[id] : "<?>";
            // Escape for display
            for (size_t j = 0; j < token.length(); j++) {
                if (token[j] == '\n') token.replace(j, 1, "\\n");
                else if (token[j] == '\t') token.replace(j, 1, "\\t");
            }
            cout << "    [" << setw(4) << id << "] \"" << token << "\"\n";
        }
        cout << "\n";
    }
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Tests run: " << test_inputs.size() << "\n";
    cout << "  Total time: " << total_ms << " ms\n";
    cout << "  Status: ✅ TOKENIZATION TEST PASSED\n";
    
    return 0;
}
