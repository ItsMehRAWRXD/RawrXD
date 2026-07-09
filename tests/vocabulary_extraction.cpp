/**
 * @file vocabulary_extraction.cpp
 * @brief Phase 5: Vocabulary Extraction from GGUF
 * 
 * Extracts the tokenizer vocabulary to enable text → token conversion.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
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

// Skip GGUF value based on type, return true if array of strings (vocab)
bool skip_value(ifstream& f, int type, vector<string>* out_strings = nullptr) {
    switch (type) {
        case 0: case 1: case 7: f.seekg(1, ios::cur); break;
        case 2: case 3: f.seekg(2, ios::cur); break;
        case 4: case 5: case 6: f.seekg(4, ios::cur); break;
        case 10: case 11: case 12: f.seekg(8, ios::cur); break;
        case 8: {
            string s = read_str(f);
            if (out_strings) out_strings->push_back(s);
            break;
        }
        case 9: {
            int arr_type = read_le<uint32_t>(f);
            uint64_t arr_len = read_le<uint64_t>(f);
            for (uint64_t i = 0; i < arr_len; i++) {
                skip_value(f, arr_type, out_strings);
            }
            break;
        }
        default: f.seekg(8, ios::cur);
    }
    return false;
}

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 5: Vocabulary Extraction\n";
    cout << "=========================================\n\n";
    
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
    
    cout << "GGUF Header:\n";
    cout << "  Magic: " << string((char*)&magic, 4) << "\n";
    cout << "  Version: " << version << "\n";
    cout << "  KV pairs: " << n_kv << "\n\n";
    
    // Parse KV pairs looking for vocabulary
    vector<string> vocab;
    uint32_t vocab_size = 0;
    uint32_t bos_token = 0, eos_token = 0, pad_token = 0;
    
    cout << "Parsing metadata for vocabulary...\n";
    
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        
        if (key == "tokenizer.ggml.tokens" && type == 9) {
            // Array of strings - this is the vocabulary
            int arr_type = read_le<uint32_t>(file);
            uint64_t arr_len = read_le<uint64_t>(file);
            vocab_size = (uint32_t)arr_len;
            
            cout << "  Found vocabulary: " << vocab_size << " tokens\n";
            vocab.reserve(vocab_size);
            
            for (uint64_t j = 0; j < arr_len; j++) {
                string token = read_str(file);
                vocab.push_back(token);
            }
        }
        else if (key == "tokenizer.ggml.bos_token_id" && type == 4) {
            bos_token = read_le<uint32_t>(file);
            cout << "  BOS token ID: " << bos_token << "\n";
        }
        else if (key == "tokenizer.ggml.eos_token_id" && type == 4) {
            eos_token = read_le<uint32_t>(file);
            cout << "  EOS token ID: " << eos_token << "\n";
        }
        else if (key == "tokenizer.ggml.padding_token_id" && type == 4) {
            pad_token = read_le<uint32_t>(file);
            cout << "  PAD token ID: " << pad_token << "\n";
        }
        else {
            skip_value(file, type);
        }
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    
    cout << "\n" << string(50, '=') << "\n";
    
    if (vocab.empty()) {
        cout << "❌ No vocabulary found in GGUF\n";
        return 1;
    }
    
    // Show sample tokens
    cout << "Vocabulary Sample:\n";
    cout << "  First 20 tokens:\n";
    for (int i = 0; i < min(20, (int)vocab.size()); i++) {
        string display = vocab[i];
        // Escape special characters
        for (size_t j = 0; j < display.length(); j++) {
            if (display[j] == '\n') display.replace(j, 1, "\\n");
            else if (display[j] == '\t') display.replace(j, 1, "\\t");
            else if (display[j] == '\r') display.replace(j, 1, "\\r");
        }
        cout << "    [" << setw(4) << i << "] \"" << display << "\"\n";
    }
    
    cout << "\n  Special tokens:\n";
    cout << "    BOS: [" << bos_token << "] \"" << vocab[bos_token] << "\"\n";
    cout << "    EOS: [" << eos_token << "] \"" << vocab[eos_token] << "\"\n";
    if (pad_token < vocab.size()) {
        cout << "    PAD: [" << pad_token << "] \"" << vocab[pad_token] << "\"\n";
    }
    
    // Sample some common tokens
    cout << "\n  Common word tokens:\n";
    vector<pair<string, int>> samples = {
        {"the", -1}, {"a", -1}, {"is", -1}, {"of", -1}, {"to", -1},
        {"and", -1}, {"in", -1}, {"that", -1}, {"have", -1}, {"it", -1}
    };
    
    for (int i = 0; i < (int)vocab.size() && samples.size() > 0; i++) {
        for (auto& s : samples) {
            if (s.second == -1 && vocab[i] == s.first) {
                s.second = i;
                break;
            }
        }
    }
    
    for (const auto& s : samples) {
        if (s.second >= 0) {
            cout << "    \"" << s.first << "\" -> [" << s.second << "]\n";
        }
    }
    
    cout << "\n" << string(50, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Vocabulary size: " << vocab.size() << "\n";
    cout << "  Extraction time: " << ms << " ms\n";
    cout << "  Status: ✅ VOCABULARY EXTRACTION PASSED\n";
    
    return 0;
}
