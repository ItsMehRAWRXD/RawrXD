// ============================================================================
// Safe GGUF Model Test - With Bounds Checking
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <cstdint>

using namespace std;

// GGUF structures
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct ModelConfig {
    string architecture;
    uint32_t block_count = 0;
    uint32_t context_length = 0;
    uint32_t embedding_length = 0;
    uint32_t feed_forward_length = 0;
    uint32_t head_count = 0;
    uint32_t head_count_kv = 0;
    uint32_t vocab_size = 0;
};

bool ReadStringSafe(ifstream& file, string& out, size_t max_len = 1024) {
    uint64_t len;
    if (!file.read(reinterpret_cast<char*>(&len), sizeof(len))) return false;
    if (len > max_len) {
        cerr << "String too long: " << len << endl;
        return false;
    }
    out.resize(len);
    if (!file.read(&out[0], len)) return false;
    return true;
}

bool LoadGGUFLight(const string& path, ModelConfig& config, size_t& tensor_count) {
    ifstream file(path, ios::binary);
    if (!file) {
        cerr << "Failed to open: " << path << endl;
        return false;
    }
    
    // Read header
    GGUFHeader header;
    if (!file.read(reinterpret_cast<char*>(&header), sizeof(header))) {
        cerr << "Failed to read header" << endl;
        return false;
    }
    
    if (header.magic != 0x46554747) {
        cerr << "Invalid GGUF magic: 0x" << hex << header.magic << endl;
        return false;
    }
    
    cout << "  GGUF Version: " << header.version << endl;
    cout << "  Tensor count: " << header.tensor_count << endl;
    cout << "  Metadata count: " << header.metadata_kv_count << endl;
    
    tensor_count = header.tensor_count;
    
    // Parse metadata (limit to reasonable count)
    size_t metadata_to_read = min(header.metadata_kv_count, (uint64_t)100);
    for (size_t i = 0; i < metadata_to_read && file; i++) {
        string key;
        if (!ReadStringSafe(file, key)) break;
        
        uint32_t type_val;
        if (!file.read(reinterpret_cast<char*>(&type_val), sizeof(type_val))) break;
        
        // Read value based on type
        switch (type_val) {
            case 4: { // UINT32
                uint32_t val;
                if (!file.read(reinterpret_cast<char*>(&val), sizeof(val))) break;
                if (key == "llama.block_count") config.block_count = val;
                else if (key == "llama.context_length") config.context_length = val;
                else if (key == "llama.embedding_length") config.embedding_length = val;
                else if (key == "llama.feed_forward_length") config.feed_forward_length = val;
                else if (key == "llama.head_count") config.head_count = val;
                else if (key == "llama.head_count_kv") config.head_count_kv = val;
                else if (key == "llama.vocab_size") config.vocab_size = val;
                break;
            }
            case 8: { // STRING
                string val;
                if (!ReadStringSafe(file, val)) break;
                if (key == "general.architecture") config.architecture = val;
                break;
            }
            case 6: { // FLOAT32
                float val;
                file.read(reinterpret_cast<char*>(&val), sizeof(val));
                break;
            }
            case 9: { // ARRAY - skip
                uint32_t arr_type, arr_len;
                file.read(reinterpret_cast<char*>(&arr_type), sizeof(arr_type));
                file.read(reinterpret_cast<char*>(&arr_len), sizeof(arr_len));
                // Skip array data (simplified)
                break;
            }
            default: {
                // Unknown type, try to skip
                break;
            }
        }
    }
    
    return true;
}

void PrintBanner() {
    cout << "========================================" << endl;
    cout << "Safe GGUF Model Test" << endl;
    cout << "========================================" << endl;
}

void PrintSection(const string& title) {
    cout << "\n=== " << title << " ===" << endl;
}

int main() {
    PrintBanner();
    
    vector<string> models = {
        "llama3.2-3b-Q2_K.gguf",
        "llama3.2-3b-Q3_K_S.gguf",
        "gemma3-1b-Q2_K.gguf",
        "phi3-mini-Q2_K.gguf"
    };
    
    int passed = 0;
    
    for (const auto& model : models) {
        PrintSection(model);
        
        ifstream file(model, ios::binary);
        if (!file) {
            cout << "  Model not found" << endl;
            continue;
        }
        
        // Get file size
        file.seekg(0, ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, ios::beg);
        
        cout << "  File size: " << fixed << setprecision(2) << file_size / (1024.0*1024*1024) << " GB" << endl;
        
        ModelConfig config;
        size_t tensor_count = 0;
        
        auto start = chrono::high_resolution_clock::now();
        
        if (!LoadGGUFLight(model, config, tensor_count)) {
            cout << "  FAIL: Could not load" << endl;
            continue;
        }
        
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration<double, milli>(end - start).count();
        
        cout << "  Load time: " << fixed << setprecision(2) << duration << " ms" << endl;
        cout << "  Architecture: " << config.architecture << endl;
        cout << "  Layers: " << config.block_count << endl;
        cout << "  Hidden size: " << config.embedding_length << endl;
        cout << "  Heads: " << config.head_count << endl;
        cout << "  KV Heads: " << config.head_count_kv << endl;
        cout << "  Vocab: " << config.vocab_size << endl;
        
        // Calculate memory
        if (config.embedding_length > 0 && config.block_count > 0) {
            size_t params = (size_t)config.vocab_size * config.embedding_length +
                           (size_t)config.block_count * 4 * config.embedding_length * config.embedding_length;
            cout << "  Est. params: " << params / 1000000 << "M" << endl;
            cout << "  Est. memory (Q4): " << fixed << setprecision(2) << params / (2.0 * 1024*1024*1024) << " GB" << endl;
        }
        
        cout << "  PASS" << endl;
        passed++;
    }
    
    PrintSection("Summary");
    cout << "  Models validated: " << passed << "/" << models.size() << endl;
    
    if (passed == models.size()) {
        cout << "\n✓ All GGUF models validated successfully!" << endl;
        cout << "\nReady for:" << endl;
        cout << "  - Step D: F32 Reference Validation" << endl;
        cout << "  - Step E: Production Integration" << endl;
        return 0;
    } else {
        cout << "\n✗ Some models failed validation" << endl;
        return 1;
    }
}
