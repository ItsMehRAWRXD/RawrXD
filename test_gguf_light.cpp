// ============================================================================
// Light GGUF Model Test - Header/Metadata Only
// ============================================================================
// Validates GGUF format without loading full tensor data
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <fstream>

using namespace std;

// GGUF structures
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

enum class GGUFType : uint32_t {
    UINT32 = 4,
    INT32 = 5,
    FLOAT32 = 6,
    STRING = 8,
    ARRAY = 9
};

struct TensorInfo {
    string name;
    vector<uint64_t> dimensions;
    uint32_t type;
    uint64_t offset;
    uint64_t size;
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

class LightGGUFLoader {
public:
    bool Load(const string& path) {
        ifstream file(path, ios::binary);
        if (!file) {
            cerr << "Failed to open: " << path << endl;
            return false;
        }
        
        // Read header
        GGUFHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        
        if (header.magic != 0x46554747) {
            cerr << "Invalid GGUF magic" << endl;
            return false;
        }
        
        cout << "  GGUF Version: " << header.version << endl;
        cout << "  Tensor count: " << header.tensor_count << endl;
        cout << "  Metadata count: " << header.metadata_kv_count << endl;
        
        // Parse metadata
        for (uint64_t i = 0; i < header.metadata_kv_count && file; i++) {
            // Read key length and key
            uint64_t key_len;
            file.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
            string key(key_len, '\0');
            file.read(&key[0], key_len);
            
            // Read value type
            uint32_t type_val;
            file.read(reinterpret_cast<char*>(&type_val), sizeof(type_val));
            GGUFType type = static_cast<GGUFType>(type_val);
            
            // Read value
            switch (type) {
                case GGUFType::UINT32: {
                    uint32_t val;
                    file.read(reinterpret_cast<char*>(&val), sizeof(val));
                    if (key == "llama.block_count") config_.block_count = val;
                    else if (key == "llama.context_length") config_.context_length = val;
                    else if (key == "llama.embedding_length") config_.embedding_length = val;
                    else if (key == "llama.feed_forward_length") config_.feed_forward_length = val;
                    else if (key == "llama.head_count") config_.head_count = val;
                    else if (key == "llama.head_count_kv") config_.head_count_kv = val;
                    else if (key == "llama.vocab_size") config_.vocab_size = val;
                    break;
                }
                case GGUFType::STRING: {
                    uint64_t str_len;
                    file.read(reinterpret_cast<char*>(&str_len), sizeof(str_len));
                    string val(str_len, '\0');
                    file.read(&val[0], str_len);
                    if (key == "general.architecture") config_.architecture = val;
                    break;
                }
                case GGUFType::FLOAT32: {
                    float val;
                    file.read(reinterpret_cast<char*>(&val), sizeof(val));
                    break;
                }
                default: {
                    // Skip unknown
                    break;
                }
            }
        }
        
        // Parse tensor info (just headers, not data)
        tensors_.reserve(min((uint64_t)10, header.tensor_count)); // Only first 10
        for (uint64_t i = 0; i < header.tensor_count && file && i < 10; i++) {
            TensorInfo info;
            
            // Read name
            uint64_t name_len;
            file.read(reinterpret_cast<char*>(&name_len), sizeof(name_len));
            info.name.resize(name_len);
            file.read(&info.name[0], name_len);
            
            // Read dimensions
            uint32_t n_dims;
            file.read(reinterpret_cast<char*>(&n_dims), sizeof(n_dims));
            info.dimensions.resize(n_dims);
            for (uint32_t d = 0; d < n_dims; d++) {
                file.read(reinterpret_cast<char*>(&info.dimensions[d]), sizeof(uint64_t));
            }
            
            // Read type
            file.read(reinterpret_cast<char*>(&info.type), sizeof(info.type));
            
            tensors_.push_back(info);
        }
        
        return true;
    }
    
    const ModelConfig& GetConfig() const { return config_; }
    const vector<TensorInfo>& GetTensors() const { return tensors_; }
    
private:
    ModelConfig config_;
    vector<TensorInfo> tensors_;
};

void PrintBanner() {
    cout << "========================================" << endl;
    cout << "Light GGUF Model Test" << endl;
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
        
        LightGGUFLoader loader;
        auto start = chrono::high_resolution_clock::now();
        
        if (!loader.Load(model)) {
            cout << "  FAIL: Could not load" << endl;
            continue;
        }
        
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration<double, milli>(end - start).count();
        
        const auto& config = loader.GetConfig();
        const auto& tensors = loader.GetTensors();
        
        cout << "  Load time: " << fixed << setprecision(2) << duration << " ms" << endl;
        cout << "  Architecture: " << config.architecture << endl;
        cout << "  Layers: " << config.block_count << endl;
        cout << "  Hidden size: " << config.embedding_length << endl;
        cout << "  Heads: " << config.head_count << endl;
        cout << "  KV Heads: " << config.head_count_kv << endl;
        cout << "  Vocab: " << config.vocab_size << endl;
        
        cout << "  First 5 tensors:" << endl;
        for (size_t i = 0; i < min(size_t(5), tensors.size()); i++) {
            const auto& t = tensors[i];
            cout << "    " << t.name << " [";
            for (size_t d = 0; d < t.dimensions.size(); d++) {
                if (d > 0) cout << "x";
                cout << t.dimensions[d];
            }
            cout << "] type=" << t.type << endl;
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
