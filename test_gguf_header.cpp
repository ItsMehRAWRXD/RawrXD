// ============================================================================
// GGUF Header Validation Test
// ============================================================================
// Validates GGUF file headers and basic structure
// ============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <cstdint>

using namespace std;

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct ModelInfo {
    string name;
    string architecture;
    size_t file_size_gb;
    uint32_t tensor_count;
    bool valid;
};

bool ValidateGGUF(const string& path, ModelInfo& info) {
    ifstream file(path, ios::binary);
    if (!file) {
        info.valid = false;
        return false;
    }
    
    // Get file size
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);
    info.file_size_gb = file_size / (1024*1024*1024);
    if (file_size % (1024*1024*1024) > 512*1024*1024) info.file_size_gb++;
    
    // Read header
    GGUFHeader header;
    if (!file.read(reinterpret_cast<char*>(&header), sizeof(header))) {
        info.valid = false;
        return false;
    }
    
    if (header.magic != 0x46554747) {  // "GGUF"
        info.valid = false;
        return false;
    }
    
    info.valid = true;
    info.tensor_count = (uint32_t)header.tensor_count;
    
    // Try to read architecture from metadata
    // Skip metadata for now, just validate header
    info.architecture = "unknown";
    
    return true;
}

void PrintBanner() {
    cout << "========================================" << endl;
    cout << "GGUF Model Validation" << endl;
    cout << "========================================" << endl;
}

int main() {
    PrintBanner();
    
    vector<pair<string, string>> models = {
        {"llama3.2-3b-Q2_K.gguf", "Llama 3.2 3B (Q2_K)"},
        {"llama3.2-3b-Q3_K_S.gguf", "Llama 3.2 3B (Q3_K_S)"},
        {"gemma3-1b-Q2_K.gguf", "Gemma 3 1B (Q2_K)"},
        {"phi3-mini-Q2_K.gguf", "Phi-3 Mini (Q2_K)"}
    };
    
    int passed = 0;
    
    cout << "\nAvailable Models:\n" << endl;
    
    for (const auto& [filename, description] : models) {
        ModelInfo info;
        info.name = description;
        
        if (ValidateGGUF(filename, info)) {
            cout << "  ✓ " << left << setw(30) << description 
                 << " [" << info.file_size_gb << " GB, " 
                 << info.tensor_count << " tensors]" << endl;
            passed++;
        } else {
            cout << "  ✗ " << left << setw(30) << description 
                 << " [Not found or invalid]" << endl;
        }
    }
    
    cout << "\n========================================" << endl;
    cout << "Results: " << passed << "/" << models.size() << " models validated" << endl;
    cout << "========================================" << endl;
    
    if (passed > 0) {
        cout << "\n✓ GGUF format validation successful!" << endl;
        cout << "\nStep A Complete: Real models available" << endl;
        cout << "\nNext Steps:" << endl;
        cout << "  → Step D: F32 Reference Validation" << endl;
        cout << "  → Step E: Production Integration" << endl;
        return 0;
    } else {
        cout << "\n✗ No valid models found" << endl;
        return 1;
    }
}
