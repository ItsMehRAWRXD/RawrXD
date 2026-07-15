/**
 * @file tensor_data_start.cpp
 * @brief Find exact tensor data section start
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <cmath>

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

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔍 Finding Tensor Data Section Start\n";
    cout << "=====================================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    // Read header
    uint32_t magic = read_le<uint32_t>(file);
    uint32_t version = read_le<uint32_t>(file);
    uint64_t n_tensors = read_le<uint64_t>(file);
    uint64_t n_kv = read_le<uint64_t>(file);
    
    cout << "Header:\n";
    cout << "  Magic: " << string((char*)&magic, 4) << "\n";
    cout << "  Version: " << version << "\n";
    cout << "  Tensors: " << n_tensors << "\n";
    cout << "  KV pairs: " << n_kv << "\n\n";
    
    // Skip all KV pairs
    cout << "Skipping " << n_kv << " KV pairs...\n";
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        skip_value(file, type);
    }
    
    size_t after_metadata = file.tellg();
    cout << "Position after metadata: " << after_metadata << "\n\n";
    
    // Read tensor directory
    cout << "Reading " << n_tensors << " tensor entries...\n";
    
    struct TensorEntry {
        string name;
        uint32_t n_dims;
        uint64_t offset;
    };
    
    vector<TensorEntry> entries;
    entries.reserve(n_tensors);
    
    for (uint64_t i = 0; i < n_tensors; i++) {
        TensorEntry entry;
        entry.name = read_str(file);
        entry.n_dims = read_le<uint32_t>(file);
        
        // Skip dimensions
        for (uint32_t d = 0; d < entry.n_dims; d++) {
            file.seekg(8, ios::cur);
        }
        
        // Skip type
        file.seekg(4, ios::cur);
        
        // Read offset
        entry.offset = read_le<uint64_t>(file);
        entries.push_back(entry);
    }
    
    size_t after_tensor_dir = file.tellg();
    cout << "Position after tensor directory: " << after_tensor_dir << "\n\n";
    
    // Calculate alignment
    // GGUF v3 aligns tensor data to 32 bytes
    size_t tensor_data_start = after_tensor_dir;
    size_t alignment = 32;
    if (tensor_data_start % alignment != 0) {
        tensor_data_start += alignment - (tensor_data_start % alignment);
    }
    
    cout << "Tensor data section:\n";
    cout << "  Raw end of directory: " << after_tensor_dir << "\n";
    cout << "  Aligned to " << alignment << " bytes: " << tensor_data_start << "\n";
    cout << "  Padding bytes: " << (tensor_data_start - after_tensor_dir) << "\n\n";
    
    // Show first few tensors with actual file offsets
    cout << "First 5 tensors (with actual file offsets):\n";
    for (int i = 0; i < min(5, (int)entries.size()); i++) {
        size_t actual_offset = tensor_data_start + entries[i].offset;
        cout << "  [" << i << "] " << entries[i].name;
        cout << " tensor.offset=" << entries[i].offset;
        cout << " file_offset=" << actual_offset << "\n";
    }
    
    // Verify by reading from tensor_data_start
    cout << "\nVerifying tensor data at file offset " << tensor_data_start << ":\n";
    file.seekg(tensor_data_start, ios::beg);
    
    // Read first Q4_0 block
    uint8_t block[18];
    file.read(reinterpret_cast<char*>(block), 18);
    
    uint16_t scale_bits = block[0] | (block[1] << 8);
    cout << "  First block scale bits: 0x" << hex << scale_bits << dec << "\n";
    
    uint16_t exp = (scale_bits >> 10) & 0x1F;
    uint16_t mant = scale_bits & 0x3FF;
    
    if (exp == 0) {
        cout << "  Scale: subnormal (exp=0)\n";
    } else if (exp == 31) {
        cout << "  Scale: inf/nan (exp=31)\n";
    } else {
        float scale = (1.0f + mant / 1024.0f) * pow(2.0f, exp - 15);
        if (scale_bits & 0x8000) scale = -scale;
        cout << "  Scale value: " << scale << "\n";
    }
    
    // Show raw bytes
    cout << "  Raw bytes: ";
    for (int i = 0; i < 18; i++) {
        cout << hex << setw(2) << setfill('0') << (int)block[i] << " ";
    }
    cout << dec << "\n";
    
    cout << "\n✅ Tensor data section starts at file offset: " << tensor_data_start << "\n";
    
    return 0;
}
