/**
 * @file find_tensor_data.cpp
 * @brief Find where tensor data actually starts
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <cmath>

using namespace std;

#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_kv;
};

struct TensorInfo {
    string name;
    uint32_t n_dims;
    vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
};
#pragma pack(pop)

string ReadString(ifstream& file) {
    uint64_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    string str(len, '\0');
    file.read(&str[0], len);
    return str;
}

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔍 Finding Tensor Data Start\n";
    cout << "=============================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    // Read header
    GGUFHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    cout << "Header:\n";
    cout << "  Magic: " << string((char*)&header.magic, 4) << "\n";
    cout << "  Version: " << header.version << "\n";
    cout << "  Tensors: " << header.n_tensors << "\n";
    cout << "  KV pairs: " << header.n_kv << "\n\n";
    
    // Skip metadata
    for (uint64_t i = 0; i < header.n_kv; i++) {
        ReadString(file); // key
        uint32_t type;
        file.read(reinterpret_cast<char*>(&type), sizeof(type));
        
        // Skip value based on type
        switch (type) {
            case 0: { uint8_t v; file.read(reinterpret_cast<char*>(&v), 1); } break;
            case 1: { int8_t v; file.read(reinterpret_cast<char*>(&v), 1); } break;
            case 2: { uint8_t v; file.read(reinterpret_cast<char*>(&v), 1); } break;
            case 3: { int8_t v; file.read(reinterpret_cast<char*>(&v), 1); } break;
            case 4: { int16_t v; file.read(reinterpret_cast<char*>(&v), 2); } break;
            case 5: { uint16_t v; file.read(reinterpret_cast<char*>(&v), 2); } break;
            case 6: { int32_t v; file.read(reinterpret_cast<char*>(&v), 4); } break;
            case 7: { uint32_t v; file.read(reinterpret_cast<char*>(&v), 4); } break;
            case 8: { int32_t v; file.read(reinterpret_cast<char*>(&v), 4); } break;
            case 9: { uint32_t v; file.read(reinterpret_cast<char*>(&v), 4); } break;
            case 10: { float v; file.read(reinterpret_cast<char*>(&v), 4); } break;
            case 11: { uint64_t v; file.read(reinterpret_cast<char*>(&v), 8); } break;
            case 12: { int64_t v; file.read(reinterpret_cast<char*>(&v), 8); } break;
            case 13: { uint64_t len; file.read(reinterpret_cast<char*>(&len), 8); file.seekg(len, ios::cur); } break;
            case 14: {
                uint64_t len;
                file.read(reinterpret_cast<char*>(&len), 8);
                for (uint64_t j = 0; j < len; j++) ReadString(file);
                break;
            }
            case 15: {
                uint64_t len;
                file.read(reinterpret_cast<char*>(&len), 8);
                file.seekg(len, ios::cur);
                break;
            }
            case 16: {
                uint64_t len;
                file.read(reinterpret_cast<char*>(&len), 8);
                for (uint64_t j = 0; j < len; j++) {
                    ReadString(file);
                    uint32_t t; file.read(reinterpret_cast<char*>(&t), 4);
                    switch (t) {
                        case 0: case 1: case 2: case 3: file.seekg(1, ios::cur); break;
                        case 4: case 5: case 8: case 9: file.seekg(4, ios::cur); break;
                        case 6: case 7: case 10: file.seekg(4, ios::cur); break;
                        case 11: case 12: file.seekg(8, ios::cur); break;
                        case 13: { uint64_t l; file.read(reinterpret_cast<char*>(&l), 8); file.seekg(l, ios::cur); } break;
                    }
                }
                break;
            }
            default: {
                cout << "Unknown type " << type << " at KV " << i << "\n";
                return 1;
            }
        }
    }
    
    size_t metadata_end = file.tellg();
    cout << "Metadata ends at: " << metadata_end << "\n\n";
    
    // Read tensor directory
    vector<TensorInfo> tensors;
    for (uint64_t i = 0; i < header.n_tensors; i++) {
        TensorInfo info;
        info.name = ReadString(file);
        file.read(reinterpret_cast<char*>(&info.n_dims), sizeof(info.n_dims));
        info.dims.resize(info.n_dims);
        for (uint32_t d = 0; d < info.n_dims; d++) {
            file.read(reinterpret_cast<char*>(&info.dims[d]), sizeof(uint64_t));
        }
        file.read(reinterpret_cast<char*>(&info.type), sizeof(info.type));
        file.read(reinterpret_cast<char*>(&info.offset), sizeof(info.offset));
        tensors.push_back(info);
    }
    
    size_t tensor_dir_end = file.tellg();
    cout << "Tensor directory ends at: " << tensor_dir_end << "\n";
    cout << "First tensor offset: " << tensors[0].offset << "\n";
    cout << "Last tensor offset: " << tensors.back().offset << "\n\n";
    
    // Calculate where tensor data should start
    // In GGUF v3, tensor data is aligned to 32 bytes
    size_t tensor_data_start = tensor_dir_end;
    if (tensor_data_start % 32 != 0) {
        tensor_data_start += 32 - (tensor_data_start % 32);
    }
    
    cout << "Tensor data section starts at: " << tensor_data_start << "\n";
    cout << "  (aligned to 32 bytes)\n\n";
    
    // Show first few tensors
    cout << "First 5 tensors:\n";
    for (int i = 0; i < min(5, (int)tensors.size()); i++) {
        cout << "  [" << i << "] " << tensors[i].name;
        cout << " [";
        for (size_t d = 0; d < tensors[i].dims.size(); d++) {
            if (d > 0) cout << ", ";
            cout << tensors[i].dims[d];
        }
        cout << "] type=" << tensors[i].type;
        cout << " offset=" << tensors[i].offset;
        
        // Calculate actual file offset
        size_t actual_offset = tensor_data_start + tensors[i].offset;
        cout << " -> file_offset=" << actual_offset;
        cout << "\n";
    }
    
    // Verify by reading from tensor_data_start
    cout << "\nVerifying tensor data at offset " << tensor_data_start << ":\n";
    file.seekg(tensor_data_start, ios::beg);
    
    uint8_t buffer[64];
    file.read(reinterpret_cast<char*>(buffer), 64);
    
    cout << "  First 64 bytes:\n";
    for (int row = 0; row < 4; row++) {
        cout << "    ";
        for (int col = 0; col < 16; col++) {
            cout << hex << setw(2) << setfill('0') << (int)buffer[row * 16 + col] << " ";
        }
        cout << "\n";
    }
    
    // Interpret first 2 bytes as FP16
    uint16_t scale_bits = buffer[0] | (buffer[1] << 8);
    cout << "\n  First 2 bytes as FP16 bits: 0x" << hex << scale_bits << dec << "\n";
    
    // Check if it looks like a reasonable scale
    uint16_t exp = (scale_bits >> 10) & 0x1F;
    uint16_t mant = scale_bits & 0x3FF;
    
    if (exp == 0) {
        cout << "  Interpretation: subnormal number\n";
    } else if (exp == 31) {
        cout << "  Interpretation: infinity or NaN\n";
    } else {
        float scale = pow(2.0f, (int)exp - 15) * (1.0f + mant / 1024.0f);
        if (scale_bits & 0x8000) scale = -scale;
        cout << "  Interpretation: scale = " << scale << "\n";
    }
    
    return 0;
}
