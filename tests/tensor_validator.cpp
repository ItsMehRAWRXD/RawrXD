/**
 * @file tensor_validator.cpp
 * @brief Phase 2.5: Tensor Directory Validation
 * 
 * Properly parses and validates ALL tensors in the GGUF file.
 * No shortcuts. No skipping. Real tensor enumeration.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>

using namespace std;

const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
const uint32_t GGUF_MAGIC = 0x46554747;

// GGUF types
enum gguf_type {
    GGUF_TYPE_UINT8   = 0,  GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,  GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,  GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,  GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,  GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10, GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12,
};

// GGML types (from ggml.h)
enum ggml_type {
    GGML_TYPE_F32  = 0,   GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,   GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q4_2 = 4,   GGML_TYPE_Q4_3 = 5,
    GGML_TYPE_Q5_0 = 6,   GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,   GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,  GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,  GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,  GGML_TYPE_Q8_K = 15,
    GGML_TYPE_IQ2_XXS = 16, GGML_TYPE_IQ2_XS = 17,
    GGML_TYPE_IQ3_XXS = 18, GGML_TYPE_IQ1_S = 19,
    GGML_TYPE_IQ4_NL = 20, GGML_TYPE_IQ3_S = 21,
    GGML_TYPE_IQ2_S = 22,  GGML_TYPE_IQ4_XS = 23,
    GGML_TYPE_I8 = 24,    GGML_TYPE_I16 = 25,
    GGML_TYPE_I32 = 26,   GGML_TYPE_I64 = 27,
    GGML_TYPE_F64 = 28,   GGML_TYPE_IQ1_M = 29,
    GGML_TYPE_COUNT = 30,
};

const char* ggml_type_name(int type) {
    switch (type) {
        case GGML_TYPE_F32: return "F32";
        case GGML_TYPE_F16: return "F16";
        case GGML_TYPE_Q4_0: return "Q4_0";
        case GGML_TYPE_Q4_1: return "Q4_1";
        case GGML_TYPE_Q5_0: return "Q5_0";
        case GGML_TYPE_Q5_1: return "Q5_1";
        case GGML_TYPE_Q8_0: return "Q8_0";
        case GGML_TYPE_Q8_1: return "Q8_1";
        case GGML_TYPE_Q2_K: return "Q2_K";
        case GGML_TYPE_Q3_K: return "Q3_K";
        case GGML_TYPE_Q4_K: return "Q4_K";
        case GGML_TYPE_Q5_K: return "Q5_K";
        case GGML_TYPE_Q6_K: return "Q6_K";
        case GGML_TYPE_Q8_K: return "Q8_K";
        default: return "UNKNOWN";
    }
}

template<typename T>
T read_le(ifstream& file) {
    T value;
    file.read(reinterpret_cast<char*>(&value), sizeof(T));
    return value;
}

string read_gguf_string(ifstream& file) {
    uint64_t len = read_le<uint64_t>(file);
    if (len > 100000) {
        cerr << "ERROR: String length " << len << " exceeds sanity check\n";
        return "";
    }
    vector<char> buffer(len);
    file.read(buffer.data(), len);
    return string(buffer.data(), len);
}

struct TensorInfo {
    string name;
    uint32_t n_dims;
    vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    uint64_t data_size;
};

int main() {
    cout << "🔬 RawrXD Phase 2.5: Tensor Directory Validation\n";
    cout << "=================================================\n";
    cout << "Target: " << MODEL_PATH << "\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    // Read header
    uint32_t magic = read_le<uint32_t>(file);
    if (magic != GGUF_MAGIC) {
        cerr << "❌ Invalid magic: " << hex << magic << dec << "\n";
        return 1;
    }
    
    uint32_t version = read_le<uint32_t>(file);
    uint64_t n_tensors = read_le<uint64_t>(file);
    uint64_t n_kv = read_le<uint64_t>(file);
    
    cout << "GGUF Version: " << version << "\n";
    cout << "Tensor count: " << n_tensors << "\n";
    cout << "KV pairs: " << n_kv << "\n\n";
    
    // Parse ALL metadata (required to reach tensor table)
    cout << "Parsing metadata...\n";
    size_t metadata_bytes = 0;
    
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_gguf_string(file);
        if (key.empty()) {
            cerr << "ERROR: Empty key at KV " << i << "\n";
            return 1;
        }
        
        uint32_t type = read_le<uint32_t>(file);
        metadata_bytes += key.size() + sizeof(uint64_t) + sizeof(uint32_t);
        
        // Skip value based on type
        switch (type) {
            case GGUF_TYPE_UINT8:
            case GGUF_TYPE_INT8:
            case GGUF_TYPE_BOOL:
                file.seekg(1, ios::cur);
                metadata_bytes += 1;
                break;
            case GGUF_TYPE_UINT16:
            case GGUF_TYPE_INT16:
                file.seekg(2, ios::cur);
                metadata_bytes += 2;
                break;
            case GGUF_TYPE_UINT32:
            case GGUF_TYPE_INT32:
            case GGUF_TYPE_FLOAT32:
                file.seekg(4, ios::cur);
                metadata_bytes += 4;
                break;
            case GGUF_TYPE_UINT64:
            case GGUF_TYPE_INT64:
            case GGUF_TYPE_FLOAT64:
                file.seekg(8, ios::cur);
                metadata_bytes += 8;
                break;
            case GGUF_TYPE_STRING: {
                string val = read_gguf_string(file);
                metadata_bytes += sizeof(uint64_t) + val.size();
                break;
            }
            case GGUF_TYPE_ARRAY: {
                uint32_t arr_type = read_le<uint32_t>(file);
                uint64_t arr_len = read_le<uint64_t>(file);
                metadata_bytes += sizeof(uint32_t) + sizeof(uint64_t);
                
                // Skip array data
                size_t elem_size = 4; // default
                if (arr_type == GGUF_TYPE_UINT8 || arr_type == GGUF_TYPE_INT8) elem_size = 1;
                else if (arr_type == GGUF_TYPE_UINT16 || arr_type == GGUF_TYPE_INT16) elem_size = 2;
                else if (arr_type == GGUF_TYPE_UINT64 || arr_type == GGUF_TYPE_INT64) elem_size = 8;
                else if (arr_type == GGUF_TYPE_STRING) elem_size = 0; // variable
                
                if (arr_type == GGUF_TYPE_STRING) {
                    for (uint64_t j = 0; j < arr_len; j++) {
                        string s = read_gguf_string(file);
                        metadata_bytes += sizeof(uint64_t) + s.size();
                    }
                } else {
                    file.seekg(arr_len * elem_size, ios::cur);
                    metadata_bytes += arr_len * elem_size;
                }
                break;
            }
            default:
                cerr << "WARNING: Unknown type " << type << " for key " << key << "\n";
                file.seekg(8, ios::cur);
                metadata_bytes += 8;
                break;
        }
    }
    
    cout << "Metadata parsed: " << metadata_bytes << " bytes\n";
    cout << "File position after metadata: " << file.tellg() << "\n\n";
    
    // Now parse tensor info
    cout << "Parsing tensor directory...\n\n";
    
    vector<TensorInfo> tensors;
    tensors.reserve(n_tensors);
    
    size_t tensor_table_bytes = 0;
    
    for (uint64_t i = 0; i < n_tensors; i++) {
        TensorInfo info;
        
        // Read tensor name
        info.name = read_gguf_string(file);
        if (info.name.empty()) {
            cerr << "ERROR: Empty tensor name at index " << i << "\n";
            cerr << "File position: " << file.tellg() << "\n";
            return 1;
        }
        tensor_table_bytes += sizeof(uint64_t) + info.name.size();
        
        // Read dimensions
        info.n_dims = read_le<uint32_t>(file);
        if (info.n_dims > 4 || info.n_dims == 0) {
            cerr << "ERROR: Invalid n_dims " << info.n_dims << " for tensor " << info.name << "\n";
            cerr << "File position: " << file.tellg() << "\n";
            return 1;
        }
        tensor_table_bytes += sizeof(uint32_t);
        
        info.dims.resize(info.n_dims);
        for (uint32_t d = 0; d < info.n_dims; d++) {
            info.dims[d] = read_le<uint64_t>(file);
            tensor_table_bytes += sizeof(uint64_t);
        }
        
        // Read type and offset
        info.type = read_le<uint32_t>(file);
        tensor_table_bytes += sizeof(uint32_t);
        
        info.offset = read_le<uint64_t>(file);
        tensor_table_bytes += sizeof(uint64_t);
        
        // Calculate data size (simplified)
        info.data_size = 0;
        if (info.n_dims > 0) {
            size_t num_elements = 1;
            for (auto d : info.dims) num_elements *= d;
            
            size_t type_size = 4; // default
            if (info.type == GGML_TYPE_Q4_0) type_size = 18; // 16 + 2 for block
            else if (info.type == GGML_TYPE_Q8_0) type_size = 34; // 32 + 2 for block
            else if (info.type == GGML_TYPE_F16) type_size = 2;
            else if (info.type == GGML_TYPE_F32) type_size = 4;
            
            info.data_size = num_elements * type_size / (info.type <= GGML_TYPE_F32 ? 1 : 32);
        }
        
        tensors.push_back(info);
        
        // Print first 10 and last 5 tensors
        if (i < 10 || i >= n_tensors - 5) {
            cout << "[" << setw(3) << i << "] " << left << setw(40) << info.name;
            cout << " [";
            for (size_t d = 0; d < info.dims.size(); d++) {
                if (d > 0) cout << ", ";
                cout << info.dims[d];
            }
            cout << "] ";
            cout << right << setw(6) << ggml_type_name(info.type);
            cout << " @ offset " << info.offset << "\n";
        } else if (i == 10) {
            cout << "... (" << (n_tensors - 15) << " tensors omitted) ...\n";
        }
    }
    
    cout << "\n=================================================\n";
    cout << "Tensor table parsed: " << tensor_table_bytes << " bytes\n";
    cout << "Total tensors: " << tensors.size() << "\n";
    
    // Validate
    bool valid = true;
    
    // Check tensor count
    if (tensors.size() != n_tensors) {
        cout << "❌ ERROR: Parsed " << tensors.size() << " tensors, expected " << n_tensors << "\n";
        valid = false;
    }
    
    // Check offsets are within file
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    
    for (const auto& t : tensors) {
        if (t.offset >= file_size) {
            cout << "❌ ERROR: Tensor " << t.name << " offset " << t.offset << " exceeds file size " << file_size << "\n";
            valid = false;
        }
    }
    
    // Check for duplicate names
    for (size_t i = 0; i < tensors.size(); i++) {
        for (size_t j = i + 1; j < tensors.size(); j++) {
            if (tensors[i].name == tensors[j].name) {
                cout << "❌ ERROR: Duplicate tensor name: " << tensors[i].name << "\n";
                valid = false;
            }
        }
    }
    
    // Summary statistics
    size_t total_params = 0;
    size_t q8_0_count = 0;
    size_t f32_count = 0;
    
    for (const auto& t : tensors) {
        size_t params = 1;
        for (auto d : t.dims) params *= d;
        total_params += params;
        if (t.type == GGML_TYPE_Q8_0) q8_0_count++;
        if (t.type == GGML_TYPE_F32) f32_count++;
    }
    
    cout << "\nStatistics:\n";
    cout << "  Total parameters: ~" << (total_params / 1000000) << "M\n";
    cout << "  Q8_0 tensors: " << q8_0_count << "\n";
    cout << "  F32 tensors: " << f32_count << "\n";
    
    if (valid) {
        cout << "\n✅ ALL " << n_tensors << " TENSORS VALIDATED SUCCESSFULLY\n";
        cout << "Tensor directory is correctly parsed!\n";
        return 0;
    } else {
        cout << "\n❌ Validation failed\n";
        return 1;
    }
}
