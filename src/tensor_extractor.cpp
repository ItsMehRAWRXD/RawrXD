// tensor_extractor.cpp
// Simple GGUF tensor extractor using working parser from RC1

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <iomanip>
struct TensorInfo {
    std::vector<uint64_t> dims;
    uint32_t dtype;
    uint64_t offset;
};

bool ParseGGUF(const std::string& filepath, 
               std::unordered_map<std::string, TensorInfo>& tensors,
               uint64_t& data_offset) {
    // Open file
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, 
                               FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file" << std::endl;
        return false;
    }
    
    // Get file size
    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    uint64_t file_size = size.QuadPart;
    
    // Create mapping
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void* view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    
    // Parse
    const uint8_t* ptr = static_cast<const uint8_t*>(view);
    const uint8_t* end = ptr + file_size;
    
    // Magic
    uint32_t magic = *reinterpret_cast<const uint32_t*>(ptr);
    if (magic != 0x46554747) {
        std::cerr << "Invalid magic" << std::endl;
        return false;
    }
    ptr += 4;
    
    // Version
    uint32_t version = *reinterpret_cast<const uint32_t*>(ptr);
    ptr += 4;
    
    // Tensor count
    uint64_t tensor_count = *reinterpret_cast<const uint64_t*>(ptr);
    ptr += 8;
    
    // Metadata count
    uint64_t metadata_count = *reinterpret_cast<const uint64_t*>(ptr);
    ptr += 8;
    
    std::cout << "Version: " << version << std::endl;
    std::cout << "Tensors: " << tensor_count << std::endl;
    std::cout << "Metadata: " << metadata_count << std::endl;
    
    // Skip metadata
    std::cout << "Skipping metadata..." << std::endl;
    for (uint64_t i = 0; i < metadata_count; ++i) {
        size_t pos = ptr - static_cast<const uint8_t*>(view);
        std::cout << "Metadata " << i << " at position " << pos << std::endl;
        
        // Key length
        if (ptr + 8 > end) {
            std::cerr << "Not enough bytes for key_len" << std::endl;
            return false;
        }
        uint64_t key_len = *reinterpret_cast<const uint64_t*>(ptr);
        std::cout << "  key_len=" << key_len << std::endl;
        ptr += 8;
        
        // Key
        if (ptr + key_len > end) {
            std::cerr << "Not enough bytes for key" << std::endl;
            return false;
        }
        std::string key(reinterpret_cast<const char*>(ptr), key_len);
        std::cout << "  key=" << key << std::endl;
        ptr += key_len;
        
        // Value type
        if (ptr + 4 > end) {
            std::cerr << "Not enough bytes for value_type" << std::endl;
            return false;
        }
        uint32_t value_type = *reinterpret_cast<const uint32_t*>(ptr);
        std::cout << "  value_type=" << value_type << std::endl;
        ptr += 4;
        
        // Skip value
        // GGUF types: 0=UINT8, 1=INT8, 2=UINT16, 3=INT16, 4=UINT32, 5=INT32, 6=FLOAT32, 7=UINT64, 8=INT64, 9=FLOAT64, 10=BOOL, 11=STRING, 12=ARRAY
        switch (value_type) {
            case 0: case 1: case 10: // UINT8, INT8, BOOL
                std::cout << "  skipping 1 byte (uint8/int8/bool)" << std::endl;
                ptr += 1; 
                break;
            case 2: case 3: // UINT16, INT16
                std::cout << "  skipping 2 bytes (uint16/int16)" << std::endl;
                ptr += 2; 
                break;
            case 4: case 5: case 6: // UINT32, INT32, FLOAT32
                std::cout << "  skipping 4 bytes (uint32/int32/float32)" << std::endl;
                ptr += 4; 
                break;
            case 7: case 8: case 9: // UINT64, INT64, FLOAT64
                std::cout << "  skipping 8 bytes (uint64/int64/float64)" << std::endl;
                ptr += 8; 
                break;
            case 8:  // INT64 (but used as STRING in this file)
            case 11: { // STRING
                if (ptr + 8 > end) {
                    std::cerr << "Not enough bytes for str_len" << std::endl;
                    return false;
                }
                uint64_t len = *reinterpret_cast<const uint64_t*>(ptr);
                std::cout << "  string len=" << len << std::endl;
                ptr += 8;
                if (len > 0) {
                    if (ptr + len > end) {
                        std::cerr << "Not enough bytes for string" << std::endl;
                        return false;
                    }
                    std::string str(reinterpret_cast<const char*>(ptr), len);
                    std::cout << "  string value=" << str << std::endl;
                    ptr += len;
                }
                break;
            }
            case 12: { // ARRAY
                if (ptr + 12 > end) {
                    std::cerr << "Not enough bytes for array header" << std::endl;
                    return false;
                }
                uint32_t arr_type = *reinterpret_cast<const uint32_t*>(ptr);
                ptr += 4;
                uint64_t arr_len = *reinterpret_cast<const uint64_t*>(ptr);
                ptr += 8;
                std::cout << "  array: type=" << arr_type << ", len=" << arr_len << std::endl;
                for (uint64_t j = 0; j < arr_len; ++j) {
                    switch (arr_type) {
                        case 4: ptr += 4; break;
                        case 8: {
                            uint64_t s_len = *reinterpret_cast<const uint64_t*>(ptr);
                            ptr += 8 + s_len;
                            break;
                        }
                    }
                }
                break;
            }
            default:
                std::cerr << "Unknown value type: " << value_type << std::endl;
                return false;
        }
    }
    std::cout << "Metadata skipped, position: " << (ptr - static_cast<const uint8_t*>(view)) << std::endl;
    
    // Parse tensor info
    for (uint64_t i = 0; i < tensor_count; ++i) {
        // Name length
        uint64_t name_len = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        // Name
        std::string name(reinterpret_cast<const char*>(ptr), name_len);
        ptr += name_len;
        
        // Dimensions
        uint32_t n_dims = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        TensorInfo info;
        info.dims.resize(n_dims);
        for (uint32_t j = 0; j < n_dims; ++j) {
            info.dims[j] = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += 8;
        }
        
        // Data type
        info.dtype = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        // Offset
        info.offset = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        tensors[name] = info;
    }
    
    // Data offset
    data_offset = (ptr - static_cast<const uint8_t*>(view) + 31) & ~31;
    
    // Cleanup
    UnmapViewOfFile(view);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    return true;
}

// Extract tensor data
bool ExtractTensorData(const std::string& filepath, 
                       const TensorInfo& info,
                       uint64_t data_offset,
                       std::vector<uint8_t>& data) {
    // Open file
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, 
                               FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Create mapping
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void* view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    
    // Calculate size
    uint64_t num_elements = 1;
    for (auto d : info.dims) num_elements *= d;
    
    uint64_t tensor_size = num_elements;
    if (info.dtype >= 2 && info.dtype <= 15) {
        // Quantized
        switch (info.dtype) {
            case 2: tensor_size = (num_elements / 32) * 18; break;  // Q4_0
            case 3: tensor_size = (num_elements / 32) * 20; break;  // Q4_1
            case 8: tensor_size = (num_elements / 32) * 34; break;  // Q8_0
            case 10: tensor_size = num_elements / 4 + 256; break;  // Q2_K
            case 12: tensor_size = num_elements / 2 + 256; break;  // Q4_K
        }
    } else if (info.dtype == 0) {
        tensor_size = num_elements * 4;  // F32
    } else if (info.dtype == 1) {
        tensor_size = num_elements * 2;  // F16
    }
    
    // Read data
    data.resize(tensor_size);
    const uint8_t* src = static_cast<const uint8_t*>(view) + data_offset + info.offset;
    memcpy(data.data(), src, tensor_size);
    
    // Cleanup
    UnmapViewOfFile(view);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    
    std::unordered_map<std::string, TensorInfo> tensors;
    uint64_t data_offset;
    
    if (!ParseGGUF(model_path, tensors, data_offset)) {
        std::cerr << "Failed to parse GGUF" << std::endl;
        return 1;
    }
    
    std::cout << "Data offset: " << data_offset << std::endl;
    std::cout << "Tensors: " << tensors.size() << std::endl;
    
    // Print first 10 tensors
    int count = 0;
    for (const auto& [name, info] : tensors) {
        std::cout << name << ": [";
        for (size_t i = 0; i < info.dims.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << info.dims[i];
        }
        std::cout << "], dtype=" << info.dtype << ", offset=" << info.offset << std::endl;
        
        if (++count >= 10) break;
    }
    
    // Try to extract token_embd.weight
    auto it = tensors.find("token_embd.weight");
    if (it != tensors.end()) {
        std::cout << "\nExtracting token_embd.weight..." << std::endl;
        
        std::vector<uint8_t> data;
        if (ExtractTensorData(model_path, it->second, data_offset, data)) {
            std::cout << "Extracted " << data.size() << " bytes" << std::endl;
            
            // Print first 16 bytes
            std::cout << "First 16 bytes: ";
            for (size_t i = 0; i < std::min(size_t(16), data.size()); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << (int)data[i] << " ";
            }
            std::cout << std::dec << std::endl;
        } else {
            std::cerr << "Failed to extract tensor data" << std::endl;
        }
    }
    
    std::cout << "\n✓ Tensor extraction complete!" << std::endl;
    
    return 0;
}
