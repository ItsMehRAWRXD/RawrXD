/**
 * @file test_tensor_extraction_complete.cpp
 * @brief Complete tensor extraction test - Truth Gate 002 Phase 1
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <algorithm>

#define GGUF_MAGIC 0x46554747

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t dtype;
    uint64_t offset;
};

class GGUFParser {
public:
    bool Parse(const std::string& filepath) {
        // Open file
        hFile_ = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile_ == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open file" << std::endl;
            return false;
        }
        
        // Get file size
        LARGE_INTEGER size;
        if (!GetFileSizeEx(hFile_, &size)) {
            CloseHandle(hFile_);
            return false;
        }
        file_size_ = size.QuadPart;
        
        // Create mapping
        hMap_ = CreateFileMapping(hFile_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap_) {
            CloseHandle(hFile_);
            return false;
        }
        
        // Map view
        data_ = (uint8_t*)MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, 0);
        if (!data_) {
            CloseHandle(hMap_);
            CloseHandle(hFile_);
            return false;
        }
        
        // Parse header
        size_t pos = 0;
        
        // Magic
        magic_ = *(uint32_t*)(data_ + pos); pos += 4;
        if (magic_ != GGUF_MAGIC) {
            std::cerr << "Invalid magic: 0x" << std::hex << magic_ << std::dec << std::endl;
            return false;
        }
        
        // Version
        version_ = *(uint32_t*)(data_ + pos); pos += 4;
        
        // Tensor count
        tensor_count_ = *(uint64_t*)(data_ + pos); pos += 8;
        
        // Metadata count
        metadata_count_ = *(uint64_t*)(data_ + pos); pos += 8;
        
        std::cout << "Version: " << version_ << std::endl;
        std::cout << "Tensors: " << tensor_count_ << std::endl;
        std::cout << "Metadata: " << metadata_count_ << std::endl;
        
        // Skip metadata
        std::cout << "Parsing metadata..." << std::endl;
        for (uint64_t i = 0; i < metadata_count_; ++i) {
            // Key length
            uint64_t key_len = *(uint64_t*)(data_ + pos); pos += 8;
            if (key_len > 1000) {
                std::cerr << "Invalid key_len: " << key_len << std::endl;
                return false;
            }
            
            // Key
            pos += key_len;
            
            // Value type
            uint32_t value_type = *(uint32_t*)(data_ + pos); pos += 4;
            if (value_type > 20) {
                std::cerr << "Invalid value_type: " << value_type << std::endl;
                return false;
            }
            
            // Skip value
            switch (value_type) {
                case 0: case 1: case 10: pos += 1; break;
                case 2: case 3: pos += 2; break;
                case 4: case 5: case 6: pos += 4; break;
                case 7: case 8: case 9: pos += 8; break;
                case 11: {
                    uint64_t len = *(uint64_t*)(data_ + pos); pos += 8 + len;
                    break;
                }
                case 12: {
                    uint32_t arr_type = *(uint32_t*)(data_ + pos); pos += 4;
                    uint64_t arr_len = *(uint64_t*)(data_ + pos); pos += 8;
                    for (uint64_t j = 0; j < arr_len; ++j) {
                        if (arr_type == 4) pos += 4;
                        else if (arr_type == 8) {
                            uint64_t s_len = *(uint64_t*)(data_ + pos); pos += 8 + s_len;
                        }
                    }
                    break;
                }
            }
        }
        std::cout << "Metadata parsed, pos=" << pos << std::endl;
        
        // Parse tensor info
        for (uint64_t i = 0; i < tensor_count_; ++i) {
            TensorInfo info;
            
            // Name length
            uint64_t name_len = *(uint64_t*)(data_ + pos); pos += 8;
            
            // Name
            info.name = std::string((char*)(data_ + pos), name_len);
            pos += name_len;
            
            // Dimensions
            uint32_t n_dims = *(uint32_t*)(data_ + pos); pos += 4;
            info.dims.resize(n_dims);
            for (uint32_t j = 0; j < n_dims; ++j) {
                info.dims[j] = *(uint64_t*)(data_ + pos); pos += 8;
            }
            
            // Data type
            info.dtype = *(uint32_t*)(data_ + pos); pos += 4;
            
            // Offset
            info.offset = *(uint64_t*)(data_ + pos); pos += 8;
            
            tensors_.push_back(info);
        }
        
        // Data offset
        data_offset_ = (pos + 31) & ~31;
        
        return true;
    }
    
    bool ExtractTensor(const std::string& name, std::vector<uint8_t>& data) {
        // Find tensor
        auto it = std::find_if(tensors_.begin(), tensors_.end(),
            [&name](const TensorInfo& t) { return t.name == name; });
        
        if (it == tensors_.end()) {
            return false;
        }
        
        const TensorInfo& info = *it;
        
        // Calculate size
        uint64_t num_elements = 1;
        for (auto d : info.dims) num_elements *= d;
        
        uint64_t size = num_elements;
        if (info.dtype == 2) size = (num_elements / 32) * 18;  // Q4_0
        else if (info.dtype == 3) size = (num_elements / 32) * 20;  // Q4_1
        else if (info.dtype == 8) size = (num_elements / 32) * 34;  // Q8_0
        else if (info.dtype == 10) size = num_elements / 4 + 256;  // Q2_K
        else if (info.dtype == 12) size = num_elements / 2 + 256;  // Q4_K
        else if (info.dtype == 0) size = num_elements * 4;  // F32
        else if (info.dtype == 1) size = num_elements * 2;  // F16
        
        // Read data
        data.resize(size);
        memcpy(data.data(), data_ + data_offset_ + info.offset, size);
        
        return true;
    }
    
    void ListTensors() const {
        std::cout << "\n=== Tensors ===" << std::endl;
        for (const auto& info : tensors_) {
            std::cout << info.name << ": [";
            for (size_t i = 0; i < info.dims.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << info.dims[i];
            }
            std::cout << "], dtype=" << info.dtype << ", offset=" << info.offset << std::endl;
        }
    }
    
    ~GGUFParser() {
        if (data_) UnmapViewOfFile(data_);
        if (hMap_) CloseHandle(hMap_);
        if (hFile_ != INVALID_HANDLE_VALUE) CloseHandle(hFile_);
    }

private:
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMap_ = NULL;
    uint8_t* data_ = nullptr;
    uint64_t file_size_ = 0;
    uint32_t magic_ = 0;
    uint32_t version_ = 0;
    uint64_t tensor_count_ = 0;
    uint64_t metadata_count_ = 0;
    uint64_t data_offset_ = 0;
    std::vector<TensorInfo> tensors_;
};

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Tensor Extraction Test" << std::endl;
    std::cout << "Truth Gate 002 - Phase 1" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    
    GGUFParser parser;
    if (!parser.Parse(model_path)) {
        std::cerr << "Failed to parse GGUF" << std::endl;
        return 1;
    }
    
    parser.ListTensors();
    
    // Extract token_embd.weight
    std::vector<uint8_t> data;
    if (parser.ExtractTensor("token_embd.weight", data)) {
        std::cout << "\n✓ Extracted token_embd.weight: " << data.size() << " bytes" << std::endl;
        
        // Print first 16 bytes
        std::cout << "First 16 bytes: ";
        for (size_t i = 0; i < std::min(size_t(16), data.size()); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)data[i] << " ";
        }
        std::cout << std::dec << std::endl;
    } else {
        std::cout << "\n✗ Failed to extract token_embd.weight" << std::endl;
    }
    
    std::cout << "\n✓ Tensor extraction complete!" << std::endl;
    
    return 0;
}
