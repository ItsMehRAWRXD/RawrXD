// tensor_loader.cpp
// Simple GGUF tensor loader

#include <windows.h>
#include <iostream>
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

class GGUFLoader {
public:
    bool Load(const std::string& filepath) {
        // Open file
        hFile_ = CreateFileA(filepath.c_str(), GENERIC_READ, 
                              FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile_ == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open file" << std::endl;
            return false;
        }
        
        // Get file size
        LARGE_INTEGER size;
        GetFileSizeEx(hFile_, &size);
        file_size_ = size.QuadPart;
        
        // Create mapping
        hMap_ = CreateFileMapping(hFile_, NULL, PAGE_READONLY, 0, 0, NULL);
        view_ = MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, 0);
        
        // Parse
        const uint8_t* ptr = static_cast<const uint8_t*>(view_);
        
        // Magic
        magic_ = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        if (magic_ != 0x46554747) {
            std::cerr << "Invalid magic: 0x" << std::hex << magic_ << std::dec << std::endl;
            return false;
        }
        
        // Version
        version_ = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        // Tensor count
        tensor_count_ = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        // Metadata count
        metadata_count_ = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        std::cout << "Version: " << version_ << std::endl;
        std::cout << "Tensors: " << tensor_count_ << std::endl;
        std::cout << "Metadata: " << metadata_count_ << std::endl;
        
        // Skip metadata
        for (uint64_t i = 0; i < metadata_count_; ++i) {
            // Key length
            uint64_t key_len = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += 8;
            
            // Key
            ptr += key_len;
            
            // Value type
            uint32_t value_type = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += 4;
            
            // Skip value
            switch (value_type) {
                case 0: case 1: case 10: ptr += 1; break;
                case 2: case 3: ptr += 2; break;
                case 4: case 5: case 6: ptr += 4; break;
                case 7: case 8: case 9: ptr += 8; break;
                case 11: {
                    uint64_t len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8 + len;
                    break;
                }
                case 12: {
                    uint32_t arr_type = *reinterpret_cast<const uint32_t*>(ptr);
                    ptr += 4;
                    uint64_t arr_len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    for (uint64_t j = 0; j < arr_len; ++j) {
                        if (arr_type == 4) ptr += 4;
                        else if (arr_type == 8) {
                            uint64_t s_len = *reinterpret_cast<const uint64_t*>(ptr);
                            ptr += 8 + s_len;
                        }
                    }
                    break;
                }
            }
        }
        
        // Parse tensor info
        for (uint64_t i = 0; i < tensor_count_; ++i) {
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
            
            tensors_[name] = info;
        }
        
        // Data offset
        data_offset_ = (ptr - static_cast<const uint8_t*>(view_) + 31) & ~31;
        
        return true;
    }
    
    bool ExtractTensor(const std::string& name, std::vector<uint8_t>& data) {
        auto it = tensors_.find(name);
        if (it == tensors_.end()) {
            return false;
        }
        
        const TensorInfo& info = it->second;
        
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
        const uint8_t* src = static_cast<const uint8_t*>(view_) + data_offset_ + info.offset;
        memcpy(data.data(), src, size);
        
        return true;
    }
    
    void ListTensors() const {
        std::cout << "\n=== Tensors ===" << std::endl;
        for (const auto& [name, info] : tensors_) {
            std::cout << name << ": [";
            for (size_t i = 0; i < info.dims.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << info.dims[i];
            }
            std::cout << "], dtype=" << info.dtype << ", offset=" << info.offset << std::endl;
        }
    }
    
    ~GGUFLoader() {
        if (view_) UnmapViewOfFile(view_);
        if (hMap_) CloseHandle(hMap_);
        if (hFile_ != INVALID_HANDLE_VALUE) CloseHandle(hFile_);
    }

private:
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMap_ = NULL;
    void* view_ = nullptr;
    uint64_t file_size_ = 0;
    uint32_t magic_ = 0;
    uint32_t version_ = 0;
    uint64_t tensor_count_ = 0;
    uint64_t metadata_count_ = 0;
    uint64_t data_offset_ = 0;
    std::unordered_map<std::string, TensorInfo> tensors_;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    
    GGUFLoader loader;
    if (!loader.Load(model_path)) {
        std::cerr << "Failed to load GGUF" << std::endl;
        return 1;
    }
    
    loader.ListTensors();
    
    // Extract token_embd.weight
    std::vector<uint8_t> data;
    if (loader.ExtractTensor("token_embd.weight", data)) {
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
    
    std::cout << "\n✓ Done!" << std::endl;
    
    return 0;
}
