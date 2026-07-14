// test_tensor_loader.cpp
// Truth Gate 002 - Phase 1: Tensor Data Loader
// Loads tensor data using offsets from JSON index

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <json/json.h>

struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t dtype;
    uint64_t offset;
    uint64_t size;
    std::vector<uint8_t> data;
};

class TensorLoader {
public:
    bool LoadFromIndex(const std::string& gguf_path, const std::string& index_path) {
        // Load index JSON
        std::ifstream index_file(index_path);
        if (!index_file) {
            std::cerr << "Failed to open index: " << index_path << std::endl;
            return false;
        }
        
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        
        if (!Json::parseFromStream(builder, index_file, &root, &errors)) {
            std::cerr << "Failed to parse JSON: " << errors << std::endl;
            return false;
        }
        
        data_offset_ = root["data_offset"].asUInt64();
        
        // Parse tensors
        const Json::Value& tensors_json = root["tensors"];
        for (const auto& t : tensors_json) {
            Tensor tensor;
            tensor.name = t["name"].asString();
            
            const Json::Value& dims_json = t["dims"];
            for (const auto& d : dims_json) {
                tensor.dims.push_back(d.asUInt64());
            }
            
            tensor.dtype = t["dtype"].asUInt();
            tensor.offset = t["offset"].asUInt64();
            tensor.size = t["size"].asUInt64();
            
            tensors_.push_back(tensor);
        }
        
        // Open GGUF file
        file_handle_ = CreateFileA(gguf_path.c_str(), GENERIC_READ, 
                                   FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open GGUF: " << gguf_path << std::endl;
            return false;
        }
        
        // Get file size
        LARGE_INTEGER size;
        GetFileSizeEx(file_handle_, &size);
        file_size_ = size.QuadPart;
        
        // Create file mapping
        file_mapping_ = CreateFileMapping(file_handle_, NULL, PAGE_READONLY, 
                                        0, 0, NULL);
        if (!file_mapping_) {
            std::cerr << "Failed to create file mapping" << std::endl;
            return false;
        }
        
        // Map view
        file_view_ = MapViewOfFile(file_mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!file_view_) {
            std::cerr << "Failed to map view" << std::endl;
            return false;
        }
        
        return true;
    }
    
    bool ExtractTensor(const std::string& name, Tensor& out_tensor) {
        // Find tensor
        auto it = std::find_if(tensors_.begin(), tensors_.end(),
            [&name](const Tensor& t) { return t.name == name; });
        
        if (it == tensors_.end()) {
            std::cerr << "Tensor not found: " << name << std::endl;
            return false;
        }
        
        const Tensor& info = *it;
        
        // Validate offset
        uint64_t absolute_offset = data_offset_ + info.offset;
        if (absolute_offset + info.size > file_size_) {
            std::cerr << "Tensor data extends beyond file" << std::endl;
            return false;
        }
        
        // Copy tensor data
        out_tensor = info;
        out_tensor.data.resize(info.size);
        
        const uint8_t* src = static_cast<const uint8_t*>(file_view_) + absolute_offset;
        memcpy(out_tensor.data.data(), src, info.size);
        
        return true;
    }
    
    void ListTensors() const {
        std::cout << "\n=== Available Tensors ===" << std::endl;
        std::cout << "Total: " << tensors_.size() << " tensors\n\n";
        
        for (const auto& t : tensors_) {
            std::cout << "  " << t.name << "\n";
            std::cout << "    Shape: [";
            for (size_t i = 0; i < t.dims.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << t.dims[i];
            }
            std::cout << "]\n";
            std::cout << "    Type: " << t.dtype << "\n";
            std::cout << "    Offset: " << t.offset << ", Size: " << t.size << " bytes\n\n";
        }
    }
    
    ~TensorLoader() {
        if (file_view_) UnmapViewOfFile(file_view_);
        if (file_mapping_) CloseHandle(file_mapping_);
        if (file_handle_ != INVALID_HANDLE_VALUE) CloseHandle(file_handle_);
    }

private:
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    HANDLE file_mapping_ = NULL;
    void* file_view_ = nullptr;
    uint64_t file_size_ = 0;
    uint64_t data_offset_ = 0;
    std::vector<Tensor> tensors_;
};

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Tensor Loader Test" << std::endl;
    std::cout << "Truth Gate 002 - Phase 1" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> <index.json>" << std::endl;
        return 1;
    }
    
    std::string gguf_path = argv[1];
    std::string index_path = argv[2];
    
    std::cout << "\nGGUF: " << gguf_path << std::endl;
    std::cout << "Index: " << index_path << std::endl;
    
    TensorLoader loader;
    if (!loader.LoadFromIndex(gguf_path, index_path)) {
        std::cerr << "Failed to load index" << std::endl;
        return 1;
    }
    
    loader.ListTensors();
    
    // Try to extract a tensor
    Tensor token_embd;
    if (loader.ExtractTensor("token_embd.weight", token_embd)) {
        std::cout << "\n✓ Successfully extracted token_embd.weight" << std::endl;
        std::cout << "  Size: " << token_embd.data.size() << " bytes" << std::endl;
        
        // Print first few bytes
        std::cout << "  First 16 bytes: ";
        for (size_t i = 0; i < std::min(size_t(16), token_embd.data.size()); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)token_embd.data[i] << " ";
        }
        std::cout << std::dec << std::endl;
    } else {
        std::cout << "\n✗ Failed to extract token_embd.weight" << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "✓ Tensor Loader Test Complete" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
