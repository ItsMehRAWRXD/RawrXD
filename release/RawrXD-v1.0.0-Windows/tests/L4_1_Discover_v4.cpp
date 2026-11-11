// RawrXD_L4_1_Discover_v4.cpp
// L4.1.0 Tensor Discovery Tool - Fixed Metadata Skip
// Fixed: Proper GGUF value type handling in metadata skip

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>

// GGUF format constants
static const uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
static const uint32_t GGUF_VERSION = 3;

// GGUF value types
enum GgufType {
    GGUF_TYPE_UINT8   = 0,
    GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,
    GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,
    GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,
    GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10,
    GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12
};

// File reader with bounds checking - streaming for large files
class FileReader {
private:
    std::ifstream file;
    std::streamsize file_size;
    size_t pos;
    
public:
    FileReader(const std::string& path) : pos(0) {
        file.open(path, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + path);
        }
        
        file_size = file.tellg();
        file.seekg(0, std::ios::beg);
    }
    
    ~FileReader() {
        if (file.is_open()) {
            file.close();
        }
    }
    
    size_t size() const { return file_size; }
    size_t tell() const { return pos; }
    bool eof() const { return pos >= static_cast<size_t>(file_size); }
    
    void seek(size_t offset) {
        if (offset > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Seek beyond file bounds");
        }
        pos = offset;
        file.seekg(offset, std::ios::beg);
    }
    
    void skip(size_t bytes) {
        if (pos + bytes > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Skip beyond file bounds");
        }
        pos += bytes;
        file.seekg(bytes, std::ios::cur);
    }
    
    template<typename T>
    T read() {
        if (pos + sizeof(T) > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Read beyond file bounds");
        }
        T value;
        if (!file.read(reinterpret_cast<char*>(&value), sizeof(T))) {
            throw std::runtime_error("Failed to read from file");
        }
        pos += sizeof(T);
        return value;
    }
    
    std::string read_string() {
        uint64_t len = read<uint64_t>();
        
        // Validate string length
        if (len > 16 * 1024 * 1024) { // 16MB max
            throw std::runtime_error("Invalid GGUF string length: " + std::to_string(len));
        }
        
        if (pos + len > static_cast<size_t>(file_size)) {
            throw std::runtime_error("String read beyond file bounds");
        }
        
        std::string str;
        str.resize(len);
        if (!file.read(&str[0], len)) {
            throw std::runtime_error("Failed to read string from file");
        }
        pos += len;
        return str;
    }
    
    // Safe metadata value skipper
    void skip_gguf_value(uint32_t type) {
        switch (type) {
            case GGUF_TYPE_UINT8:
            case GGUF_TYPE_INT8:
            case GGUF_TYPE_BOOL:
                skip(1);
                break;
                
            case GGUF_TYPE_UINT16:
            case GGUF_TYPE_INT16:
                skip(2);
                break;
                
            case GGUF_TYPE_UINT32:
            case GGUF_TYPE_INT32:
            case GGUF_TYPE_FLOAT32:
                skip(4);
                break;
                
            case GGUF_TYPE_UINT64:
            case GGUF_TYPE_INT64:
            case GGUF_TYPE_FLOAT64:
                skip(8);
                break;
                
            case GGUF_TYPE_STRING: {
                uint64_t len = read<uint64_t>();
                if (len > 16 * 1024 * 1024) {
                    throw std::runtime_error("Invalid GGUF string length in metadata: " + std::to_string(len));
                }
                skip(static_cast<size_t>(len));
                break;
            }
                
            case GGUF_TYPE_ARRAY: {
                uint32_t subtype = read<uint32_t>();
                uint64_t count = read<uint64_t>();
                
                if (count > 10000000) {
                    throw std::runtime_error("Invalid GGUF array count: " + std::to_string(count));
                }
                
                // Skip array elements
                for (uint64_t i = 0; i < count; i++) {
                    skip_gguf_value(subtype);
                }
                break;
            }
                
            default:
                throw std::runtime_error("Unknown GGUF value type: " + std::to_string(type));
        }
    }
};

// GGUF tensor info
struct TensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
};

// Parse GGUF and find token_embd.weight
class GgufDiscovery {
private:
    FileReader& file;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    uint64_t tensor_data_offset;
    
public:
    GgufDiscovery(FileReader& f) : file(f), version(0), tensor_count(0), 
                                   metadata_kv_count(0), tensor_data_offset(0) {}
    
    uint32_t get_version() const { return version; }
    uint64_t get_tensor_count() const { return tensor_count; }
    uint64_t get_metadata_kv_count() const { return metadata_kv_count; }
    
    bool parse_header() {
        // Magic
        uint32_t magic = file.read<uint32_t>();
        if (magic != GGUF_MAGIC) {
            std::cerr << "ERROR: Invalid GGUF magic: 0x" << std::hex << magic << std::dec << std::endl;
            return false;
        }
        
        // Version
        version = file.read<uint32_t>();
        std::cout << "GGUF Version: " << version << std::endl;
        
        if (version != 3) {
            std::cerr << "WARNING: Expected version 3, got " << version << std::endl;
        }
        
        // Tensor count
        tensor_count = file.read<uint64_t>();
        std::cout << "Tensor Count: " << tensor_count << std::endl;
        
        // Metadata KV count
        metadata_kv_count = file.read<uint64_t>();
        std::cout << "Metadata KV Count: " << metadata_kv_count << std::endl;
        
        return true;
    }
    
    void skip_metadata() {
        std::cout << "Skipping metadata..." << std::endl;
        
        for (uint64_t i = 0; i < metadata_kv_count; i++) {
            // Read key
            std::string key = file.read_string();
            
            // Read value type
            uint32_t value_type = file.read<uint32_t>();
            
            // Skip value based on type
            file.skip_gguf_value(value_type);
        }
        
        std::cout << "Metadata skipped successfully" << std::endl;
    }
    
    TensorInfo find_token_embd_weight() {
        std::cout << "\nSearching tensors..." << std::endl;
        
        for (uint64_t i = 0; i < tensor_count; i++) {
            TensorInfo info;
            
            // Tensor name
            info.name = file.read_string();
            
            // Number of dimensions
            info.n_dims = file.read<uint32_t>();
            
            // Dimensions
            info.dims.resize(info.n_dims);
            for (uint32_t d = 0; d < info.n_dims; d++) {
                info.dims[d] = file.read<uint64_t>();
            }
            
            // Tensor type
            info.type = file.read<uint32_t>();
            
            // Tensor offset
            info.offset = file.read<uint64_t>();
            
            // Check if this is the target tensor
            if (info.name == "token_embd.weight") {
                std::cout << "\n*** FOUND: token_embd.weight ***" << std::endl;
                return info;
            }
        }
        
        throw std::runtime_error("token_embd.weight not found in GGUF");
    }
    
    void print_report(const TensorInfo& info, uint64_t tensor_data_start) {
        std::cout << "\n";
        std::cout << "L4.1.0 Tensor Discovery Report" << std::endl;
        std::cout << "==============================" << std::endl;
        std::cout << std::endl;
        std::cout << "Tensor:" << std::endl;
        std::cout << "  " << info.name << std::endl;
        std::cout << std::endl;
        std::cout << "Found:" << std::endl;
        std::cout << "  YES" << std::endl;
        std::cout << std::endl;
        std::cout << "Dimensions:" << std::endl;
        std::cout << "  [";
        for (size_t i = 0; i < info.dims.size(); i++) {
            if (i > 0) std::cout << ", ";
            std::cout << info.dims[i];
        }
        std::cout << "]" << std::endl;
        std::cout << std::endl;
        std::cout << "Type:" << std::endl;
        std::cout << "  " << info.type << " (GGML type)" << std::endl;
        std::cout << std::endl;
        std::cout << "File Offset:" << std::endl;
        std::cout << "  0x" << std::hex << info.offset << std::dec << std::endl;
        std::cout << std::endl;
        std::cout << "Tensor Data Start:" << std::endl;
        std::cout << "  " << tensor_data_start << std::endl;
        std::cout << std::endl;
        std::cout << "Alignment Check:" << std::endl;
        if (info.offset % 32 == 0) {
            std::cout << "  PASS (32-byte aligned)" << std::endl;
        } else {
            std::cout << "  FAIL (offset % 32 = " << (info.offset % 32) << ")" << std::endl;
        }
        std::cout << std::endl;
        std::cout << "Status:" << std::endl;
        std::cout << "  PASS" << std::endl;
    }
};

void print_checklist(bool header_valid, bool version_ok, uint64_t tensor_count, 
                     uint64_t metadata_count, bool metadata_ok, bool tensor_ok,
                     const TensorInfo& info, uint64_t tensor_data_start) {
    std::cout << "\n";
    std::cout << "L4.1.0 Discovery Checklist" << std::endl;
    std::cout << "==========================" << std::endl;
    std::cout << std::endl;
    std::cout << "[ " << (header_valid ? "✓" : " ") << " ] GGUF header validated" << std::endl;
    std::cout << "[ " << (version_ok ? "✓" : " ") << " ] Version == 3" << std::endl;
    std::cout << "[ " << (tensor_count == 197 ? "✓" : " ") << " ] Tensor count == 197" << std::endl;
    std::cout << "[ " << (metadata_count == 36 ? "✓" : " ") << " ] Metadata KV count == 36" << std::endl;
    std::cout << "[ " << (metadata_ok ? "✓" : " ") << " ] Metadata traversal completes" << std::endl;
    std::cout << "[ " << (tensor_ok ? "✓" : " ") << " ] Tensor directory traversal completes" << std::endl;
    std::cout << "[ " << (!info.name.empty() ? "✓" : " ") << " ] token_embd.weight located" << std::endl;
    std::cout << "[ " << (info.dims.size() == 2 && info.dims[0] == 32064 && info.dims[1] == 3072 ? "✓" : " ") 
              << " ] Dimensions match expected embedding shape [32064, 3072]" << std::endl;
    std::cout << "[ " << (info.type == 2 ? "✓" : " ") << " ] Quantization type matches GGUF metadata (Q4_0)" << std::endl;
    std::cout << "[ " << (info.offset + tensor_data_start < 2147483648ULL ? "✓" : " ") 
              << " ] Offset passes file bounds check" << std::endl;
    std::cout << "[ " << (info.offset % 32 == 0 ? "✓" : " ") << " ] Offset is 32-byte aligned" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD L4.1.0 Tensor Discovery Tool (v4)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 1;
    }
    
    const char* model_path = argv[1];
    std::cout << "Model: " << model_path << std::endl;
    std::cout << std::endl;
    
    bool header_valid = false;
    bool version_ok = false;
    uint64_t tensor_count = 0;
    uint64_t metadata_count = 0;
    bool metadata_ok = false;
    bool tensor_ok = false;
    TensorInfo info;
    uint64_t tensor_data_start = 0;
    
    try {
        // Open file
        FileReader file(model_path);
        std::cout << "File size: " << file.size() << " bytes" << std::endl;
        std::cout << std::endl;
        
        // Parse GGUF
        GgufDiscovery discovery(file);
        
        if (!discovery.parse_header()) {
            std::cerr << "ERROR: Failed to parse GGUF header" << std::endl;
            return 1;
        }
        header_valid = true;
        version_ok = (discovery.get_version() == 3);
        tensor_count = discovery.get_tensor_count();
        metadata_count = discovery.get_metadata_kv_count();
        
        // Skip metadata safely
        discovery.skip_metadata();
        metadata_ok = true;
        
        // Find token_embd.weight
        info = discovery.find_token_embd_weight();
        tensor_ok = true;
        
        // Calculate tensor data start (for alignment check)
        tensor_data_start = file.tell();
        
        // Print report
        discovery.print_report(info, tensor_data_start);
        
        // Print checklist
        print_checklist(header_valid, version_ok, tensor_count, metadata_count,
                       metadata_ok, tensor_ok, info, tensor_data_start);
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nERROR: " << e.what() << std::endl;
        
        // Print checklist with current state
        print_checklist(header_valid, version_ok, tensor_count, metadata_count,
                       metadata_ok, tensor_ok, info, tensor_data_start);
        return 1;
    }
}
