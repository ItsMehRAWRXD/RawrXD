// test_tensor_extraction.cpp
// Truth Gate 002 - Phase 1: Tensor Extraction
// Extract actual tensor data from GGUF files

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <unordered_map>
#include <iomanip>
#include "gguf_loader.h"

// GGUF v3 format structures (from RC1)
#pragma pack(push, 1)

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct GGUFMetadataKV {
    uint64_t key_len;
    // key follows
    uint32_t value_type;
    // value follows
};

struct GGUFTensorInfo {
    uint64_t name_len;
    // name follows
    uint32_t n_dims;
    // dims follow (uint64_t each)
    uint32_t dtype;
    uint64_t offset;
};

#pragma pack(pop)

// Tensor data structure
struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t dtype;
    uint64_t offset;
    uint64_t size;
    std::vector<uint8_t> data;
    
    // Helper to get total element count
    uint64_t NumElements() const {
        if (dims.empty()) return 0;
        uint64_t count = 1;
        for (auto d : dims) count *= d;
        return count;
    }
    
    // Helper to get bytes per element
    size_t BytesPerElement() const {
        switch (dtype) {
            case 0: return 4;   // F32
            case 1: return 2;   // F16
            case 2: return 1;   // Q4_0
            case 3: return 1;   // Q4_1
            case 6: return 1;   // Q5_0
            case 7: return 1;   // Q5_1
            case 8: return 1;   // Q8_0
            case 9: return 1;   // Q8_1
            case 10: return 1;  // Q2_K
            case 11: return 1;  // Q3_K
            case 12: return 1;  // Q4_K
            case 13: return 1;  // Q5_K
            case 14: return 1;  // Q6_K
            case 15: return 1;  // Q8_K
            case 16: return 2;  // I8
            case 17: return 4;  // I16
            case 18: return 4;  // I32
            case 19: return 8;  // I64
            case 20: return 1;  // F64
            case 21: return 1;  // I64 (duplicate)
            default: return 1;
        }
    }
    
    // Get data type name
    std::string GetDtypeName() const {
        switch (dtype) {
            case 0: return "F32";
            case 1: return "F16";
            case 2: return "Q4_0";
            case 3: return "Q4_1";
            case 6: return "Q5_0";
            case 7: return "Q5_1";
            case 8: return "Q8_0";
            case 9: return "Q8_1";
            case 10: return "Q2_K";
            case 11: return "Q3_K";
            case 12: return "Q4_K";
            case 13: return "Q5_K";
            case 14: return "Q6_K";
            case 15: return "Q8_K";
            case 16: return "I8";
            case 17: return "I16";
            case 18: return "I32";
            case 19: return "I64";
            case 20: return "F64";
            default: return "UNKNOWN";
        }
    }
};

// GGUF Loader with tensor extraction
class GGUFTensorExtractor {
public:
    GGUFTensorExtractor() : file_handle_(INVALID_HANDLE_VALUE), 
                           file_mapping_(NULL), 
                           file_view_(NULL),
                           file_size_(0),
                           data_offset_(0) {}
    
    ~GGUFTensorExtractor() {
        Cleanup();
    }
    
    bool Load(const std::string& filepath) {
        Cleanup();
        
        // Open file
        file_handle_ = CreateFileA(filepath.c_str(), GENERIC_READ, 
                                   FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open file: " << filepath << std::endl;
            return false;
        }
        
        // Get file size
        LARGE_INTEGER size;
        if (!GetFileSizeEx(file_handle_, &size)) {
            std::cerr << "Failed to get file size" << std::endl;
            return false;
        }
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
        
        // Parse header
        if (!ParseHeader()) {
            std::cerr << "Failed to parse GGUF header" << std::endl;
            return false;
        }
        
        return true;
    }
    
    // Extract a specific tensor by name
    bool ExtractTensor(const std::string& name, Tensor& out_tensor) {
        auto it = tensor_map_.find(name);
        if (it == tensor_map_.end()) {
            std::cerr << "Tensor not found: " << name << std::endl;
            return false;
        }
        
        const TensorInfo& info = it->second;
        
        // Calculate tensor size
        uint64_t num_elements = 1;
        for (auto d : info.dims) num_elements *= d;
        
        size_t bytes_per_element = GetBytesPerElement(info.dtype);
        uint64_t tensor_size = num_elements * bytes_per_element;
        
        // Handle quantized formats with block structure
        if (info.dtype >= 2 && info.dtype <= 15) {
            tensor_size = CalculateQuantizedSize(info.dtype, num_elements);
        }
        
        // Validate offset and size
        if (data_offset_ + info.offset + tensor_size > file_size_) {
            std::cerr << "Tensor data extends beyond file bounds" << std::endl;
            return false;
        }
        
        // Extract tensor data
        out_tensor.name = name;
        out_tensor.dims = info.dims;
        out_tensor.dtype = info.dtype;
        out_tensor.offset = info.offset;
        out_tensor.size = tensor_size;
        
        // Copy data
        const uint8_t* data_ptr = static_cast<const uint8_t*>(file_view_) + 
                                  data_offset_ + info.offset;
        out_tensor.data.resize(tensor_size);
        memcpy(out_tensor.data.data(), data_ptr, tensor_size);
        
        return true;
    }
    
    // List all available tensors
    void ListTensors() const {
        std::cout << "\n=== Available Tensors ===" << std::endl;
        std::cout << "Total: " << tensor_map_.size() << " tensors\n\n";
        
        for (const auto& [name, info] : tensor_map_) {
            std::cout << "  " << name << "\n";
            std::cout << "    Shape: [";
            for (size_t i = 0; i < info.dims.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << info.dims[i];
            }
            std::cout << "]\n";
            std::cout << "    Type: " << GetDtypeName(info.dtype) << "\n";
            std::cout << "    Offset: " << info.offset << "\n\n";
        }
    }
    
    // Get tensor count
    size_t GetTensorCount() const {
        return tensor_map_.size();
    }
    
    // Get header info
    void GetHeaderInfo(uint64_t& tensor_count, uint64_t& metadata_count) const {
        tensor_count = header_.tensor_count;
        metadata_count = header_.metadata_kv_count;
    }

private:
    struct TensorInfo {
        std::vector<uint64_t> dims;
        uint32_t dtype;
        uint64_t offset;
    };
    
    HANDLE file_handle_;
    HANDLE file_mapping_;
    void* file_view_;
    uint64_t file_size_;
    uint64_t data_offset_;
    GGUFHeader header_;
    std::unordered_map<std::string, TensorInfo> tensor_map_;
    
    void Cleanup() {
        if (file_view_) {
            UnmapViewOfFile(file_view_);
            file_view_ = nullptr;
        }
        if (file_mapping_) {
            CloseHandle(file_mapping_);
            file_mapping_ = NULL;
        }
        if (file_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_handle_);
            file_handle_ = INVALID_HANDLE_VALUE;
        }
        tensor_map_.clear();
    }
    
    bool ParseHeader() {
        const uint8_t* ptr = static_cast<const uint8_t*>(file_view_);
        const uint8_t* end = ptr + file_size_;
        
        // Check magic
        header_.magic = *reinterpret_cast<const uint32_t*>(ptr);
        if (header_.magic != 0x46554747) {  // "GGUF"
            std::cerr << "Invalid GGUF magic: 0x" << std::hex << header_.magic << std::dec << std::endl;
            return false;
        }
        ptr += 4;
        
        // Version
        header_.version = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        // Tensor count
        header_.tensor_count = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        // Metadata KV count
        header_.metadata_kv_count = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        std::cout << "GGUF Version: " << header_.version << std::endl;
        std::cout << "Tensor Count: " << header_.tensor_count << std::endl;
        std::cout << "Metadata Count: " << header_.metadata_kv_count << std::endl;
        
        // Metadata starts immediately after header (no padding in GGUF v3)
        
        // Skip metadata
        for (uint64_t i = 0; i < header_.metadata_kv_count; ++i) {
            if (!SkipMetadataKV(ptr, end, i)) {
                return false;
            }
        }
        
        // Parse tensor info
        for (uint64_t i = 0; i < header_.tensor_count; ++i) {
            if (!ParseTensorInfo(ptr, end)) {
                return false;
            }
        }
        
        // Calculate data offset (align to 32 bytes)
        data_offset_ = ptr - static_cast<const uint8_t*>(file_view_);
        data_offset_ = (data_offset_ + 31) & ~31;
        
        std::cout << "Data Offset: " << data_offset_ << std::endl;
        
        return true;
    }
    
    bool SkipMetadataKV(const uint8_t*& ptr, const uint8_t* end, int index) {
        // Key length (u64)
        if (ptr + 8 > end) {
            std::cerr << "Metadata " << index << ": Failed at key length" << std::endl;
            return false;
        }
        uint64_t key_len = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        // Key (string of key_len bytes)
        if (ptr + key_len > end) {
            std::cerr << "Metadata " << index << ": Failed at key (len=" << key_len << ")" << std::endl;
            return false;
        }
        std::string key(reinterpret_cast<const char*>(ptr), key_len);
        ptr += key_len;
        
        // Align to 8 bytes after key
        size_t key_end_offset = ptr - static_cast<const uint8_t*>(file_view_);
        size_t padding = (8 - (key_end_offset % 8)) % 8;
        ptr += padding;
        
        // Value type (u32)
        if (ptr + 4 > end) {
            std::cerr << "Metadata " << index << " (" << key << "): Failed at value type" << std::endl;
            return false;
        }
        uint32_t value_type = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        // Align to 8 bytes after value type
        size_t type_end_offset = ptr - static_cast<const uint8_t*>(file_view_);
        padding = (8 - (type_end_offset % 8)) % 8;
        ptr += padding;
        
        // Skip value based on type
        if (!SkipValue(ptr, end, value_type)) {
            std::cerr << "Metadata " << index << " (" << key << "): Failed to skip value (type=" << value_type << ")" << std::endl;
            return false;
        }
        
        // Align to 8 bytes after value
        size_t value_end_offset = ptr - static_cast<const uint8_t*>(file_view_);
        padding = (8 - (value_end_offset % 8)) % 8;
        ptr += padding;
        
        return true;
    }
    
    bool SkipValue(const uint8_t*& ptr, const uint8_t* end, uint32_t type) {
        switch (type) {
            case 0: // UINT8
            case 1: // INT8
            case 10: // BOOL
                if (ptr + 1 > end) return false;
                ptr += 1;
                break;
            case 2: // UINT16
            case 3: // INT16
                if (ptr + 2 > end) return false;
                ptr += 2;
                break;
            case 4: // UINT32
            case 5: // INT32
            case 6: // FLOAT32
                if (ptr + 4 > end) return false;
                ptr += 4;
                break;
            case 7: // UINT64
            case 8: // INT64
            case 9: // FLOAT64
                if (ptr + 8 > end) return false;
                ptr += 8;
                break;
            case 11: // STRING
                // String: u64 length + bytes
                if (ptr + 8 > end) return false;
                {
                    uint64_t len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    if (ptr + len > end) return false;
                    ptr += len;
                }
                break;
            case 12: // ARRAY
                // Array: u32 type + u64 length + values
                if (ptr + 12 > end) return false;
                {
                    uint32_t arr_type = *reinterpret_cast<const uint32_t*>(ptr);
                    ptr += 4;
                    uint64_t arr_len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    for (uint64_t i = 0; i < arr_len; ++i) {
                        if (!SkipValue(ptr, end, arr_type)) return false;
                        // Align after each array element
                        size_t elem_end = ptr - static_cast<const uint8_t*>(file_view_);
                        size_t padding = (8 - (elem_end % 8)) % 8;
                        ptr += padding;
                    }
                }
                break;
            default:
                std::cerr << "Unknown metadata type: " << type << std::endl;
                return false;
        }
        return true;
    }
    
    bool ParseTensorInfo(const uint8_t*& ptr, const uint8_t* end) {
        // Name length (u64)
        if (ptr + 8 > end) return false;
        uint64_t name_len = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        // Name (string of name_len bytes)
        if (ptr + name_len > end) return false;
        std::string name(reinterpret_cast<const char*>(ptr), name_len);
        ptr += name_len;
        
        // Dimensions count (u32)
        if (ptr + 4 > end) return false;
        uint32_t n_dims = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        TensorInfo info;
        info.dims.resize(n_dims);
        for (uint32_t i = 0; i < n_dims; ++i) {
            if (ptr + 8 > end) return false;
            info.dims[i] = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += 8;
        }
        
        // Data type (u32)
        if (ptr + 4 > end) return false;
        info.dtype = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        // Offset (u64)
        if (ptr + 8 > end) return false;
        info.offset = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        tensor_map_[name] = info;
        
        return true;
    }
    
    size_t GetBytesPerElement(uint32_t dtype) const {
        switch (dtype) {
            case 0: return 4;   // F32
            case 1: return 2;   // F16
            case 2: case 3: case 6: case 7: case 8: case 9:
            case 10: case 11: case 12: case 13: case 14: case 15:
                return 1;  // Quantized
            case 16: return 1;   // I8
            case 17: return 2;   // I16
            case 18: return 4;   // I32
            case 19: return 8;   // I64
            case 20: return 8;   // F64
            default: return 1;
        }
    }
    
    std::string GetDtypeName(uint32_t dtype) const {
        switch (dtype) {
            case 0: return "F32";
            case 1: return "F16";
            case 2: return "Q4_0";
            case 3: return "Q4_1";
            case 6: return "Q5_0";
            case 7: return "Q5_1";
            case 8: return "Q8_0";
            case 9: return "Q8_1";
            case 10: return "Q2_K";
            case 11: return "Q3_K";
            case 12: return "Q4_K";
            case 13: return "Q5_K";
            case 14: return "Q6_K";
            case 15: return "Q8_K";
            case 16: return "I8";
            case 17: return "I16";
            case 18: return "I32";
            case 19: return "I64";
            case 20: return "F64";
            default: return "UNKNOWN";
        }
    }
    
    uint64_t CalculateQuantizedSize(uint32_t dtype, uint64_t num_elements) const {
        // Simplified - actual size depends on block structure
        // For now, return approximate size
        switch (dtype) {
            case 2: // Q4_0 - 18 bytes per 32 elements
                return (num_elements / 32) * 18 + (num_elements % 32 ? 18 : 0);
            case 3: // Q4_1 - 20 bytes per 32 elements
                return (num_elements / 32) * 20 + (num_elements % 32 ? 20 : 0);
            case 8: // Q8_0 - 34 bytes per 32 elements
                return (num_elements / 32) * 34 + (num_elements % 32 ? 34 : 0);
            case 10: // Q2_K
                return num_elements / 4 + 256;  // Approximate
            case 12: // Q4_K
                return num_elements / 2 + 256;  // Approximate
            default:
                return num_elements;
        }
    }
};

// Test functions
bool TestBasicExtraction(const std::string& model_path) {
    std::cout << "\n=== Test: Basic Tensor Extraction ===" << std::endl;
    
    GGUFTensorExtractor extractor;
    if (!extractor.Load(model_path)) {
        std::cerr << "FAILED: Could not load model" << std::endl;
        return false;
    }
    
    // List all tensors
    extractor.ListTensors();
    
    // Try to extract token embedding
    Tensor token_embd;
    if (extractor.ExtractTensor("token_embd.weight", token_embd)) {
        std::cout << "\n✓ Successfully extracted token_embd.weight" << std::endl;
        std::cout << "  Shape: [";
        for (size_t i = 0; i < token_embd.dims.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << token_embd.dims[i];
        }
        std::cout << "]" << std::endl;
        std::cout << "  Type: " << token_embd.GetDtypeName() << std::endl;
        std::cout << "  Size: " << token_embd.size << " bytes" << std::endl;
        std::cout << "  Elements: " << token_embd.NumElements() << std::endl;
        
        // Verify data
        if (!token_embd.data.empty()) {
            std::cout << "  Data: " << token_embd.data.size() << " bytes extracted" << std::endl;
            
            // Print first few bytes as hex
            std::cout << "  First 16 bytes: ";
            for (size_t i = 0; i < std::min(size_t(16), token_embd.data.size()); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << (int)token_embd.data[i] << " ";
            }
            std::cout << std::dec << std::endl;
        }
    } else {
        std::cout << "\n⚠ token_embd.weight not found (may have different name)" << std::endl;
    }
    
    // Try to extract output norm
    Tensor output_norm;
    if (extractor.ExtractTensor("output_norm.weight", output_norm)) {
        std::cout << "\n✓ Successfully extracted output_norm.weight" << std::endl;
        std::cout << "  Shape: [";
        for (size_t i = 0; i < output_norm.dims.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << output_norm.dims[i];
        }
        std::cout << "]" << std::endl;
        std::cout << "  Type: " << output_norm.GetDtypeName() << std::endl;
    }
    
    return true;
}

bool TestMultipleTensors(const std::string& model_path) {
    std::cout << "\n=== Test: Multiple Tensor Extraction ===" << std::endl;
    
    GGUFTensorExtractor extractor;
    if (!extractor.Load(model_path)) {
        std::cerr << "FAILED: Could not load model" << std::endl;
        return false;
    }
    
    // Extract multiple tensors
    std::vector<std::string> tensor_names = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight",
        "blk.0.attn_norm.weight",
        "blk.0.ffn_norm.weight"
    };
    
    int success_count = 0;
    for (const auto& name : tensor_names) {
        Tensor tensor;
        if (extractor.ExtractTensor(name, tensor)) {
            std::cout << "✓ " << name << " - " << tensor.NumElements() << " elements" << std::endl;
            success_count++;
        } else {
            std::cout << "✗ " << name << " - not found" << std::endl;
        }
    }
    
    std::cout << "\nExtracted " << success_count << "/" << tensor_names.size() << " tensors" << std::endl;
    
    return success_count > 0;
}

bool TestDataIntegrity(const std::string& model_path) {
    std::cout << "\n=== Test: Data Integrity ===" << std::endl;
    
    GGUFTensorExtractor extractor;
    if (!extractor.Load(model_path)) {
        std::cerr << "FAILED: Could not load model" << std::endl;
        return false;
    }
    
    // Extract a tensor and verify data is not all zeros
    Tensor tensor;
    if (!extractor.ExtractTensor("output_norm.weight", tensor)) {
        std::cout << "⚠ output_norm.weight not found, trying alternatives..." << std::endl;
        
        // Try to find any suitable tensor
        if (!extractor.ExtractTensor("token_embd.weight", tensor)) {
            std::cerr << "FAILED: Could not find any tensor to test" << std::endl;
            return false;
        }
    }
    
    // Check if data is all zeros (would indicate a problem)
    bool all_zeros = true;
    for (auto b : tensor.data) {
        if (b != 0) {
            all_zeros = false;
            break;
        }
    }
    
    if (all_zeros) {
        std::cerr << "FAILED: Tensor data is all zeros!" << std::endl;
        return false;
    }
    
    // Check if data is all same value (would indicate a problem)
    bool all_same = true;
    uint8_t first = tensor.data[0];
    for (auto b : tensor.data) {
        if (b != first) {
            all_same = false;
            break;
        }
    }
    
    if (all_same) {
        std::cerr << "WARNING: Tensor data is all same value (0x" << std::hex 
                  << (int)first << std::dec << ")" << std::endl;
    }
    
    // Calculate simple checksum
    uint64_t checksum = 0;
    for (auto b : tensor.data) {
        checksum += b;
    }
    
    std::cout << "✓ Data integrity check passed" << std::endl;
    std::cout << "  Data size: " << tensor.data.size() << " bytes" << std::endl;
    std::cout << "  Checksum: " << checksum << std::endl;
    std::cout << "  All zeros: " << (all_zeros ? "YES" : "NO") << std::endl;
    std::cout << "  All same: " << (all_same ? "YES" : "NO") << std::endl;
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Tensor Extraction Test" << std::endl;
    std::cout << "Truth Gate 002 - Phase 1" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::string model_path;
    if (argc > 1) {
        model_path = argv[1];
    } else {
        // Try to find a model in common locations
        std::vector<std::string> search_paths = {
            "D:\\models\\unlock-60M-Q2_K.gguf",
            "D:\\models\\*.gguf",
            "F:\\models\\*.gguf",
            "G:\\models\\*.gguf"
        };
        
        for (const auto& path : search_paths) {
            if (path.find('*') != std::string::npos) {
                // Try to find first .gguf file
                WIN32_FIND_DATAA find_data;
                HANDLE find_handle = FindFirstFileA(path.c_str(), &find_data);
                if (find_handle != INVALID_HANDLE_VALUE) {
                    std::string dir = path.substr(0, path.find_last_of('\\'));
                    model_path = dir + "\\" + find_data.cFileName;
                    FindClose(find_handle);
                    break;
                }
            } else if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                model_path = path;
                break;
            }
        }
        
        if (model_path.empty()) {
            std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
            std::cerr << "Or place a .gguf file in D:\\models\\, F:\\models\\, or G:\\models\\" << std::endl;
            return 1;
        }
    }
    
    std::cout << "\nModel: " << model_path << std::endl;
    
    // Run tests
    bool all_passed = true;
    
    all_passed &= TestBasicExtraction(model_path);
    all_passed &= TestMultipleTensors(model_path);
    all_passed &= TestDataIntegrity(model_path);
    
    std::cout << "\n========================================" << std::endl;
    if (all_passed) {
        std::cout << "✓ ALL TESTS PASSED" << std::endl;
        std::cout << "Truth Gate 002 - Phase 1: COMPLETE" << std::endl;
    } else {
        std::cout << "✗ SOME TESTS FAILED" << std::endl;
    }
    std::cout << "========================================" << std::endl;
    
    return all_passed ? 0 : 1;
}

