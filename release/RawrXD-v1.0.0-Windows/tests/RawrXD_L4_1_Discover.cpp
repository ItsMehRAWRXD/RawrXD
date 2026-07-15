// RawrXD_L4_1_Discover.cpp
// L4.1.0 Tensor Discovery — Standalone Validation Tool
//
// Purpose: Verify GGUF tensor discovery without decoding complexity
// Scope: Parse header, read tensor directory, find token_embd.weight, report metadata
//
// Build: cl.exe /std:c++17 /EHsc /O2 /W4 /WX RawrXD_L4_1_Discover.cpp /Fe:RawrXD_L4_1_Discover.exe
//
// Usage: RawrXD_L4_1_Discover.exe <model.gguf>
//
// Exit codes:
//   0 = PASS (tensor found and validated)
//   1 = FAIL (tensor not found or validation error)
//   2 = USAGE ERROR (wrong arguments)

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

// GGUF magic number (little-endian)
constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF" in ASCII

// GGUF tensor types
enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    COUNT
};

// GGUF header structure (v3)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

// Tensor info structure
struct TensorInfo {
    std::string name;
    uint32_t dimensions;
    std::vector<uint64_t> shape;
    GGMLType type;
    uint64_t offset;
    uint64_t size;
};

// Helper: Get type name
const char* GetTypeName(GGMLType type) {
    switch (type) {
        case GGMLType::F32:  return "F32";
        case GGMLType::F16:  return "F16";
        case GGMLType::Q4_0: return "Q4_0";
        case GGMLType::Q4_1: return "Q4_1";
        case GGMLType::Q5_0: return "Q5_0";
        case GGMLType::Q5_1: return "Q5_1";
        case GGMLType::Q8_0: return "Q8_0";
        case GGMLType::Q8_1: return "Q8_1";
        case GGMLType::Q2_K: return "Q2_K";
        case GGMLType::Q3_K: return "Q3_K";
        case GGMLType::Q4_K: return "Q4_K";
        case GGMLType::Q5_K: return "Q5_K";
        case GGMLType::Q6_K: return "Q6_K";
        case GGMLType::Q8_K: return "Q8_K";
        default:             return "UNKNOWN";
    }
}

// Helper: Get type size in bytes per block
size_t GetTypeBlockSize(GGMLType type) {
    switch (type) {
        case GGMLType::F32:  return 4;
        case GGMLType::F16:  return 2;
        case GGMLType::Q4_0: return 18;  // 32 4-bit weights + 2 scale bytes
        case GGMLType::Q4_1: return 20;  // 32 4-bit weights + 2 scale + 2 min
        case GGMLType::Q5_0: return 22;
        case GGMLType::Q5_1: return 24;
        case GGMLType::Q8_0: return 34;  // 32 8-bit weights + 2 scale bytes
        case GGMLType::Q8_1: return 36;
        case GGMLType::Q2_K: return 256; // k-quants use blocks
        case GGMLType::Q3_K: return 256;
        case GGMLType::Q4_K: return 256;
        case GGMLType::Q5_K: return 256;
        case GGMLType::Q6_K: return 256;
        case GGMLType::Q8_K: return 256;
        default:             return 0;
    }
}

// Helper: Get number of elements per block
size_t GetTypeBlockElements(GGMLType type) {
    switch (type) {
        case GGMLType::F32:
        case GGMLType::F16:
            return 1;
        case GGMLType::Q4_0:
        case GGMLType::Q4_1:
        case GGMLType::Q5_0:
        case GGMLType::Q5_1:
        case GGMLType::Q8_0:
        case GGMLType::Q8_1:
            return 32;
        case GGMLType::Q2_K:
        case GGMLType::Q3_K:
        case GGMLType::Q4_K:
        case GGMLType::Q5_K:
        case GGMLType::Q6_K:
        case GGMLType::Q8_K:
            return 256;
        default:
            return 0;
    }
}

// Read a string from file (GGUF format: uint64_t length + bytes)
std::string ReadString(std::ifstream& file) {
    uint64_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    // Sanity check: strings shouldn't be more than 1MB
    if (len > 1000000) {
        std::cerr << "ERROR: String length too large: " << len << std::endl;
        return "";
    }
    std::string str(len, '\0');
    if (len > 0 && file.good()) {
        file.read(&str[0], static_cast<std::streamsize>(len));
    }
    return str;
}

// Read a uint64_t value
uint64_t ReadU64(std::ifstream& file) {
    uint64_t value;
    file.read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
}

// Read a uint32_t value
uint32_t ReadU32(std::ifstream& file) {
    uint32_t value;
    file.read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
}

// Forward declarations
void SkipMetadataValue(std::ifstream& file, uint32_t type);
void SkipArray(std::ifstream& file, uint32_t arr_type, uint64_t arr_len);

// Skip array values
void SkipArray(std::ifstream& file, uint32_t arr_type, uint64_t arr_len) {
    for (uint64_t i = 0; i < arr_len && file.good(); ++i) {
        SkipMetadataValue(file, arr_type);
    }
}

// Skip metadata value based on type
void SkipMetadataValue(std::ifstream& file, uint32_t type) {
    if (!file.good()) return;
    
    switch (type) {
        case 0: // uint8
        case 1: // int8
        case 10: // bool
            file.seekg(1, std::ios::cur);
            break;
        case 2: // uint16
        case 3: // int16
            file.seekg(2, std::ios::cur);
            break;
        case 4: // uint32
        case 5: // int32
        case 6: // float32
        case 13: // GGUF v3 type (uint32)
            file.seekg(4, std::ios::cur);
            break;
        case 7: // uint64
        case 8: // int64
        case 9: // float64
            file.seekg(8, std::ios::cur);
            break;
        case 11: { // string
            uint64_t len;
            file.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (file.good() && len > 0 && len < 1000000) {
                file.seekg(static_cast<std::streamoff>(len), std::ios::cur);
            }
            break;
        }
        case 12: { // array
            uint32_t arr_type = ReadU32(file);
            uint64_t arr_len = ReadU64(file);
            if (arr_len < 100000) {
                SkipArray(file, arr_type, arr_len);
            }
            break;
        }
        default:
            break;
    }
}

// Parse GGUF file and find tensor
bool DiscoverTensor(const char* filename, const char* target_tensor, TensorInfo& out_info) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "ERROR: Cannot open file: " << filename << std::endl;
        return false;
    }

    // Read header
    GGUFHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // Validate magic
    if (header.magic != GGUF_MAGIC) {
        std::cerr << "ERROR: Invalid GGUF magic (expected 0x" << std::hex << GGUF_MAGIC 
                  << ", got 0x" << header.magic << ")" << std::endl;
        return false;
    }

    std::cout << "GGUF Version: " << header.version << std::endl;
    std::cout << "Tensor Count: " << header.tensor_count << std::endl;
    std::cout << "Metadata KV Count: " << header.metadata_kv_count << std::endl;

    // Sanity checks
    if (header.tensor_count > 10000 || header.tensor_count == 0) {
        std::cerr << "ERROR: Unreasonable tensor count: " << header.tensor_count << std::endl;
        return false;
    }
    if (header.metadata_kv_count > 10000) {
        std::cerr << "ERROR: Unreasonable metadata count: " << header.metadata_kv_count << std::endl;
        return false;
    }

    // Skip metadata (we don't need it for tensor discovery)
    std::cout << "Skipping metadata..." << std::endl;
    for (uint64_t i = 0; i < header.metadata_kv_count && file.good(); ++i) {
        std::string key = ReadString(file);
        if (!file.good() || key.empty()) {
            std::cerr << "ERROR: Failed to read metadata key " << i << std::endl;
            return false;
        }
        uint32_t value_type = ReadU32(file);
        if (!file.good()) {
            std::cerr << "ERROR: Failed to read metadata type " << i << std::endl;
            return false;
        }
        SkipMetadataValue(file, value_type);
        if (!file.good()) {
            std::cerr << "ERROR: Failed to skip metadata value " << i << std::endl;
            return false;
        }
    }
    std::cout << "Metadata skipped." << std::endl;

    // Align to 32-byte boundary before tensor info (GGUF v3 requirement)
    std::streampos current_pos = file.tellg();
    std::streamoff alignment = 32;
    std::streamoff padding = (alignment - (current_pos % alignment)) % alignment;
    if (padding > 0) {
        file.seekg(padding, std::ios::cur);
    }

    // Read tensor info
    // Note: tensor data starts after tensor info section
    // (not used directly, but marks the boundary)
    (void)file.tellg(); // Current position is start of tensor info

    for (uint64_t i = 0; i < header.tensor_count; ++i) {
        TensorInfo info;
        
        // Read tensor name
        info.name = ReadString(file);
        
        // Read dimensions
        uint32_t n_dims = ReadU32(file);
        info.dimensions = n_dims;
        info.shape.resize(n_dims);
        
        uint64_t num_elements = 1;
        for (uint32_t d = 0; d < n_dims; ++d) {
            info.shape[d] = ReadU64(file);
            num_elements *= info.shape[d];
        }
        
        // Read type
        info.type = static_cast<GGMLType>(ReadU32(file));
        
        // Read offset
        info.offset = ReadU64(file);
        
        // Calculate size
        size_t block_size = GetTypeBlockSize(info.type);
        size_t block_elements = GetTypeBlockElements(info.type);
        
        if (block_elements > 0) {
            uint64_t num_blocks = (num_elements + block_elements - 1) / block_elements;
            info.size = num_blocks * block_size;
        } else {
            info.size = num_elements * block_size;
        }

        // Check if this is the target tensor
        if (info.name == target_tensor) {
            out_info = info;
            return true;
        }
    }

    return false; // Tensor not found
}

// Validate tensor metadata
bool ValidateTensor(const TensorInfo& info) {
    bool valid = true;

    // Check dimensions
    if (info.dimensions != 2) {
        std::cerr << "WARNING: Expected 2D tensor, got " << info.dimensions << "D" << std::endl;
        valid = false;
    }

    // Check shape (expecting [vocab_size, embedding_dim] or [embedding_dim, vocab_size])
    if (info.shape.size() >= 2) {
        uint64_t dim0 = info.shape[0];
        uint64_t dim1 = info.shape[1];
        
        // For token_embd.weight, typically [vocab_size, embedding_dim]
        // Phi-3-mini: vocab_size ~ 32000, embedding_dim = 3072
        if (dim0 < 1000 || dim0 > 100000) {
            std::cerr << "WARNING: Unusual vocab_size: " << dim0 << std::endl;
            valid = false;
        }
        
        if (dim1 < 512 || dim1 > 8192) {
            std::cerr << "WARNING: Unusual embedding_dim: " << dim1 << std::endl;
            valid = false;
        }
    }

    // Check quantization type
    if (info.type != GGMLType::Q4_0 && 
        info.type != GGMLType::Q4_1 &&
        info.type != GGMLType::Q5_0 &&
        info.type != GGMLType::Q5_1 &&
        info.type != GGMLType::Q8_0 &&
        info.type != GGMLType::Q2_K &&
        info.type != GGMLType::Q3_K &&
        info.type != GGMLType::Q4_K &&
        info.type != GGMLType::Q5_K &&
        info.type != GGMLType::Q6_K &&
        info.type != GGMLType::F16 &&
        info.type != GGMLType::F32) {
        std::cerr << "WARNING: Unusual quantization type: " << static_cast<uint32_t>(info.type) << std::endl;
        valid = false;
    }

    // Check offset is reasonable
    if (info.offset == 0) {
        std::cerr << "WARNING: Tensor offset is zero" << std::endl;
        valid = false;
    }

    // Check size is reasonable
    if (info.size == 0 || info.size > 10ULL * 1024 * 1024 * 1024) { // > 10GB
        std::cerr << "WARNING: Unusual tensor size: " << info.size << " bytes" << std::endl;
        valid = false;
    }

    return valid;
}

int main(int argc, char* argv[]) {
    // Print header
    std::cout << "L4.1.0 Tensor Discovery Report" << std::endl;
    std::cout << "==============================" << std::endl;
    std::cout << std::endl;

    // Check arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>" << std::endl;
        return 2;
    }

    const char* model_path = argv[1];
    const char* target_tensor = "token_embd.weight";

    std::cout << "Model:" << std::endl;
    std::cout << "  " << model_path << std::endl;
    std::cout << std::endl;

    std::cout << "Tensor:" << std::endl;
    std::cout << "  " << target_tensor << std::endl;
    std::cout << std::endl;

    // Discover tensor
    TensorInfo info;
    bool found = DiscoverTensor(model_path, target_tensor, info);

    std::cout << "Found:" << std::endl;
    std::cout << "  " << (found ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    if (!found) {
        std::cout << "Validation:" << std::endl;
        std::cout << "  FAIL (tensor not found)" << std::endl;
        return 1;
    }

    // Report dimensions
    std::cout << "Dimensions:" << std::endl;
    std::cout << "  [";
    for (size_t i = 0; i < info.shape.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << info.shape[i];
    }
    std::cout << "]" << std::endl;
    std::cout << std::endl;

    // Report quantization
    std::cout << "Quantization:" << std::endl;
    std::cout << "  " << GetTypeName(info.type) << std::endl;
    std::cout << std::endl;

    // Report file offset
    std::cout << "File Offset:" << std::endl;
    std::cout << "  0x" << std::hex << info.offset << std::dec << std::endl;
    std::cout << std::endl;

    // Report tensor size
    std::cout << "Tensor Size:" << std::endl;
    std::cout << "  " << info.size << " bytes" << std::endl;
    std::cout << std::endl;

    // Validate
    bool valid = ValidateTensor(info);

    std::cout << "Validation:" << std::endl;
    if (valid) {
        std::cout << "  PASS" << std::endl;
        return 0;
    } else {
        std::cout << "  FAIL (metadata validation failed)" << std::endl;
        return 1;
    }
}
