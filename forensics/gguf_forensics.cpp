/**
 * GGUF Binary Forensics Tool
 * 
 * Reverse engineers GGUF files at the byte level.
 * Maps every header field, tensor entry, metadata KV, and alignment pattern.
 * 
 * Usage: gguf_forensics <file.gguf> [options]
 *        --tensor <name>    Dump specific tensor raw bytes + stats
 *        --metadata         Show all metadata key-value pairs
 *        --verify           Check alignment, padding, anomalies
 *        --entropy          Calculate entropy of tensor data
 *        --hex              Hex dump tensor data
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

// ============================================================================
// GGUF Format Constants (from spec + reverse engineered)
// ============================================================================

static constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF" in little-endian
static constexpr uint32_t GGUF_VERSION = 3;

enum class GGMLType : uint32_t {
    GGML_TYPE_F32     = 0,
    GGML_TYPE_F16     = 1,
    GGML_TYPE_Q4_0    = 2,
    GGML_TYPE_Q4_1    = 3,
    GGML_TYPE_Q5_0    = 6,
    GGML_TYPE_Q5_1    = 7,
    GGML_TYPE_Q8_0    = 8,
    GGML_TYPE_Q8_1    = 9,
    GGML_TYPE_Q2_K    = 10,
    GGML_TYPE_Q3_K    = 11,
    GGML_TYPE_Q4_K    = 12,
    GGML_TYPE_Q5_K    = 13,
    GGML_TYPE_Q6_K    = 14,
    GGML_TYPE_Q8_K    = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_I8      = 24,
    GGML_TYPE_I16     = 25,
    GGML_TYPE_I32     = 26,
    GGML_TYPE_I64     = 27,
    GGML_TYPE_F64     = 28,
    GGML_TYPE_IQ1_M   = 29,
    GGML_TYPE_COUNT   = 30,
};

enum class GGUFValueType : uint32_t {
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
    GGUF_TYPE_FLOAT64 = 12,
    GGUF_TYPE_COUNT   = 13,
};

// ============================================================================
// Type Information
// ============================================================================

struct TypeInfo {
    const char* name;
    size_t size;
    bool is_quantized;
    uint32_t block_size;  // For quantized types
};

static const std::map<GGMLType, TypeInfo> kTypeInfo = {
    {GGMLType::GGML_TYPE_F32,     {"F32",     4,  false, 1}},
    {GGMLType::GGML_TYPE_F16,     {"F16",     2,  false, 1}},
    {GGMLType::GGML_TYPE_Q4_0,    {"Q4_0",    18, true,  32}},
    {GGMLType::GGML_TYPE_Q4_1,    {"Q4_1",    20, true,  32}},
    {GGMLType::GGML_TYPE_Q5_0,    {"Q5_0",    22, true,  32}},
    {GGMLType::GGML_TYPE_Q5_1,    {"Q5_1",    24, true,  32}},
    {GGMLType::GGML_TYPE_Q8_0,    {"Q8_0",    34, true,  32}},
    {GGMLType::GGML_TYPE_Q8_1,    {"Q8_1",    36, true,  32}},
    {GGMLType::GGML_TYPE_Q2_K,    {"Q2_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_Q3_K,    {"Q3_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_Q4_K,    {"Q4_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_Q5_K,    {"Q5_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_Q6_K,    {"Q6_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_Q8_K,    {"Q8_K",    0,  true,  256}}, // Variable
    {GGMLType::GGML_TYPE_I8,      {"I8",      1,  false, 1}},
    {GGMLType::GGML_TYPE_I16,     {"I16",     2,  false, 1}},
    {GGMLType::GGML_TYPE_I32,     {"I32",     4,  false, 1}},
    {GGMLType::GGML_TYPE_I64,     {"I64",     8,  false, 1}},
    {GGMLType::GGML_TYPE_F64,     {"F64",     8,  false, 1}},
};

const char* GetTypeName(GGMLType type) {
    auto it = kTypeInfo.find(type);
    return (it != kTypeInfo.end()) ? it->second.name : "UNKNOWN";
}

size_t GetTypeSize(GGMLType type) {
    auto it = kTypeInfo.find(type);
    return (it != kTypeInfo.end()) ? it->second.size : 0;
}

bool IsQuantized(GGMLType type) {
    auto it = kTypeInfo.find(type);
    return (it != kTypeInfo.end()) ? it->second.is_quantized : false;
}

// ============================================================================
// GGUF Header Structures (packed, little-endian)
// ============================================================================

#pragma pack(push, 1)

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct GGUFMetadataKV {
    uint64_t key_len;
    // char key[key_len];
    // GGUFValueType value_type;
    // ... value data ...
};

struct GGUFTensorInfo {
    uint64_t name_len;
    // char name[name_len];
    // uint32_t n_dims;
    // uint64_t dims[n_dims];
    // uint32_t type;
    // uint64_t offset;
    // Padding to align(64)
};

#pragma pack(pop)

// ============================================================================
// Forensics State
// ============================================================================

struct ForensicsConfig {
    bool show_metadata = false;
    bool verify = false;
    bool calculate_entropy = false;
    bool hex_dump = false;
    std::string target_tensor;
};

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dims;
    GGMLType type;
    uint64_t offset;
    uint64_t size;
    uint64_t file_offset;
};

struct MetadataKV {
    std::string key;
    GGUFValueType type;
    std::string value_str;
};

class GGUFForensics {
public:
    GGUFForensics(const char* filepath, const ForensicsConfig& config)
        : config_(config), filepath_(filepath) {}

    bool Analyze() {
        if (!MapFile()) {
            return false;
        }

        PrintBanner();
        
        if (!ParseHeader()) {
            return false;
        }

        if (!ParseMetadata()) {
            return false;
        }

        if (!ParseTensorInfo()) {
            return false;
        }

        PrintSummary();

        if (!config_.target_tensor.empty()) {
            AnalyzeTensor(config_.target_tensor);
        }

        if (config_.verify) {
            VerifyAlignment();
        }

        return true;
    }

private:
    ForensicsConfig config_;
    std::string filepath_;
    
    // Memory mapping
    int fd_ = -1;
    size_t file_size_ = 0;
    uint8_t* data_ = nullptr;
    size_t pos_ = 0;

    // Parsed data
    GGUFHeader header_;
    std::vector<MetadataKV> metadata_;
    std::vector<TensorInfo> tensors_;
    uint64_t data_offset_ = 0;

    bool MapFile() {
        fd_ = open(filepath_, O_RDONLY);
        if (fd_ < 0) {
            fprintf(stderr, "Error: Cannot open file: %s (errno=%d)\n", filepath_, errno);
            return false;
        }

        struct stat st;
        if (fstat(fd_, &st) != 0) {
            fprintf(stderr, "Error: Cannot stat file: %s\n", filepath_);
            close(fd_);
            return false;
        }

        file_size_ = st.st_size;
        
        data_ = (uint8_t*)mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, fd_, 0);
        if (data_ == MAP_FAILED) {
            fprintf(stderr, "Error: Cannot mmap file: %s\n", filepath_);
            close(fd_);
            return false;
        }

        printf("[+] Mapped %zu bytes from %s\n", file_size_, filepath_);
        return true;
    }

    void PrintBanner() {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════════╗\n");
        printf("║           GGUF BINARY FORENSICS TOOL v1.0                        ║\n");
        printf("║           Reverse Engineering at the Byte Level                   ║\n");
        printf("╚══════════════════════════════════════════════════════════════════╝\n");
        printf("\n");
    }

    bool ParseHeader() {
        if (file_size_ < sizeof(GGUFHeader)) {
            fprintf(stderr, "Error: File too small for GGUF header\n");
            return false;
        }

        memcpy(&header_, data_, sizeof(GGUFHeader));
        pos_ = sizeof(GGUFHeader);

        // Verify magic
        if (header_.magic != GGUF_MAGIC) {
            fprintf(stderr, "Error: Invalid GGUF magic: 0x%08X (expected 0x%08X)\n",
                    header_.magic, GGUF_MAGIC);
            return false;
        }

        // Verify version
        if (header_.version != 2 && header_.version != 3) {
            fprintf(stderr, "Warning: Unknown GGUF version: %u (expected 2 or 3)\n",
                    header_.version);
        }

        printf("[+] Header Analysis\n");
        printf("    Magic:      0x%08X ('GGUF') ✓\n", header_.magic);
        printf("    Version:    %u %s\n", header_.version,
               header_.version == 3 ? "(latest)" : "(legacy)");
        printf("    Tensors:    %lu\n", header_.tensor_count);
        printf("    Metadata:   %lu KV pairs\n", header_.metadata_kv_count);
        printf("    Header end: offset 0x%04zX\n", pos_);
        printf("\n");

        return true;
    }

    bool ParseMetadata() {
        printf("[+] Metadata Section (%lu entries)\n", header_.metadata_kv_count);
        printf("    %-40s %-12s %s\n", "Key", "Type", "Value");
        printf("    ");
        for (int i = 0; i < 80; i++) printf("-");
        printf("\n");

        for (uint64_t i = 0; i < header_.metadata_kv_count; i++) {
            if (!ParseMetadataKV()) {
                return false;
            }
        }

        printf("\n");
        return true;
    }

    bool ParseMetadataKV() {
        // Read key length
        if (pos_ + 8 > file_size_) return false;
        uint64_t key_len = *(uint64_t*)(data_ + pos_);
        pos_ += 8;

        // Read key
        if (pos_ + key_len > file_size_) return false;
        std::string key((char*)(data_ + pos_), key_len);
        pos_ += key_len;

        // Read value type
        if (pos_ + 4 > file_size_) return false;
        GGUFValueType value_type = *(GGUFValueType*)(data_ + pos_);
        pos_ += 4;

        // Parse value based on type
        std::string value_str = ParseMetadataValue(value_type);

        MetadataKV kv;
        kv.key = key;
        kv.type = value_type;
        kv.value_str = value_str;
        metadata_.push_back(kv);

        if (config_.show_metadata) {
            printf("    %-40s %-12s %s\n", key.c_str(), GetValueTypeName(value_type), value_str.c_str());
        }

        return true;
    }

    std::string ParseMetadataValue(GGUFValueType type) {
        switch (type) {
            case GGUFValueType::GGUF_TYPE_UINT8: {
                uint8_t v = *(data_ + pos_);
                pos_ += 1;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_INT8: {
                int8_t v = *(int8_t*)(data_ + pos_);
                pos_ += 1;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_UINT16: {
                uint16_t v = *(uint16_t*)(data_ + pos_);
                pos_ += 2;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_INT16: {
                int16_t v = *(int16_t*)(data_ + pos_);
                pos_ += 2;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_UINT32: {
                uint32_t v = *(uint32_t*)(data_ + pos_);
                pos_ += 4;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_INT32: {
                int32_t v = *(int32_t*)(data_ + pos_);
                pos_ += 4;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_FLOAT32: {
                float v = *(float*)(data_ + pos_);
                pos_ += 4;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_UINT64: {
                uint64_t v = *(uint64_t*)(data_ + pos_);
                pos_ += 8;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_INT64: {
                int64_t v = *(int64_t*)(data_ + pos_);
                pos_ += 8;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_FLOAT64: {
                double v = *(double*)(data_ + pos_);
                pos_ += 8;
                return std::to_string(v);
            }
            case GGUFValueType::GGUF_TYPE_BOOL: {
                uint8_t v = *(data_ + pos_);
                pos_ += 1;
                return v ? "true" : "false";
            }
            case GGUFValueType::GGUF_TYPE_STRING: {
                uint64_t len = *(uint64_t*)(data_ + pos_);
                pos_ += 8;
                std::string s((char*)(data_ + pos_), len);
                pos_ += len;
                return "\"" + s + "\"";
            }
            case GGUFValueType::GGUF_TYPE_ARRAY: {
                GGUFValueType elem_type = *(GGUFValueType*)(data_ + pos_);
                pos_ += 4;
                uint64_t count = *(uint64_t*)(data_ + pos_);
                pos_ += 8;
                
                // Skip array elements
                for (uint64_t i = 0; i < count; i++) {
                    SkipMetadataValue(elem_type);
                }
                
                return "[" + std::to_string(count) + " " + GetValueTypeName(elem_type) + "]";
            }
            default:
                return "UNKNOWN";
        }
    }

    void SkipMetadataValue(GGUFValueType type) {
        switch (type) {
            case GGUFValueType::GGUF_TYPE_UINT8:
            case GGUFValueType::GGUF_TYPE_INT8:
            case GGUFValueType::GGUF_TYPE_BOOL:
                pos_ += 1; break;
            case GGUFValueType::GGUF_TYPE_UINT16:
            case GGUFValueType::GGUF_TYPE_INT16:
                pos_ += 2; break;
            case GGUFValueType::GGUF_TYPE_UINT32:
            case GGUFValueType::GGUF_TYPE_INT32:
            case GGUFValueType::GGUF_TYPE_FLOAT32:
                pos_ += 4; break;
            case GGUFValueType::GGUF_TYPE_UINT64:
            case GGUFValueType::GGUF_TYPE_INT64:
            case GGUFValueType::GGUF_TYPE_FLOAT64:
                pos_ += 8; break;
            case GGUFValueType::GGUF_TYPE_STRING: {
                uint64_t len = *(uint64_t*)(data_ + pos_);
                pos_ += 8 + len;
                break;
            }
            default:
                break;
        }
    }

    const char* GetValueTypeName(GGUFValueType type) {
        switch (type) {
            case GGUFValueType::GGUF_TYPE_UINT8:   return "uint8";
            case GGUFValueType::GGUF_TYPE_INT8:    return "int8";
            case GGUFValueType::GGUF_TYPE_UINT16:  return "uint16";
            case GGUFValueType::GGUF_TYPE_INT16:   return "int16";
            case GGUFValueType::GGUF_TYPE_UINT32:  return "uint32";
            case GGUFValueType::GGUF_TYPE_INT32:   return "int32";
            case GGUFValueType::GGUF_TYPE_FLOAT32: return "float32";
            case GGUFValueType::GGUF_TYPE_BOOL:    return "bool";
            case GGUFValueType::GGUF_TYPE_STRING:  return "string";
            case GGUFValueType::GGUF_TYPE_ARRAY:   return "array";
            case GGUFValueType::GGUF_TYPE_UINT64:  return "uint64";
            case GGUFValueType::GGUF_TYPE_INT64:   return "int64";
            case GGUFValueType::GGUF_TYPE_FLOAT64: return "float64";
            default: return "unknown";
        }
    }

    bool ParseTensorInfo() {
        printf("[+] Tensor Info Section (%lu tensors)\n", header_.tensor_count);
        printf("    %-30s %-8s %-20s %-12s %-12s\n", 
               "Name", "Type", "Dimensions", "Offset", "Size");
        printf("    ");
        for (int i = 0; i < 100; i++) printf("-");
        printf("\n");

        for (uint64_t i = 0; i < header_.tensor_count; i++) {
            if (!ParseTensorEntry()) {
                return false;
            }
        }

        // Calculate data offset (aligned to 64 bytes after tensor info)
        data_offset_ = (pos_ + 63) & ~63ULL;
        
        printf("\n");
        printf("[+] Data Section starts at offset 0x%08lX (aligned to 64)\n", data_offset_);
        printf("\n");

        return true;
    }

    bool ParseTensorEntry() {
        // Read name length
        if (pos_ + 8 > file_size_) return false;
        uint64_t name_len = *(uint64_t*)(data_ + pos_);
        pos_ += 8;

        // Read name
        if (pos_ + name_len > file_size_) return false;
        std::string name((char*)(data_ + pos_), name_len);
        pos_ += name_len;

        // Read dimensions
        if (pos_ + 4 > file_size_) return false;
        uint32_t n_dims = *(uint32_t*)(data_ + pos_);
        pos_ += 4;

        std::vector<uint64_t> dims;
        uint64_t num_elements = 1;
        for (uint32_t i = 0; i < n_dims; i++) {
            if (pos_ + 8 > file_size_) return false;
            uint64_t dim = *(uint64_t*)(data_ + pos_);
            pos_ += 8;
            dims.push_back(dim);
            num_elements *= dim;
        }

        // Read type
        if (pos_ + 4 > file_size_) return false;
        GGMLType type = *(GGMLType*)(data_ + pos_);
        pos_ += 4;

        // Read offset
        if (pos_ + 8 > file_size_) return false;
        uint64_t offset = *(uint64_t*)(data_ + pos_);
        pos_ += 8;

        // Calculate size
        size_t type_size = GetTypeSize(type);
        uint64_t tensor_size = 0;
        
        if (IsQuantized(type)) {
            // For quantized types, size depends on block structure
            tensor_size = CalculateQuantizedSize(type, num_elements);
        } else {
            tensor_size = num_elements * type_size;
        }

        TensorInfo info;
        info.name = name;
        info.dims = dims;
        info.type = type;
        info.offset = offset;
        info.size = tensor_size;
        info.file_offset = data_offset_ + offset;
        tensors_.push_back(info);

        // Print tensor info
        std::string dims_str = "[";
        for (size_t i = 0; i < dims.size(); i++) {
            if (i > 0) dims_str += ", ";
            dims_str += std::to_string(dims[i]);
        }
        dims_str += "]";

        printf("    %-30s %-8s %-20s 0x%08lX %lu bytes\n",
               name.c_str(), GetTypeName(type), dims_str.c_str(), 
               offset, tensor_size);

        return true;
    }

    uint64_t CalculateQuantizedSize(GGMLType type, uint64_t num_elements) {
        // Simplified - actual sizes depend on specific quantization scheme
        switch (type) {
            case GGMLType::GGML_TYPE_Q4_K:
                // Q4_K: 256 elements per block, each block has:
                // - 2 scales (F16) = 4 bytes
                // - 1 min scale (F16) = 2 bytes
                // - 1 dmin (F16) = 2 bytes
                // - 128 nibbles (Q4) = 64 bytes
                // - 32 scales (6-bit) packed = 24 bytes
                // Total: ~96 bytes per 256 elements
                return (num_elements / 256) * 96 + ((num_elements % 256) ? 96 : 0);
            case GGMLType::GGML_TYPE_Q2_K:
                return (num_elements / 256) * 64 + ((num_elements % 256) ? 64 : 0);
            case GGMLType::GGML_TYPE_Q6_K:
                return (num_elements / 256) * 128 + ((num_elements % 256) ? 128 : 0);
            default:
                return num_elements; // Fallback
        }
    }

    void PrintSummary() {
        printf("[+] Summary\n");
        printf("    Total file size:     %zu bytes\n", file_size_);
        printf("    Header size:         %zu bytes\n", sizeof(GGUFHeader));
        printf("    Metadata section:    %zu bytes\n", pos_ - sizeof(GGUFHeader));
        printf("    Tensor info section: %zu bytes\n", data_offset_ - (sizeof(GGUFHeader) + (pos_ - sizeof(GGUFHeader))));
        printf("    Data section offset: %lu bytes\n", data_offset_);
        
        // Calculate total tensor data size
        uint64_t total_tensor_size = 0;
        for (const auto& t : tensors_) {
            total_tensor_size += t.size;
        }
        printf("    Total tensor data:   %lu bytes\n", total_tensor_size);
        printf("    Padding/overhead:    %zu bytes\n", file_size_ - data_offset_ - total_tensor_size);
        printf("\n");

        // Type distribution
        std::map<GGMLType, int> type_counts;
        for (const auto& t : tensors_) {
            type_counts[t.type]++;
        }
        
        printf("    Tensor type distribution:\n");
        for (const auto& [type, count] : type_counts) {
            printf("      %s: %d tensors\n", GetTypeName(type), count);
        }
        printf("\n");
    }

    void AnalyzeTensor(const std::string& target_name) {
        printf("[+] Analyzing tensor: %s\n", target_name.c_str());
        
        auto it = std::find_if(tensors_.begin(), tensors_.end(),
            [&target_name](const TensorInfo& t) { return t.name == target_name; });
        
        if (it == tensors_.end()) {
            printf("    ERROR: Tensor '%s' not found!\n", target_name.c_str());
            printf("    Available tensors:\n");
            for (const auto& t : tensors_) {
                printf("      - %s\n", t.name.c_str());
            }
            return;
        }

        const TensorInfo& tensor = *it;
        
        printf("    Name:        %s\n", tensor.name.c_str());
        printf("    Type:        %s\n", GetTypeName(tensor.type));
        printf("    Dimensions:  ");
        for (size_t i = 0; i < tensor.dims.size(); i++) {
            if (i > 0) printf(" x ");
            printf("%lu", tensor.dims[i]);
        }
        printf("\n");
        printf("    File offset: 0x%08lX\n", tensor.file_offset);
        printf("    Size:        %lu bytes\n", tensor.size);
        printf("\n");

        // Calculate statistics
        if (tensor.type == GGMLType::GGML_TYPE_F32) {
            AnalyzeFloatTensor(tensor);
        } else if (tensor.type == GGMLType::GGML_TYPE_F16) {
            AnalyzeF16Tensor(tensor);
        } else if (IsQuantized(tensor.type)) {
            AnalyzeQuantizedTensor(tensor);
        }

        // Hex dump if requested
        if (config_.hex_dump) {
            HexDumpTensor(tensor);
        }

        // Entropy calculation
        if (config_.calculate_entropy) {
            CalculateTensorEntropy(tensor);
        }
    }

    void AnalyzeFloatTensor(const TensorInfo& tensor) {
        const float* data = (const float*)(data_ + tensor.file_offset);
        size_t num_elements = tensor.size / sizeof(float);
        
        float min_val = data[0];
        float max_val = data[0];
        double sum = 0;
        double sum_sq = 0;
        
        for (size_t i = 0; i < num_elements; i++) {
            float v = data[i];
            min_val = std::min(min_val, v);
            max_val = std::max(max_val, v);
            sum += v;
            sum_sq += v * v;
        }
        
        float mean = sum / num_elements;
        float variance = (sum_sq / num_elements) - (mean * mean);
        float std_dev = std::sqrt(variance);
        
        printf("    Statistics (F32):\n");
        printf("      Elements:  %zu\n", num_elements);
        printf("      Min:       %f\n", min_val);
        printf("      Max:       %f\n", max_val);
        printf("      Mean:      %f\n", mean);
        printf("      Std Dev:   %f\n", std_dev);
        printf("\n");
    }

    void AnalyzeF16Tensor(const TensorInfo& tensor) {
        // F16 analysis would require conversion
        printf("    Statistics: F16 tensor (use --hex to dump raw bytes)\n");
        printf("\n");
    }

    void AnalyzeQuantizedTensor(const TensorInfo& tensor) {
        printf("    Statistics: Quantized tensor (%s)\n", GetTypeName(tensor.type));
        printf("      Block-based format - per-block analysis required\n");
        printf("\n");
    }

    void HexDumpTensor(const TensorInfo& tensor) {
        printf("    Hex dump (first 256 bytes):\n");
        
        const uint8_t* ptr = data_ + tensor.file_offset;
        size_t dump_size = std::min(tensor.size, (uint64_t)256);
        
        for (size_t i = 0; i < dump_size; i += 16) {
            printf("      %08zX: ", i);
            
            // Hex bytes
            for (size_t j = 0; j < 16 && (i + j) < dump_size; j++) {
                printf("%02X ", ptr[i + j]);
            }
            
            // Padding
            for (size_t j = (dump_size - i < 16) ? dump_size - i : 16; j < 16; j++) {
                printf("   ");
            }
            
            printf(" |");
            
            // ASCII
            for (size_t j = 0; j < 16 && (i + j) < dump_size; j++) {
                uint8_t c = ptr[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            
            printf("|\n");
        }
        printf("\n");
    }

    void CalculateTensorEntropy(const TensorInfo& tensor) {
        printf("    Entropy analysis:\n");
        
        // Simple byte-level entropy
        const uint8_t* ptr = data_ + tensor.file_offset;
        size_t sample_size = std::min(tensor.size, (uint64_t)65536); // Sample first 64KB
        
        int freq[256] = {0};
        for (size_t i = 0; i < sample_size; i++) {
            freq[ptr[i]]++;
        }
        
        double entropy = 0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                double p = (double)freq[i] / sample_size;
                entropy -= p * std::log2(p);
            }
        }
        
        printf("      Sample size: %zu bytes\n", sample_size);
        printf("      Entropy:     %.4f bits/byte\n", entropy);
        printf("      Max entropy: 8.0000 bits/byte (random)\n");
        printf("      Ratio:       %.2f%%\n", (entropy / 8.0) * 100);
        
        if (entropy < 1.0) {
            printf("      Pattern:     HIGHLY STRUCTURED (likely zeros or constants)\n");
        } else if (entropy < 4.0) {
            printf("      Pattern:     STRUCTURED (quantized weights)\n");
        } else if (entropy < 7.0) {
            printf("      Pattern:     MODERATE (compressed/encoded data)\n");
        } else {
            printf("      Pattern:     HIGH ENTROPY (near-random, possibly encrypted)\n");
        }
        printf("\n");
    }

    void VerifyAlignment() {
        printf("[+] Alignment Verification\n");
        
        bool issues_found = false;
        
        // Check header alignment
        if (sizeof(GGUFHeader) % 8 != 0) {
            printf("    WARNING: Header size (%zu) not 8-byte aligned\n", sizeof(GGUFHeader));
            issues_found = true;
        }
        
        // Check tensor data alignment
        for (const auto& t : tensors_) {
            if (t.file_offset % 64 != 0) {
                printf("    WARNING: Tensor '%s' at offset 0x%08lX not 64-byte aligned\n",
                       t.name.c_str(), t.file_offset);
                issues_found = true;
            }
        }
        
        // Check for gaps between tensors
        uint64_t expected_end = data_offset_;
        for (const auto& t : tensors_) {
            if (t.file_offset > expected_end) {
                uint64_t gap = t.file_offset - expected_end;
                printf("    INFO: Gap of %lu bytes before tensor '%s'\n", gap, t.name.c_str());
            }
            expected_end = t.file_offset + t.size;
        }
        
        // Check file size consistency
        if (expected_end > file_size_) {
            printf("    ERROR: Expected data end (0x%08lX) exceeds file size (0x%08zX)\n",
                   expected_end, file_size_);
            issues_found = true;
        }
        
        if (!issues_found) {
            printf("    ✓ All alignment checks passed\n");
        }
        
        printf("\n");
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================

void PrintUsage(const char* program) {
    printf("Usage: %s <file.gguf> [options]\n", program);
    printf("\n");
    printf("Options:\n");
    printf("  --tensor <name>    Analyze specific tensor in detail\n");
    printf("  --metadata         Show all metadata key-value pairs\n");
    printf("  --verify           Check alignment and structural integrity\n");
    printf("  --entropy          Calculate entropy of tensor data\n");
    printf("  --hex              Hex dump tensor data\n");
    printf("  --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s model.gguf --metadata --verify\n", program);
    printf("  %s model.gguf --tensor token_embd.weight --entropy --hex\n", program);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char* filepath = argv[1];
    
    if (strcmp(filepath, "--help") == 0 || strcmp(filepath, "-h") == 0) {
        PrintUsage(argv[0]);
        return 0;
    }

    ForensicsConfig config;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--tensor") == 0 && i + 1 < argc) {
            config.target_tensor = argv[++i];
        } else if (strcmp(argv[i], "--metadata") == 0) {
            config.show_metadata = true;
        } else if (strcmp(argv[i], "--verify") == 0) {
            config.verify = true;
        } else if (strcmp(argv[i], "--entropy") == 0) {
            config.calculate_entropy = true;
        } else if (strcmp(argv[i], "--hex") == 0) {
            config.hex_dump = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    GGUFForensics forensics(filepath, config);
    
    if (!forensics.Analyze()) {
        return 1;
    }

    return 0;
}
