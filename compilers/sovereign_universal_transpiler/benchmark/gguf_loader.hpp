// ============================================================================
// benchmark/gguf_loader.hpp - Minimal GGUF Model Loader for SME2 Benchmarking
// Loads GGUF format models and extracts weight tensors for INT2/INT4 dequant
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <windows.h>

#ifndef GGUF_LOADER_H
#define GGUF_LOADER_H

// GGUF Magic: "GGUF" at offset 0
#define GGUF_MAGIC 0x46554747u

// GGUF Tensor types relevant to SME2 dequantization
enum ggml_type : uint32_t {
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
    GGML_TYPE_BF16    = 30,
    GGML_TYPE_Q4_0_4_4 = 31,
    GGML_TYPE_Q4_0_4_8 = 32,
    GGML_TYPE_Q4_0_8_8 = 33,
    GGML_TYPE_TQ1_0   = 34,
    GGML_TYPE_TQ2_0   = 35,
};

// GGUF header structures (v3)
struct gguf_header_t {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct gguf_tensor_info_t {
    char     name[64];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;  // Offset from start of tensor data
};

// Memory-mapped GGUF model wrapper
class GGUFFile {
private:
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    HANDLE  hMap  = nullptr;
    void*   pView = nullptr;
    size_t  fileSize = 0;

public:
    ~GGUFFile() { Close(); }

    bool Open(const char* path) {
        hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER li;
        GetFileSizeEx(hFile, &li);
        fileSize = static_cast<size_t>(li.QuadPart);

        hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { Close(); return false; }

        pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!pView) { Close(); return false; }
        return true;
    }

    void Close() {
        if (pView) { UnmapViewOfFile(pView); pView = nullptr; }
        if (hMap)  { CloseHandle(hMap); hMap = nullptr; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
    }

    const void* Data() const { return pView; }
    size_t      Size() const { return fileSize; }
    bool        IsOpen() const { return pView != nullptr; }
};

// GGUF model parser for SME2 benchmark integration
class GGUFParser {
public:
    struct TensorEntry {
        std::string name;
        uint32_t    type;
        uint64_t    offset;
        uint64_t    n_elements;
        uint64_t    dims[4];
        uint32_t    n_dims;
    };

private:
    std::vector<TensorEntry> tensors;
    uint64_t tensor_data_offset = 0;

public:
    bool Parse(const void* data, size_t size) {
        if (size < sizeof(gguf_header_t)) return false;

        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        const auto* hdr = reinterpret_cast<const gguf_header_t*>(ptr);

        if (hdr->magic != GGUF_MAGIC) return false;

        ptr += sizeof(gguf_header_t);

        // Skip metadata KV pairs
        for (uint64_t i = 0; i < hdr->metadata_kv_count; ++i) {
            // Skip key
            uint64_t key_len = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += sizeof(uint64_t) + key_len;
            // Skip value type + data
            uint32_t val_type = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += sizeof(uint32_t);
            switch (val_type) {
                case 0: case 1: case 2: case 3: case 4: // uint8/uint16/uint32/uint64/float32
                    ptr += 4; break;
                case 5: case 6: case 7: { // bool, int16, int32
                    ptr += 4; break;
                }
                case 8: { // float64
                    ptr += 8; break;
                }
                case 9: { // int64
                    ptr += 8; break;
                }
                case 10: { // string
                    uint64_t len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += sizeof(uint64_t) + len;
                    break;
                }
                case 11: { // array
                    uint32_t arr_type = *reinterpret_cast<const uint32_t*>(ptr);
                    ptr += sizeof(uint32_t);
                    uint64_t arr_len = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += sizeof(uint64_t);
                    for (uint64_t j = 0; j < arr_len; ++j) {
                        if (arr_type == 10) { // string array
                            uint64_t slen = *reinterpret_cast<const uint64_t*>(ptr);
                            ptr += sizeof(uint64_t) + slen;
                        } else {
                            ptr += 4;
                        }
                    }
                    break;
                }
                default: return false;
            }
        }

        // Parse tensor info
        tensors.clear();
        tensors.reserve(hdr->tensor_count);

        for (uint64_t i = 0; i < hdr->tensor_count; ++i) {
            TensorEntry te;
            uint64_t name_len = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += sizeof(uint64_t);

            size_t name_cap = (name_len < 64) ? name_len : 63;
            memcpy(te.name.data(), ptr, name_cap);
            te.name[name_cap] = '\0';
            ptr += name_len;

            te.n_dims = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += sizeof(uint32_t);

            te.n_elements = 1;
            for (uint32_t d = 0; d < te.n_dims; ++d) {
                te.dims[d] = *reinterpret_cast<const uint64_t*>(ptr);
                te.n_elements *= te.dims[d];
                ptr += sizeof(uint64_t);
            }

            te.type = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += sizeof(uint32_t);

            te.offset = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += sizeof(uint64_t);

            tensors.push_back(te);
        }

        // Tensor data starts here
        tensor_data_offset = static_cast<uint64_t>(ptr - static_cast<const uint8_t*>(data));
        return true;
    }

    const std::vector<TensorEntry>& GetTensors() const { return tensors; }
    uint64_t GetTensorDataOffset() const { return tensor_data_offset; }

    // Find a tensor by name substring
    const TensorEntry* FindTensor(const char* name) const {
        for (const auto& t : tensors) {
            if (t.name.find(name) != std::string::npos) return &t;
        }
        return nullptr;
    }

    // Get raw tensor data pointer from memory-mapped file
    const void* GetTensorData(const void* base, const TensorEntry& te) const {
        return static_cast<const uint8_t*>(base) + tensor_data_offset + te.offset;
    }

    // Convert GGUF quantized tensor to raw INT4 for SME2 benchmarking
    static std::vector<int8_t> ConvertToINT4(const void* src, size_t n_elements, uint32_t src_type) {
        std::vector<int8_t> result(n_elements, 0);
        const uint8_t* s = static_cast<const uint8_t*>(src);

        switch (src_type) {
            case GGML_TYPE_Q4_0: {
                // Q4_0: block of 32 elements, 2 bytes scale (FP16) + 16 bytes quant data
                size_t blocks = n_elements / 32;
                for (size_t b = 0; b < blocks; ++b) {
                    const uint8_t* block = s + b * 18; // 2 bytes scale + 16 bytes data
                    for (int j = 0; j < 16; ++j) {
                        uint8_t byte_val = block[2 + j];
                        result[b * 32 + j * 2 + 0] = (byte_val & 0x0F) - 8; // low nibble
                        result[b * 32 + j * 2 + 1] = (byte_val >> 4) - 8;   // high nibble
                    }
                }
                break;
            }
            case GGML_TYPE_Q4_K: {
                // Q4_K: similar block structure, extract nibbles
                size_t blocks = n_elements / 256;
                for (size_t b = 0; b < blocks; ++b) {
                    const uint8_t* block = s + b * 144; // Q4_K block size
                    size_t base_idx = b * 256;
                    for (int j = 0; j < 128; ++j) {
                        uint8_t byte_val = block[16 + j]; // quant data starts at offset 16
                        result[base_idx + j * 2 + 0] = (byte_val & 0x0F);
                        result[base_idx + j * 2 + 1] = (byte_val >> 4);
                    }
                }
                break;
            }
            default:
                // For unsupported types, just copy raw bytes
                memcpy(result.data(), src, n_elements);
                break;
        }
        return result;
    }
};

#endif // GGUF_LOADER_H
