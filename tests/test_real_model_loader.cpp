/**
 * @file test_real_model_loader.cpp
 * @brief Load and verify a real GGUF model file
 * 
 * Usage: test_real_model_loader.exe <path_to_gguf_file>
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
#endif

// GGUF v3 constants
#define GGUF_MAGIC 0x46554747  // "GGUF" in little-endian
#define GGUF_VERSION 3

// GGML types
enum ggml_type {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
};

const char* ggml_type_name(int type) {
    switch (type) {
        case GGML_TYPE_F32:  return "F32";
        case GGML_TYPE_F16:  return "F16";
        case GGML_TYPE_Q4_0: return "Q4_0";
        case GGML_TYPE_Q4_1: return "Q4_1";
        case GGML_TYPE_Q5_0: return "Q5_0";
        case GGML_TYPE_Q5_1: return "Q5_1";
        case GGML_TYPE_Q8_0: return "Q8_0";
        case GGML_TYPE_Q8_1: return "Q8_1";
        case GGML_TYPE_Q4_K: return "Q4_K";
        case GGML_TYPE_Q5_K: return "Q5_K";
        case GGML_TYPE_Q6_K: return "Q6_K";
        case GGML_TYPE_Q8_K: return "Q8_K";
        default:             return "UNKNOWN";
    }
}

// Memory-mapped file
struct MappedFile {
    void* data;
    size_t size;
    #ifdef _WIN32
    HANDLE hFile;
    HANDLE hMap;
    #else
    int fd;
    #endif
};

bool mmap_file(const char* path, MappedFile* out) {
    #ifdef _WIN32
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Failed to open file: %s\n", path);
            return false;
        }
        
        LARGE_INTEGER size;
        if (!GetFileSizeEx(hFile, &size)) {
            CloseHandle(hFile);
            return false;
        }
        
        HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) {
            CloseHandle(hFile);
            return false;
        }
        
        void* data = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!data) {
            CloseHandle(hMap);
            CloseHandle(hFile);
            return false;
        }
        
        out->hFile = hFile;
        out->hMap = hMap;
        out->data = data;
        out->size = size.QuadPart;
    #else
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Failed to open file: %s\n", path);
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return false;
        }
        
        void* data = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) {
            close(fd);
            return false;
        }
        
        out->fd = fd;
        out->data = data;
        out->size = st.st_size;
    #endif
    
    return true;
}

void munmap_file(MappedFile* file) {
    #ifdef _WIN32
        UnmapViewOfFile(file->data);
        CloseHandle(file->hMap);
        CloseHandle(file->hFile);
    #else
        munmap(file->data, file->size);
        close(file->fd);
    #endif
}

// Read helpers
struct Buffer {
    uint8_t* data;
    size_t pos;
    size_t size;
};

uint8_t read_u8(Buffer* buf) {
    return buf->data[buf->pos++];
}

uint32_t read_u32(Buffer* buf) {
    uint32_t val = *(uint32_t*)(buf->data + buf->pos);
    buf->pos += 4;
    return val;
}

uint64_t read_u64(Buffer* buf) {
    uint64_t val = *(uint64_t*)(buf->data + buf->pos);
    buf->pos += 8;
    return val;
}

int64_t read_i64(Buffer* buf) {
    int64_t val = *(int64_t*)(buf->data + buf->pos);
    buf->pos += 8;
    return val;
}

float read_f32(Buffer* buf) {
    float val = *(float*)(buf->data + buf->pos);
    buf->pos += 4;
    return val;
}

double read_f64(Buffer* buf) {
    double val = *(double*)(buf->data + buf->pos);
    buf->pos += 8;
    return val;
}

bool read_bool(Buffer* buf) {
    return read_u8(buf) != 0;
}

// Read string (returns pointer into buffer, not null-terminated)
const char* read_string(Buffer* buf, uint64_t* len) {
    *len = read_u64(buf);
    const char* str = (const char*)(buf->data + buf->pos);
    buf->pos += *len;
    return str;
}

// Read array header
void read_array_header(Buffer* buf, uint32_t* type, uint64_t* len) {
    *type = read_u32(buf);
    *len = read_u64(buf);
}

// Skip value based on type
void skip_value(Buffer* buf, uint32_t type) {
    switch (type) {
        case 0: // uint8
            buf->pos += 1;
            break;
        case 1: // int8
            buf->pos += 1;
            break;
        case 2: // uint16
            buf->pos += 2;
            break;
        case 3: // int16
            buf->pos += 2;
            break;
        case 4: // uint32
            buf->pos += 4;
            break;
        case 5: // int32
            buf->pos += 4;
            break;
        case 6: // float32
            buf->pos += 4;
            break;
        case 7: // uint64
            buf->pos += 8;
            break;
        case 8: // int64
            buf->pos += 8;
            break;
        case 9: // float64
            buf->pos += 8;
            break;
        case 10: { // bool
            buf->pos += 1;
            break;
        }
        case 11: { // string
            uint64_t len;
            read_string(buf, &len);
            break;
        }
        case 12: { // array
            uint32_t arr_type = read_u32(buf);
            uint64_t arr_len = read_u64(buf);
            for (uint64_t i = 0; i < arr_len; i++) {
                skip_value(buf, arr_type);
            }
            break;
        }
        default:
            fprintf(stderr, "Unknown value type: %u\n", type);
            break;
    }
}

int main(int argc, char* argv[]) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Real Model Test                                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_gguf_file>\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    printf("Loading model: %s\n\n", model_path);
    
    // Memory map the file
    MappedFile mapped;
    if (!mmap_file(model_path, &mapped)) {
        fprintf(stderr, "Failed to memory-map file\n");
        return 1;
    }
    
    printf("✓ File mapped: %zu bytes\n", mapped.size);
    
    // Parse header
    Buffer buf;
    buf.data = (uint8_t*)mapped.data;
    buf.pos = 0;
    buf.size = mapped.size;
    
    // Read magic
    uint32_t magic = read_u32(&buf);
    if (magic != GGUF_MAGIC) {
        fprintf(stderr, "Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", magic, GGUF_MAGIC);
        munmap_file(&mapped);
        return 1;
    }
    printf("✓ GGUF magic valid\n");
    
    // Read version
    uint32_t version = read_u32(&buf);
    if (version != GGUF_VERSION) {
        fprintf(stderr, "Unsupported GGUF version: %u (expected %d)\n", version, GGUF_VERSION);
        munmap_file(&mapped);
        return 1;
    }
    printf("✓ GGUF version: %u\n", version);
    
    // Read tensor count
    uint64_t tensor_count = read_u64(&buf);
    printf("✓ Tensor count: %llu\n", (unsigned long long)tensor_count);
    
    // Read metadata KV count
    uint64_t metadata_kv_count = read_u64(&buf);
    printf("✓ Metadata KV count: %llu\n", (unsigned long long)metadata_kv_count);
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Metadata                                                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Parse metadata
    for (uint64_t i = 0; i < metadata_kv_count && i < 20; i++) {
        uint64_t key_len;
        const char* key = read_string(&buf, &key_len);
        
        uint32_t value_type = read_u32(&buf);
        
        // Print key
        printf("%.*s = ", (int)key_len, key);
        
        // Print value based on type
        switch (value_type) {
            case 0:  printf("%u (uint8)\n", read_u8(&buf)); break;
            case 1:  printf("%d (int8)\n", (int8_t)read_u8(&buf)); break;
            case 4:  printf("%u (uint32)\n", read_u32(&buf)); break;
            case 5:  printf("%d (int32)\n", (int32_t)read_u32(&buf)); break;
            case 6:  printf("%f (float32)\n", read_f32(&buf)); break;
            case 7:  printf("%llu (uint64)\n", (unsigned long long)read_u64(&buf)); break;
            case 8:  printf("%lld (int64)\n", (long long)read_i64(&buf)); break;
            case 9:  printf("%f (float64)\n", read_f64(&buf)); break;
            case 10: printf("%s (bool)\n", read_bool(&buf) ? "true" : "false"); break;
            case 11: {
                uint64_t str_len;
                const char* str = read_string(&buf, &str_len);
                printf("%.*s (string)\n", (int)str_len, str);
                break;
            }
            case 12: {
                uint32_t arr_type = read_u32(&buf);
                uint64_t arr_len = read_u64(&buf);
                printf("[array of %llu items, type %u]\n", (unsigned long long)arr_len, arr_type);
                // Skip array data
                for (uint64_t j = 0; j < arr_len; j++) {
                    skip_value(&buf, arr_type);
                }
                break;
            }
            default:
                printf("(unknown type %u)\n", value_type);
                skip_value(&buf, value_type);
                break;
        }
    }
    
    if (metadata_kv_count > 20) {
        printf("... (%llu more metadata entries)\n", (unsigned long long)(metadata_kv_count - 20));
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Tensor Info (first 10)                                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Parse tensor info
    size_t tensor_data_size = 0;
    for (uint64_t i = 0; i < tensor_count && i < 10; i++) {
        uint64_t name_len;
        const char* name = read_string(&buf, &name_len);
        
        uint32_t n_dims = read_u32(&buf);
        uint64_t dims[4] = {1, 1, 1, 1};
        for (uint32_t d = 0; d < n_dims; d++) {
            dims[d] = read_u64(&buf);
        }
        
        uint32_t type = read_u32(&buf);
        uint64_t offset = read_u64(&buf);
        
        // Calculate tensor size
        size_t type_size = 4;  // F32 default
        size_t block_size = 1;
        switch (type) {
            case GGML_TYPE_F32:  type_size = 4; block_size = 1; break;
            case GGML_TYPE_F16:  type_size = 2; block_size = 1; break;
            case GGML_TYPE_Q4_0: type_size = 18; block_size = 32; break;
            case GGML_TYPE_Q4_1: type_size = 20; block_size = 32; break;
            case GGML_TYPE_Q5_0: type_size = 22; block_size = 32; break;
            case GGML_TYPE_Q5_1: type_size = 24; block_size = 32; break;
            case GGML_TYPE_Q8_0: type_size = 34; block_size = 32; break;
            case GGML_TYPE_Q8_1: type_size = 36; block_size = 32; break;
            case GGML_TYPE_Q4_K: type_size = 12; block_size = 256; break;
            case GGML_TYPE_Q5_K: type_size = 13; block_size = 256; break;
            case GGML_TYPE_Q6_K: type_size = 14; block_size = 256; break;
            case GGML_TYPE_Q8_K: type_size = 20; block_size = 256; break;
        }
        
        size_t num_elements = dims[0] * dims[1] * dims[2] * dims[3];
        size_t tensor_size = (num_elements / block_size) * type_size;
        tensor_data_size += tensor_size;
        
        printf("%.*s: %s [", (int)name_len, name, ggml_type_name(type));
        for (uint32_t d = 0; d < n_dims; d++) {
            if (d > 0) printf(", ");
            printf("%llu", (unsigned long long)dims[d]);
        }
        printf("] @ offset %llu (%zu bytes)\n", (unsigned long long)offset, tensor_size);
    }
    
    if (tensor_count > 10) {
        printf("... (%llu more tensors)\n", (unsigned long long)(tensor_count - 10));
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Summary                                                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("File size:        %zu bytes (%.2f MB)\n", mapped.size, mapped.size / (1024.0 * 1024.0));
    printf("Tensors:          %llu\n", (unsigned long long)tensor_count);
    printf("Metadata entries: %llu\n", (unsigned long long)metadata_kv_count);
    printf("Tensor data:      ~%zu bytes (%.2f MB)\n", tensor_data_size, tensor_data_size / (1024.0 * 1024.0));
    printf("\n");
    printf("✓ Model loaded successfully!\n");
    printf("\n");
    
    munmap_file(&mapped);
    return 0;
}
