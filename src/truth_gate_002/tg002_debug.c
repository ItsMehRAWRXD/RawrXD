/* tg002_debug.c - Debug version to find the hang */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#define GGUF_MAGIC 0x46554747

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
    uint64_t n_elements;
    uint64_t size;
} tensor_info_t;

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    void* base_addr;
    size_t file_size;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    tensor_info_t* tensors;
    uint64_t data_offset;
} gguf_context_t;

int main(int argc, char* argv[]) {
    printf("Debug: Starting...\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    printf("Debug: Opening %s\n", model_path);
    
    /* Open file */
    HANDLE file_handle = CreateFileA(model_path, GENERIC_READ, FILE_SHARE_READ,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        printf("Debug: Failed to open file\n");
        return 1;
    }
    printf("Debug: File opened\n");
    
    /* Get size */
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file_handle, &size)) {
        printf("Debug: Failed to get file size\n");
        CloseHandle(file_handle);
        return 1;
    }
    printf("Debug: File size: %llu bytes\n", (unsigned long long)size.QuadPart);
    
    /* Create mapping */
    HANDLE map_handle = CreateFileMappingA(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map_handle) {
        printf("Debug: Failed to create file mapping\n");
        CloseHandle(file_handle);
        return 1;
    }
    printf("Debug: File mapping created\n");
    
    /* Map view */
    void* base_addr = MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!base_addr) {
        printf("Debug: Failed to map view\n");
        CloseHandle(map_handle);
        CloseHandle(file_handle);
        return 1;
    }
    printf("Debug: File mapped at %p\n", base_addr);
    
    /* Read header */
    uint8_t* data = (uint8_t*)base_addr;
    uint32_t magic = *(uint32_t*)data;
    printf("Debug: Magic: 0x%08X (expected 0x%08X)\n", magic, GGUF_MAGIC);
    
    if (magic != GGUF_MAGIC) {
        printf("Debug: Invalid magic!\n");
        UnmapViewOfFile(base_addr);
        CloseHandle(map_handle);
        CloseHandle(file_handle);
        return 1;
    }
    
    uint32_t version = *(uint32_t*)(data + 4);
    uint64_t tensor_count = *(uint64_t*)(data + 8);
    uint64_t metadata_kv_count = *(uint64_t*)(data + 16);
    
    printf("Debug: Version: %u\n", version);
    printf("Debug: Tensor count: %llu\n", (unsigned long long)tensor_count);
    printf("Debug: Metadata KV count: %llu\n", (unsigned long long)metadata_kv_count);
    
    /* Parse metadata with timeout protection */
    printf("Debug: Parsing metadata...\n");
    size_t pos = 24;
    uint64_t parsed_kv = 0;
    
    for (uint64_t i = 0; i < metadata_kv_count && i < 10000; i++) {
        if (pos + 8 > (size_t)size.QuadPart) {
            printf("Debug: Metadata parsing overflow at pos %zu\n", pos);
            break;
        }
        
        uint64_t key_len = *(uint64_t*)(data + pos);
        pos += 8;
        
        if (key_len > 1000 || pos + key_len > (size_t)size.QuadPart) {
            printf("Debug: Invalid key length %llu at pos %zu\n", (unsigned long long)key_len, pos);
            break;
        }
        
        pos += key_len;
        
        if (pos + 4 > (size_t)size.QuadPart) {
            printf("Debug: Metadata parsing overflow before val_type\n");
            break;
        }
        
        uint32_t val_type = *(uint32_t*)(data + pos);
        pos += 4;
        
        /* Skip value based on type */
        switch (val_type) {
            case 0: case 1: case 10: 
                pos += 1; 
                break;
            case 2: case 3: 
                pos += 2; 
                break;
            case 4: case 5: case 6: 
                pos += 4; 
                break;
            case 7: case 8: case 9: 
                pos += 8; 
                break;
            case 11: { 
                if (pos + 8 > (size_t)size.QuadPart) { pos = (size_t)size.QuadPart; break; }
                uint64_t len = *(uint64_t*)(data + pos); 
                pos += 8 + len; 
                break; 
            }
            case 12: { 
                if (pos + 12 > (size_t)size.QuadPart) { pos = (size_t)size.QuadPart; break; }
                pos += 4; 
                uint64_t arr_len = *(uint64_t*)(data + pos); 
                pos += 8 + arr_len * 4; 
                break; 
            }
            default:
                printf("Debug: Unknown value type %u at pos %zu\n", val_type, pos);
                pos += 4;
                break;
        }
        
        parsed_kv++;
        
        if (i % 100 == 0) {
            printf("Debug: Parsed %llu/%llu metadata entries, pos=%zu\n", 
                   (unsigned long long)parsed_kv, (unsigned long long)metadata_kv_count, pos);
        }
    }
    
    printf("Debug: Metadata parsing complete. Parsed %llu entries, final pos=%zu\n", 
           (unsigned long long)parsed_kv, pos);
    
    /* Parse tensors */
    printf("Debug: Parsing tensors...\n");
    uint64_t parsed_tensors = 0;
    
    for (uint64_t i = 0; i < tensor_count && i < 1000; i++) {
        if (pos + 8 > (size_t)size.QuadPart) {
            printf("Debug: Tensor parsing overflow at pos %zu\n", pos);
            break;
        }
        
        uint64_t name_len = *(uint64_t*)(data + pos);
        pos += 8 + name_len + 4; /* name + n_dims */
        
        if (pos > (size_t)size.QuadPart) {
            printf("Debug: Tensor parsing overflow after name\n");
            break;
        }
        
        /* Skip dims */
        uint32_t n_dims = *(uint32_t*)(data + pos - 4);
        pos += n_dims * 8 + 4 + 8; /* dims + type + offset */
        
        parsed_tensors++;
        
        if (i % 50 == 0) {
            printf("Debug: Parsed %llu/%llu tensors, pos=%zu\n", 
                   (unsigned long long)parsed_tensors, (unsigned long long)tensor_count, pos);
        }
    }
    
    printf("Debug: Tensor parsing complete. Parsed %llu tensors\n", (unsigned long long)parsed_tensors);
    
    /* Cleanup */
    UnmapViewOfFile(base_addr);
    CloseHandle(map_handle);
    CloseHandle(file_handle);
    
    printf("Debug: Complete!\n");
    return 0;
}
