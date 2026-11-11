/* tg002_minimal.c - Minimal working GGUF loader */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#define GGUF_MAGIC 0x46554747

static uint64_t get_u64(uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | 
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint32_t get_u32(uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.gguf>\n", argv[0]);
        return 1;
    }
    
    HANDLE h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open\n");
        return 1;
    }
    
    LARGE_INTEGER size;
    GetFileSizeEx(h, &size);
    
    HANDLE map = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    uint8_t* data = (uint8_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    
    printf("File: %s (%llu bytes)\n\n", argv[1], (unsigned long long)size.QuadPart);
    
    /* Header */
    uint32_t magic = get_u32(data);
    printf("Magic: 0x%08X (%s)\n", magic, magic == GGUF_MAGIC ? "OK" : "FAIL");
    
    uint32_t version = get_u32(data + 4);
    printf("Version: %u\n", version);
    
    uint64_t n_tensors = get_u64(data + 8);
    uint64_t n_metadata = get_u64(data + 16);
    printf("Tensors: %llu\n", (unsigned long long)n_tensors);
    printf("Metadata: %llu\n\n", (unsigned long long)n_metadata);
    
    /* Parse metadata */
    size_t pos = 24;
    printf("=== Metadata ===\n");
    
    for (uint64_t i = 0; i < n_metadata && i < 10; i++) {
        /* Key */
        uint64_t key_len = get_u64(data + pos);
        pos += 8;
        
        printf("[%llu] Key (%llu): \"", (unsigned long long)i, (unsigned long long)key_len);
        for (uint64_t j = 0; j < key_len && j < 50; j++) {
            printf("%c", data[pos + j]);
        }
        printf("\"\n");
        pos += key_len;
        
        /* Value type */
        uint32_t val_type = get_u32(data + pos);
        pos += 4;
        printf("    Type: %u\n", val_type);
        
        /* Skip value */
        switch (val_type) {
            case 0: case 1: case 10: pos += 1; break;
            case 2: case 3: pos += 2; break;
            case 4: case 5: case 6: 
                printf("    Value: %u\n", get_u32(data + pos));
                pos += 4; 
                break;
            case 7: case 8: case 9: 
                printf("    Value: %llu\n", (unsigned long long)get_u64(data + pos));
                pos += 8; 
                break;
            case 11: {
                uint64_t str_len = get_u64(data + pos);
                pos += 8;
                printf("    String (%llu): \"", (unsigned long long)str_len);
                for (uint64_t j = 0; j < str_len && j < 50; j++) {
                    printf("%c", data[pos + j]);
                }
                printf("\"\n");
                pos += str_len;
                break;
            }
            case 12: {
                uint32_t arr_type = get_u32(data + pos);
                pos += 4;
                uint64_t arr_len = get_u64(data + pos);
                pos += 8;
                printf("    Array: type=%u, len=%llu\n", arr_type, (unsigned long long)arr_len);
                /* Skip array */
                size_t elem_size = 1;
                switch (arr_type) {
                    case 4: case 5: case 6: elem_size = 4; break;
                    case 7: case 8: case 9: elem_size = 8; break;
                }
                pos += arr_len * elem_size;
                break;
            }
            default:
                printf("    Unknown type!\n");
                return 1;
        }
        
        printf("    Pos: %zu\n\n", pos);
    }
    
    /* Parse tensors */
    printf("=== Tensors (first 5) ===\n");
    for (uint64_t i = 0; i < n_tensors && i < 5; i++) {
        uint64_t name_len = get_u64(data + pos);
        pos += 8;
        
        printf("[%llu] Name (%llu): \"", (unsigned long long)i, (unsigned long long)name_len);
        for (uint64_t j = 0; j < name_len && j < 50; j++) {
            printf("%c", data[pos + j]);
        }
        printf("\"\n");
        pos += name_len;
        
        uint32_t n_dims = get_u32(data + pos);
        pos += 4;
        printf("    Dims: %u [", n_dims);
        for (uint32_t j = 0; j < n_dims; j++) {
            printf("%llu", (unsigned long long)get_u64(data + pos));
            pos += 8;
            if (j < n_dims - 1) printf(", ");
        }
        printf("]\n");
        
        uint32_t tensor_type = get_u32(data + pos);
        pos += 4;
        uint64_t tensor_offset = get_u64(data + pos);
        pos += 8;
        printf("    Type: %u, Offset: %llu\n", tensor_type, (unsigned long long)tensor_offset);
        printf("    Pos: %zu\n\n", pos);
    }
    
    UnmapViewOfFile(data);
    CloseHandle(map);
    CloseHandle(h);
    
    return 0;
}
