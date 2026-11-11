/* tg002_trace.c - Trace GGUF parsing step by step */
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
    
    printf("File size: %llu\n", (unsigned long long)size.QuadPart);
    printf("\n=== Header ===\n");
    printf("Magic: 0x%08X\n", get_u32(data));
    printf("Version: %u\n", get_u32(data + 4));
    printf("Tensor count: %llu\n", (unsigned long long)get_u64(data + 8));
    printf("Metadata count: %llu\n", (unsigned long long)get_u64(data + 16));
    
    size_t pos = 24;
    uint64_t metadata_count = get_u64(data + 16);
    
    printf("\n=== Metadata Entries ===\n");
    for (uint64_t i = 0; i < metadata_count && i < 5; i++) {
        printf("\n--- Entry %llu at pos %zu ---\n", (unsigned long long)i, pos);
        
        /* Key length */
        uint64_t key_len = get_u64(data + pos);
        printf("Key length raw bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
               data[pos], data[pos+1], data[pos+2], data[pos+3],
               data[pos+4], data[pos+5], data[pos+6], data[pos+7]);
        printf("Key length: %llu\n", (unsigned long long)key_len);
        pos += 8;
        
        if (key_len > 1000) {
            printf("ERROR: Key length too large!\n");
            break;
        }
        
        /* Key */
        printf("Key: \"");
        for (uint64_t j = 0; j < key_len && j < 50; j++) {
            printf("%c", data[pos + j]);
        }
        printf("\"\n");
        pos += key_len;
        
        /* Value type */
        uint32_t val_type = get_u32(data + pos);
        printf("Value type: %u\n", val_type);
        pos += 4;
        
        /* Skip value */
        switch (val_type) {
            case 0: case 1: case 10: /* uint8, int8, bool */
                printf("Value: %u (uint8)\n", data[pos]);
                pos += 1;
                break;
            case 2: case 3: /* uint16, int16 */
                pos += 2;
                break;
            case 4: case 5: case 6: /* uint32, int32, float32 */
                printf("Value: %u\n", get_u32(data + pos));
                pos += 4;
                break;
            case 7: case 8: case 9: /* uint64, int64, float64 */
                pos += 8;
                break;
            case 11: { /* string */
                uint64_t str_len = get_u64(data + pos);
                printf("String length: %llu\n", (unsigned long long)str_len);
                pos += 8;
                printf("String value: \"");
                for (uint64_t j = 0; j < str_len && j < 50; j++) {
                    printf("%c", data[pos + j]);
                }
                printf("\"\n");
                pos += str_len;
                break;
            }
            case 12: { /* array */
                uint32_t arr_type = get_u32(data + pos);
                pos += 4;
                uint64_t arr_len = get_u64(data + pos);
                pos += 8;
                printf("Array: type=%u, len=%llu\n", arr_type, (unsigned long long)arr_len);
                /* Skip array data */
                size_t elem_size = 1;
                switch (arr_type) {
                    case 4: case 5: case 6: elem_size = 4; break;
                    case 7: case 8: case 9: elem_size = 8; break;
                }
                pos += arr_len * elem_size;
                break;
            }
            default:
                printf("Unknown type!\n");
                return 1;
        }
        
        printf("New pos: %zu\n", pos);
    }
    
    printf("\n=== First Tensor ===\n");
    printf("Pos before tensor: %zu\n", pos);
    
    uint64_t name_len = get_u64(data + pos);
    printf("Tensor name length: %llu\n", (unsigned long long)name_len);
    pos += 8;
    
    printf("Tensor name: \"");
    for (uint64_t j = 0; j < name_len && j < 50; j++) {
        printf("%c", data[pos + j]);
    }
    printf("\"\n");
    pos += name_len;
    
    uint32_t n_dims = get_u32(data + pos);
    printf("Num dims: %u\n", n_dims);
    pos += 4;
    
    printf("Dims: ");
    for (uint32_t i = 0; i < n_dims; i++) {
        printf("%llu ", (unsigned long long)get_u64(data + pos));
        pos += 8;
    }
    printf("\n");
    
    uint32_t tensor_type = get_u32(data + pos);
    printf("Tensor type: %u\n", tensor_type);
    pos += 4;
    
    uint64_t tensor_offset = get_u64(data + pos);
    printf("Tensor offset: %llu\n", (unsigned long long)tensor_offset);
    pos += 8;
    
    UnmapViewOfFile(data);
    CloseHandle(map);
    CloseHandle(h);
    
    return 0;
}
