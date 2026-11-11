// Debug GGUF file structure
#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <file.gguf>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Cannot open file\n");
        return 1;
    }
    
    // Read header
    uint32_t magic, version;
    uint64_t tensor_count, metadata_count;
    
    fread(&magic, 4, 1, fp);
    fread(&version, 4, 1, fp);
    fread(&tensor_count, 8, 1, fp);
    fread(&metadata_count, 8, 1, fp);
    
    printf("Magic: 0x%08X (expected: 0x46554747)\n", magic);
    printf("Version: %u\n", version);
    printf("Tensor count: %llu\n", (unsigned long long)tensor_count);
    printf("Metadata count: %llu\n", (unsigned long long)metadata_count);
    printf("Header size: %zu bytes\n", sizeof(magic) + sizeof(version) + sizeof(tensor_count) + sizeof(metadata_count));
    printf("Current position: %ld\n", ftell(fp));
    
    // Read first few metadata entries
    printf("\n=== First 5 metadata entries ===\n");
    for (int i = 0; i < 5 && i < (int)metadata_count; i++) {
        uint64_t key_len;
        if (fread(&key_len, 8, 1, fp) != 1) break;
        
        printf("\nEntry %d:\n", i);
        printf("  Key length: %llu\n", (unsigned long long)key_len);
        
        if (key_len > 0 && key_len < 256) {
            char key[256];
            fread(key, 1, key_len, fp);
            key[key_len] = '\0';
            printf("  Key: '%s'\n", key);
        } else if (key_len > 0) {
            printf("  Key: (too long, skipping %llu bytes)\n", (unsigned long long)key_len);
            fseek(fp, (long)key_len, SEEK_CUR);
        }
        
        // Read value type
        uint32_t val_type;
        fread(&val_type, 4, 1, fp);
        printf("  Value type: %u\n", val_type);
        
        // Skip value based on type
        switch(val_type) {
            case 0: case 1: fseek(fp, 1, SEEK_CUR); break;  // uint8/int8
            case 2: case 3: fseek(fp, 2, SEEK_CUR); break;  // uint16/int16
            case 4: case 5: case 6: fseek(fp, 4, SEEK_CUR); break;  // uint32/int32/float32
            case 10: case 11: case 12: fseek(fp, 8, SEEK_CUR); break; // uint64/int64/float64
            case 7: {  // bool
                uint8_t b;
                fread(&b, 1, 1, fp);
                printf("    Bool value: %u\n", b);
                break;
            }
            case 8: {  // string
                uint64_t str_len;
                fread(&str_len, 8, 1, fp);
                printf("    String length: %llu\n", (unsigned long long)str_len);
                if (str_len > 0 && str_len < 256) {
                    char str[256];
                    fread(str, 1, str_len, fp);
                    str[str_len] = '\0';
                    printf("    String value: '%s'\n", str);
                } else if (str_len > 0) {
                    fseek(fp, (long)str_len, SEEK_CUR);
                }
                break;
            }
            case 9: {  // array
                uint32_t arr_type;
                uint64_t arr_len;
                fread(&arr_type, 4, 1, fp);
                fread(&arr_len, 8, 1, fp);
                printf("    Array type: %u, length: %llu\n", arr_type, (unsigned long long)arr_len);
                // Skip array data
                size_t elem_size = 4;
                fseek(fp, (long)(arr_len * elem_size), SEEK_CUR);
                break;
            }
            default:
                printf("    Unknown type, skipping 4 bytes\n");
                fseek(fp, 4, SEEK_CUR);
        }
    }
    
    printf("\n=== First 3 tensor infos ===\n");
    printf("Current position: %ld\n", ftell(fp));
    
    for (int i = 0; i < 3 && i < (int)tensor_count; i++) {
        uint64_t name_len;
        if (fread(&name_len, 8, 1, fp) != 1) break;
        
        printf("\nTensor %d:\n", i);
        printf("  Name length: %llu\n", (unsigned long long)name_len);
        
        if (name_len > 0 && name_len < 256) {
            char name[256];
            fread(name, 1, name_len, fp);
            name[name_len] = '\0';
            printf("  Name: '%s'\n", name);
        } else if (name_len > 0) {
            printf("  Name: (too long, skipping)\n");
            fseek(fp, (long)name_len, SEEK_CUR);
        }
        
        uint32_t n_dims;
        fread(&n_dims, 4, 1, fp);
        printf("  Num dims: %u\n", n_dims);
        
        printf("  Dims: [");
        for (uint32_t j = 0; j < n_dims && j < 4; j++) {
            uint64_t dim;
            fread(&dim, 8, 1, fp);
            printf("%llu", (unsigned long long)dim);
            if (j < n_dims - 1) printf(", ");
        }
        printf("]\n");
        
        uint32_t type;
        fread(&type, 4, 1, fp);
        printf("  Type: %u\n", type);
        
        uint64_t offset;
        fread(&offset, 8, 1, fp);
        printf("  Offset: %llu\n", (unsigned long long)offset);
    }
    
    fclose(fp);
    return 0;
}
