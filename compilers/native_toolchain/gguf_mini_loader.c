// gguf_mini_loader.c - Minimal GGUF loader for RawrXD
// This loader reads GGUF headers without full tensor loading
// Compile: gcc gguf_mini_loader.c -o gguf_mini_loader.exe

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// GGUF magic number: "GGUF" in little-endian
#define GGUF_MAGIC 0x46554747  // 'GGUF'

// GGUF version
#define GGUF_VERSION 3

// GGUF metadata value types
typedef enum {
    GGUF_METADATA_TYPE_UINT8 = 0,
    GGUF_METADATA_TYPE_INT8 = 1,
    GGUF_METADATA_TYPE_UINT16 = 2,
    GGUF_METADATA_TYPE_INT16 = 3,
    GGUF_METADATA_TYPE_UINT32 = 4,
    GGUF_METADATA_TYPE_INT32 = 5,
    GGUF_METADATA_TYPE_FLOAT32 = 6,
    GGUF_METADATA_TYPE_BOOL = 7,
    GGUF_METADATA_TYPE_STRING = 8,
    GGUF_METADATA_TYPE_ARRAY = 9,
    GGUF_METADATA_TYPE_UINT64 = 10,
    GGUF_METADATA_TYPE_INT64 = 11,
    GGUF_METADATA_TYPE_FLOAT64 = 12,
    GGUF_METADATA_TYPE_COUNT
} gguf_metadata_type_t;

// GGUF header structure
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;
#pragma pack(pop)

// Tensor info structure
typedef struct {
    char name[256];
    uint32_t n_dimensions;
    uint64_t dimensions[4];
    uint32_t type;
    uint64_t offset;
} gguf_tensor_info_t;

// Function to read a string from file
bool read_string(FILE* f, char* buffer, size_t max_len) {
    uint64_t len;
    if (fread(&len, sizeof(len), 1, f) != 1) return false;
    
    if (len >= max_len) {
        // Skip the string if too long
        fseek(f, (long)len, SEEK_CUR);
        buffer[0] = '\0';
        return true;
    }
    
    if (fread(buffer, 1, len, f) != len) return false;
    buffer[len] = '\0';
    return true;
}

// Function to skip metadata value based on type
bool skip_metadata_value(FILE* f, uint32_t type) {
    switch (type) {
        case GGUF_METADATA_TYPE_UINT8:
        case GGUF_METADATA_TYPE_INT8:
            fseek(f, 1, SEEK_CUR);
            return true;
        case GGUF_METADATA_TYPE_UINT16:
        case GGUF_METADATA_TYPE_INT16:
            fseek(f, 2, SEEK_CUR);
            return true;
        case GGUF_METADATA_TYPE_UINT32:
        case GGUF_METADATA_TYPE_INT32:
        case GGUF_METADATA_TYPE_FLOAT32:
            fseek(f, 4, SEEK_CUR);
            return true;
        case GGUF_METADATA_TYPE_UINT64:
        case GGUF_METADATA_TYPE_INT64:
        case GGUF_METADATA_TYPE_FLOAT64:
            fseek(f, 8, SEEK_CUR);
            return true;
        case GGUF_METADATA_TYPE_BOOL:
            fseek(f, 1, SEEK_CUR);
            return true;
        case GGUF_METADATA_TYPE_STRING: {
            char buffer[256];
            return read_string(f, buffer, sizeof(buffer));
        }
        case GGUF_METADATA_TYPE_ARRAY: {
            uint32_t elem_type;
            uint64_t count;
            if (fread(&elem_type, sizeof(elem_type), 1, f) != 1) return false;
            if (fread(&count, sizeof(count), 1, f) != 1) return false;
            
            // Skip array elements
            for (uint64_t i = 0; i < count; i++) {
                if (!skip_metadata_value(f, elem_type)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

// Load and validate GGUF file
int load_gguf(const char* filename, bool verbose) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("[ERROR] Cannot open file: %s\n", filename);
        return 1;
    }
    
    printf("[INFO] Loading GGUF file: %s\n", filename);
    
    // Read header
    gguf_header_t header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        printf("[ERROR] Failed to read GGUF header\n");
        fclose(f);
        return 1;
    }
    
    // Validate magic
    if (header.magic != GGUF_MAGIC) {
        printf("[ERROR] Invalid GGUF magic: 0x%08X (expected 0x%08X)\n", 
               header.magic, GGUF_MAGIC);
        fclose(f);
        return 1;
    }
    
    printf("[PASS] GGUF magic validated\n");
    printf("[INFO] Version: %u\n", header.version);
    printf("[INFO] Tensor count: %llu\n", (unsigned long long)header.tensor_count);
    printf("[INFO] Metadata KV pairs: %llu\n", (unsigned long long)header.metadata_kv_count);
    
    // Validate version
    if (header.version != GGUF_VERSION) {
        printf("[WARN] GGUF version %u may not be fully supported (expected %d)\n", 
               header.version, GGUF_VERSION);
    }
    
    // Read metadata
    if (verbose) {
        printf("\n[METADATA]\n");
    }
    
    for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
        char key[256];
        if (!read_string(f, key, sizeof(key))) {
            printf("[ERROR] Failed to read metadata key %llu\n", (unsigned long long)i);
            fclose(f);
            return 1;
        }
        
        uint32_t value_type;
        if (fread(&value_type, sizeof(value_type), 1, f) != 1) {
            printf("[ERROR] Failed to read metadata value type\n");
            fclose(f);
            return 1;
        }
        
        if (verbose) {
            printf("  %s (type=%u)\n", key, value_type);
        }
        
        // Skip the value
        if (!skip_metadata_value(f, value_type)) {
            printf("[ERROR] Failed to skip metadata value\n");
            fclose(f);
            return 1;
        }
    }
    
    // Read tensor info
    if (verbose) {
        printf("\n[TENSORS]\n");
    }
    
    gguf_tensor_info_t* tensors = NULL;
    if (header.tensor_count > 0) {
        tensors = calloc(header.tensor_count, sizeof(gguf_tensor_info_t));
        if (!tensors) {
            printf("[ERROR] Failed to allocate tensor info array\n");
            fclose(f);
            return 1;
        }
    }
    
    for (uint64_t i = 0; i < header.tensor_count; i++) {
        if (!read_string(f, tensors[i].name, sizeof(tensors[i].name))) {
            printf("[ERROR] Failed to read tensor name %llu\n", (unsigned long long)i);
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (fread(&tensors[i].n_dimensions, sizeof(tensors[i].n_dimensions), 1, f) != 1) {
            printf("[ERROR] Failed to read tensor dimensions count\n");
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (tensors[i].n_dimensions > 4) {
            printf("[ERROR] Invalid dimension count: %u\n", tensors[i].n_dimensions);
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (fread(tensors[i].dimensions, sizeof(uint64_t), tensors[i].n_dimensions, f) != 
            tensors[i].n_dimensions) {
            printf("[ERROR] Failed to read tensor dimensions\n");
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (fread(&tensors[i].type, sizeof(tensors[i].type), 1, f) != 1) {
            printf("[ERROR] Failed to read tensor type\n");
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (fread(&tensors[i].offset, sizeof(tensors[i].offset), 1, f) != 1) {
            printf("[ERROR] Failed to read tensor offset\n");
            free(tensors);
            fclose(f);
            return 1;
        }
        
        if (verbose) {
            printf("  %s: type=%u, dims=%u, offset=%llu\n", 
                   tensors[i].name, tensors[i].type, tensors[i].n_dimensions,
                   (unsigned long long)tensors[i].offset);
        }
    }
    
    // Calculate data offset (must be aligned to 32 bytes)
    long current_pos = ftell(f);
    uint64_t data_offset = (current_pos + 31) & ~31;
    
    printf("\n[SUMMARY]\n");
    printf("  File: %s\n", filename);
    printf("  Version: %u\n", header.version);
    printf("  Tensors: %llu\n", (unsigned long long)header.tensor_count);
    printf("  Metadata entries: %llu\n", (unsigned long long)header.metadata_kv_count);
    printf("  Data offset: %llu bytes\n", (unsigned long long)data_offset);
    printf("  Status: VALID\n");
    
    // Cleanup
    free(tensors);
    fclose(f);
    
    return 0;
}

void print_usage(const char* program) {
    printf("Usage: %s [options] <model.gguf>\n", program);
    printf("Options:\n");
    printf("  -v, --verbose    Show detailed metadata and tensor info\n");
    printf("  -h, --help       Show this help message\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    bool verbose = false;
    const char* filename = NULL;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        }
    }
    
    if (!filename) {
        printf("[ERROR] No GGUF file specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    return load_gguf(filename, verbose);
}
