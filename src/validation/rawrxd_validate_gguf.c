//=============================================================================
// rawrxd_validate_gguf.c
// GGUF Format Validation Implementation
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>

// GGUF magic number
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
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S = 19,
    GGML_TYPE_IQ4_NL = 20,
    GGML_TYPE_IQ3_S = 21,
    GGML_TYPE_IQ4_XS = 22,
    GGML_TYPE_I8 = 23,
    GGML_TYPE_I16 = 24,
    GGML_TYPE_I32 = 25,
    GGML_TYPE_I64 = 26,
    GGML_TYPE_F64 = 27,
    GGML_TYPE_IQ1_M = 28,
    GGML_TYPE_COUNT = 29,
};

static const char* ggml_type_name(int type) {
    switch (type) {
        case GGML_TYPE_F32: return "F32";
        case GGML_TYPE_F16: return "F16";
        case GGML_TYPE_Q4_0: return "Q4_0";
        case GGML_TYPE_Q4_1: return "Q4_1";
        case GGML_TYPE_Q5_0: return "Q5_0";
        case GGML_TYPE_Q5_1: return "Q5_1";
        case GGML_TYPE_Q8_0: return "Q8_0";
        case GGML_TYPE_Q8_1: return "Q8_1";
        case GGML_TYPE_Q2_K: return "Q2_K";
        case GGML_TYPE_Q3_K: return "Q3_K";
        case GGML_TYPE_Q4_K: return "Q4_K";
        case GGML_TYPE_Q5_K: return "Q5_K";
        case GGML_TYPE_Q6_K: return "Q6_K";
        case GGML_TYPE_Q8_K: return "Q8_K";
        default: return "UNKNOWN";
    }
}

static size_t ggml_type_size(int type) {
    switch (type) {
        case GGML_TYPE_F32: return 4;
        case GGML_TYPE_F16: return 2;
        case GGML_TYPE_Q4_0: return 18;  // 2 (scale) + 16 (qs)
        case GGML_TYPE_Q4_1: return 20;  // 2*2 (scales) + 16 (qs)
        case GGML_TYPE_Q5_0: return 22;  // 2 (scale) + 4 (qh) + 16 (qs)
        case GGML_TYPE_Q5_1: return 24;  // 2*2 (scales) + 4 (qh) + 16 (qs)
        case GGML_TYPE_Q8_0: return 34;  // 2 (scale) + 32 (qs)
        case GGML_TYPE_Q8_1: return 36;  // 4*2 (scales) + 32 (qs)
        default: return 0;
    }
}

static int ggml_blck_size(int type) {
    switch (type) {
        case GGML_TYPE_F32:
        case GGML_TYPE_F16:
        case GGML_TYPE_I8:
        case GGML_TYPE_I16:
        case GGML_TYPE_I32:
        case GGML_TYPE_I64:
        case GGML_TYPE_F64:
            return 1;
        case GGML_TYPE_Q4_0:
        case GGML_TYPE_Q4_1:
        case GGML_TYPE_Q5_0:
        case GGML_TYPE_Q5_1:
        case GGML_TYPE_Q8_0:
        case GGML_TYPE_Q8_1:
            return 32;
        default:
            return 0;
    }
}

//=============================================================================
// GGUF Header Validation
//=============================================================================

rawrxd_test_result rawrxd_validate_gguf_header(const char* path) {
    if (!path) {
        printf("  [FAIL] No path provided\n");
        return RAWRXD_TEST_FAIL;
    }
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("  [FAIL] Cannot open file: %s\n", path);
        return RAWRXD_TEST_FAIL;
    }
    
    // Read header
    u32 magic, version, n_tensors, n_kv;
    if (fread(&magic, 4, 1, f) != 1) {
        printf("  [FAIL] Cannot read magic\n");
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    if (magic != GGUF_MAGIC) {
        printf("  [FAIL] Invalid magic: 0x%08X (expected 0x%08X)\n", magic, GGUF_MAGIC);
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    if (fread(&version, 4, 1, f) != 1) {
        printf("  [FAIL] Cannot read version\n");
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    if (version != 2 && version != 3) {
        printf("  [FAIL] Unsupported version: %u (expected 2 or 3)\n", version);
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    if (fread(&n_tensors, 8, 1, f) != 1) {
        printf("  [FAIL] Cannot read tensor count\n");
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    if (fread(&n_kv, 8, 1, f) != 1) {
        printf("  [FAIL] Cannot read KV count\n");
        fclose(f);
        return RAWRXD_TEST_FAIL;
    }
    
    printf("  [INFO] Magic: OK, Version: %u, Tensors: %llu, KV pairs: %llu\n",
           version, (unsigned long long)n_tensors, (unsigned long long)n_kv);
    
    fclose(f);
    return RAWRXD_TEST_PASS;
}

rawrxd_test_result rawrxd_validate_gguf_metadata(const char* path) {
    if (!path) return RAWRXD_TEST_FAIL;
    
    FILE* f = fopen(path, "rb");
    if (!f) return RAWRXD_TEST_FAIL;
    
    // Skip header
    u32 magic, version;
    u64 n_tensors, n_kv;
    fread(&magic, 4, 1, f);
    fread(&version, 4, 1, f);
    fread(&n_tensors, 8, 1, f);
    fread(&n_kv, 8, 1, f);
    
    // Check for required metadata keys
    bool has_arch = false;
    bool has_quant = false;
    bool has_vocab = false;
    
    // Skip KV pairs (simplified - just count)
    for (u64 i = 0; i < n_kv && i < 1000; i++) {
        u64 key_len;
        if (fread(&key_len, 8, 1, f) != 1) break;
        
        if (key_len > 256) {
            printf("  [WARN] Suspicious key length: %llu\n", (unsigned long long)key_len);
            break;
        }
        
        char key[256];
        size_t to_read = key_len < 255 ? key_len : 255;
        if (fread(key, 1, to_read, f) != to_read) break;
        key[to_read] = '\0';
        
        // Skip remaining key bytes
        if (key_len > to_read) {
            fseek(f, (long)(key_len - to_read), SEEK_CUR);
        }
        
        // Check for important keys
        if (strcmp(key, "general.architecture") == 0) has_arch = true;
        if (strstr(key, "quant") != NULL) has_quant = true;
        if (strstr(key, "vocab") != NULL) has_vocab = true;
        
        // Skip value (simplified)
        u32 value_type;
        if (fread(&value_type, 4, 1, f) != 1) break;
        
        // Skip value based on type
        switch (value_type) {
            case 0: { u8 v; fread(&v, 1, 1, f); } break;  // UINT8
            case 1: { u8 v; fread(&v, 1, 1, f); } break;  // INT8
            case 2: { u32 v; fread(&v, 4, 1, f); } break;  // UINT32
            case 3: { i32 v; fread(&v, 4, 1, f); } break;  // INT32
            case 4: { f32 v; fread(&v, 4, 1, f); } break;  // FLOAT32
            case 5: { u64 v; fread(&v, 8, 1, f); } break;  // UINT64
            case 6: { i64 v; fread(&v, 8, 1, f); } break;  // INT64
            case 7: { f64 v; fread(&v, 8, 1, f); } break;  // FLOAT64
            case 8: {  // BOOL
                u8 v; fread(&v, 1, 1, f);
            } break;
            case 9: {  // STRING
                u64 len;
                fread(&len, 8, 1, f);
                fseek(f, (long)len, SEEK_CUR);
            } break;
            default:
                // Skip unknown types
                break;
        }
    }
    
    fclose(f);
    
    printf("  [INFO] Metadata: arch=%s, quant=%s, vocab=%s\n",
           has_arch ? "yes" : "no",
           has_quant ? "yes" : "no",
           has_vocab ? "yes" : "no");
    
    if (!has_arch) {
        printf("  [WARN] Missing 'general.architecture' key\n");
    }
    
    return RAWRXD_TEST_PASS;
}

rawrxd_test_result rawrxd_validate_gguf_tensors(const char* path) {
    if (!path) return RAWRXD_TEST_FAIL;
    
    FILE* f = fopen(path, "rb");
    if (!f) return RAWRXD_TEST_FAIL;
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Skip header
    u32 magic, version;
    u64 n_tensors, n_kv;
    fread(&magic, 4, 1, f);
    fread(&version, 4, 1, f);
    fread(&n_tensors, 8, 1, f);
    fread(&n_kv, 8, 1, f);
    
    // Skip KV pairs
    for (u64 i = 0; i < n_kv && i < 10000; i++) {
        u64 key_len;
        if (fread(&key_len, 8, 1, f) != 1) break;
        fseek(f, (long)key_len, SEEK_CUR);
        
        u32 value_type;
        if (fread(&value_type, 4, 1, f) != 1) break;
        
        switch (value_type) {
            case 0: case 1: fseek(f, 1, SEEK_CUR); break;
            case 2: case 3: fseek(f, 4, SEEK_CUR); break;
            case 4: fseek(f, 4, SEEK_CUR); break;
            case 5: case 6: fseek(f, 8, SEEK_CUR); break;
            case 7: fseek(f, 8, SEEK_CUR); break;
            case 8: fseek(f, 1, SEEK_CUR); break;
            case 9: {
                u64 len;
                fread(&len, 8, 1, f);
                fseek(f, (long)len, SEEK_CUR);
            } break;
            default: break;
        }
    }
    
    // Validate tensors
    u64 data_offset = 0;
    u32 valid_tensors = 0;
    u32 invalid_tensors = 0;
    
    for (u64 i = 0; i < n_tensors && i < 10000; i++) {
        // Read tensor name
        u64 name_len;
        if (fread(&name_len, 8, 1, f) != 1) break;
        
        if (name_len > 256) {
            printf("  [WARN] Tensor %llu: suspicious name length %llu\n",
                   (unsigned long long)i, (unsigned long long)name_len);
            invalid_tensors++;
            break;
        }
        
        char name[256];
        size_t to_read = name_len < 255 ? name_len : 255;
        if (fread(name, 1, to_read, f) != to_read) break;
        name[to_read] = '\0';
        if (name_len > to_read) {
            fseek(f, (long)(name_len - to_read), SEEK_CUR);
        }
        
        // Read dimensions
        u32 n_dims;
        if (fread(&n_dims, 4, 1, f) != 1) break;
        
        if (n_dims < 1 || n_dims > 4) {
            printf("  [WARN] Tensor '%s': invalid dimensions count %u\n", name, n_dims);
            invalid_tensors++;
            continue;
        }
        
        u64 dims[4];
        u64 total_elements = 1;
        for (u32 d = 0; d < n_dims; d++) {
            if (fread(&dims[d], 8, 1, f) != 1) break;
            total_elements *= dims[d];
        }
        
        // Read type
        u32 type;
        if (fread(&type, 4, 1, f) != 1) break;
        
        if (type >= GGML_TYPE_COUNT) {
            printf("  [WARN] Tensor '%s': invalid type %u\n", name, type);
            invalid_tensors++;
            continue;
        }
        
        // Read offset
        u64 offset;
        if (fread(&offset, 8, 1, f) != 1) break;
        
        // Calculate expected size
        size_t type_size = ggml_type_size(type);
        int blck_size = ggml_blck_size(type);
        u64 tensor_size = (total_elements / blck_size) * type_size;
        
        // Validate offset
        if (data_offset == 0) {
            data_offset = offset;
        }
        
        if (offset < data_offset || offset + tensor_size > (u64)file_size) {
            printf("  [WARN] Tensor '%s': offset %llu out of bounds (file size: %ld)\n",
                   name, (unsigned long long)offset, file_size);
            invalid_tensors++;
            continue;
        }
        
        valid_tensors++;
    }
    
    fclose(f);
    
    printf("  [INFO] Tensors: %u valid, %u invalid\n", valid_tensors, invalid_tensors);
    
    return invalid_tensors == 0 ? RAWRXD_TEST_PASS : RAWRXD_TEST_FAIL;
}

rawrxd_gguf_validation* rawrxd_validate_gguf_full(const char* path) {
    rawrxd_gguf_validation* val = rawrxd_alloc(sizeof(rawrxd_gguf_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->model_name = path;
    
    // Run all GGUF tests
    if (rawrxd_validate_gguf_header(path) == RAWRXD_TEST_PASS) {
        val->header_valid = true;
    }
    
    if (rawrxd_validate_gguf_metadata(path) == RAWRXD_TEST_PASS) {
        val->metadata_valid = true;
    }
    
    if (rawrxd_validate_gguf_tensors(path) == RAWRXD_TEST_PASS) {
        val->tensors_valid = true;
    }
    
    val->tensors_checked = val->tensors_passed + val->tensors_failed;
    
    return val;
}

rawrxd_test_suite* rawrxd_validate_gguf_matrix(void) {
    rawrxd_test_suite* suite = rawrxd_alloc(sizeof(rawrxd_test_suite));
    if (!suite) return NULL;
    
    memset(suite, 0, sizeof(*suite));
    suite->name = "GGUF Validation Matrix";
    
    printf("[SUITE] %s\n", suite->name);
    printf("  Note: Requires test models. Run with -m <model.gguf>\n");
    
    return suite;
}
