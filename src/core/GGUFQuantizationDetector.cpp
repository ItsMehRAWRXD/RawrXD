//==============================================================================
// GGUFQuantizationDetector.cpp - Phase 15B: Quantization Detection Implementation
//==============================================================================

#include "GGUFQuantizationDetector.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

//==============================================================================
// GGUF Header Structures
//==============================================================================

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
} GgufHeader;

typedef struct {
    uint64_t type;
    uint64_t offset;
} GgufTensorInfo;

#pragma pack(pop)

//==============================================================================
// Internal State
//==============================================================================

typedef struct {
    int is_initialized;
    char last_error[256];
} DetectorState;

static DetectorState g_detector = {0};

//==============================================================================
// Quantization Type Mapping
//==============================================================================

// GGML type enum (from llama.cpp/ggml.h)
typedef enum {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q4_2 = 4,  // removed
    GGML_TYPE_Q4_3 = 5,  // removed
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
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ4_XS  = 22,
    GGML_TYPE_I8      = 23,
    GGML_TYPE_I16     = 24,
    GGML_TYPE_I32     = 25,
    GGML_TYPE_I64     = 26,
    GGML_TYPE_F64     = 27,
    GGML_TYPE_IQ1_M   = 28,
    GGML_TYPE_COUNT   = 29,
} GgmlType;

static struct {
    GgmlType ggml_type;
    QuantizationType quant_type;
    const char* name;
    float bits_per_weight;
    int quality_score;  // 0-100
} g_quant_map[] = {
    { GGML_TYPE_F32,     QUANT_F32,      "F32",     32.0f, 100 },
    { GGML_TYPE_F16,     QUANT_F16,      "F16",     16.0f, 95 },
    { GGML_TYPE_Q4_0,    QUANT_Q4_0,     "Q4_0",     4.5f, 60 },
    { GGML_TYPE_Q4_1,    QUANT_Q4_1,     "Q4_1",     5.0f, 65 },
    { GGML_TYPE_Q5_0,    QUANT_Q5_0,     "Q5_0",     5.5f, 70 },
    { GGML_TYPE_Q5_1,    QUANT_Q5_1,     "Q5_1",     6.0f, 75 },
    { GGML_TYPE_Q8_0,    QUANT_Q8_0,     "Q8_0",     8.5f, 85 },
    { GGML_TYPE_Q8_1,    QUANT_Q8_1,     "Q8_1",     9.0f, 88 },
    { GGML_TYPE_Q2_K,    QUANT_Q2_K,     "Q2_K",     2.625f, 45 },
    { GGML_TYPE_Q3_K,    QUANT_Q3_K,     "Q3_K",     3.4375f, 55 },
    { GGML_TYPE_Q4_K,    QUANT_Q4_K,     "Q4_K",     4.5f, 70 },
    { GGML_TYPE_Q5_K,    QUANT_Q5_K,     "Q5_K",     5.5f, 78 },
    { GGML_TYPE_Q6_K,    QUANT_Q6_K,     "Q6_K",     6.5625f, 82 },
    { GGML_TYPE_Q8_K,    QUANT_Q8_K,     "Q8_K",     8.5f, 90 },
    { GGML_TYPE_IQ2_XXS, QUANT_IQ2_XXS,  "IQ2_XXS",  2.06f, 50 },
    { GGML_TYPE_IQ2_XS,  QUANT_IQ2_XS,   "IQ2_XS",   2.31f, 55 },
    { GGML_TYPE_IQ3_XXS, QUANT_IQ3_XXS,  "IQ3_XXS",  3.06f, 60 },
    { GGML_TYPE_IQ4_XS,  QUANT_IQ4_XS,   "IQ4_XS",   4.25f, 75 },
    { GGML_TYPE_IQ4_NL,  QUANT_Q4_K,     "IQ4_NL",   4.5f, 72 },
    { GGML_TYPE_IQ3_S,   QUANT_Q3_K,     "IQ3_S",    3.44f, 58 },
    { GGML_TYPE_IQ1_S,   QUANT_UNKNOWN,  "IQ1_S",    1.56f, 35 },
    { GGML_TYPE_IQ1_M,   QUANT_UNKNOWN,  "IQ1_M",    1.75f, 38 },
    { GGML_TYPE_I8,      QUANT_UNKNOWN,  "I8",       8.0f, 80 },
    { GGML_TYPE_I16,     QUANT_UNKNOWN,  "I16",     16.0f, 90 },
    { GGML_TYPE_I32,     QUANT_UNKNOWN,  "I32",     32.0f, 95 },
    { GGML_TYPE_I64,     QUANT_UNKNOWN,  "I64",     64.0f, 98 },
    { GGML_TYPE_F64,     QUANT_UNKNOWN,  "F64",     64.0f, 100 },
};

//==============================================================================
// Helper Functions
//==============================================================================

static void SetError(const char* msg) {
    strncpy(g_detector.last_error, msg, sizeof(g_detector.last_error) - 1);
}

static QuantizationType MapGgmlTypeToQuant(GgmlType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].ggml_type == type) {
            return g_quant_map[i].quant_type;
        }
    }
    return QUANT_UNKNOWN;
}

static const char* GetQuantNameFromGgmlType(GgmlType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].ggml_type == type) {
            return g_quant_map[i].name;
        }
    }
    return "UNKNOWN";
}

static float GetBitsPerWeightFromGgmlType(GgmlType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].ggml_type == type) {
            return g_quant_map[i].bits_per_weight;
        }
    }
    return 16.0f;  // Default to F16
}

static int ReadLE32(const uint8_t* data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

static uint64_t ReadLE64(const uint8_t* data) {
    return (uint64_t)data[0] |
           ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) |
           ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) |
           ((uint64_t)data[7] << 56);
}

static uint64_t ReadVarInt(FILE* f) {
    uint64_t value = 0;
    int shift = 0;
    uint8_t byte;
    
    do {
        if (fread(&byte, 1, 1, f) != 1) return 0;
        value |= (uint64_t)(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    return value;
}

static int ReadString(FILE* f, char* out, size_t max_len) {
    uint64_t len = ReadVarInt(f);
    if (len >= max_len) len = max_len - 1;
    
    if (fread(out, 1, (size_t)len, f) != len) return -1;
    out[len] = '\0';
    
    return 0;
}

//==============================================================================
// Subsystem Lifecycle
//==============================================================================

int GGUFDetector_Init(void) {
    if (g_detector.is_initialized) return 0;
    
    memset(&g_detector, 0, sizeof(g_detector));
    g_detector.is_initialized = 1;
    
    return 0;
}

int GGUFDetector_Shutdown(void) {
    g_detector.is_initialized = 0;
    return 0;
}

//==============================================================================
// Detection API
//==============================================================================

int GGUFDetector_AnalyzeFile(const char* file_path, DetectedModelInfo* out_info) {
    if (!file_path || !out_info) {
        SetError("Invalid parameters");
        return -1;
    }
    
    memset(out_info, 0, sizeof(DetectedModelInfo));
    strncpy(out_info->file_path, file_path, sizeof(out_info->file_path) - 1);
    
    FILE* f = fopen(file_path, "rb");
    if (!f) {
        SetError("Failed to open file");
        out_info->detection_success = 0;
        strncpy(out_info->error_message, g_detector.last_error, sizeof(out_info->error_message) - 1);
        return -1;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    out_info->file_size = (uint64_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Read header
    GgufHeader header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        SetError("Failed to read GGUF header");
        fclose(f);
        out_info->detection_success = 0;
        strncpy(out_info->error_message, g_detector.last_error, sizeof(out_info->error_message) - 1);
        return -1;
    }
    
    // Verify magic
    if (header.magic != GGUF_MAGIC) {
        SetError("Invalid GGUF magic number");
        fclose(f);
        out_info->detection_success = 0;
        strncpy(out_info->error_message, g_detector.last_error, sizeof(out_info->error_message) - 1);
        return -1;
    }
    
    // Store version
    uint32_t version = header.version;
    
    // Track quantization types found
    int quant_types_found[GGML_TYPE_COUNT] = {0};
    int dominant_quant = GGML_TYPE_F16;
    uint64_t max_tensor_size = 0;
    
    // Read KV pairs to find architecture info
    for (uint64_t i = 0; i < header.kv_count; i++) {
        char key[256];
        if (ReadString(f, key, sizeof(key)) != 0) break;
        
        uint64_t type = ReadVarInt(f);
        
        // Read value based on type
        switch (type) {
            case GGUF_TYPE_UINT8: {
                uint8_t val;
                fread(&val, 1, 1, f);
                break;
            }
            case GGUF_TYPE_INT8: {
                int8_t val;
                fread(&val, 1, 1, f);
                break;
            }
            case GGUF_TYPE_UINT16: {
                uint16_t val;
                fread(&val, 2, 1, f);
                break;
            }
            case GGUF_TYPE_INT16: {
                int16_t val;
                fread(&val, 2, 1, f);
                break;
            }
            case GGUF_TYPE_UINT32: {
                uint32_t val;
                fread(&val, 4, 1, f);
                
                if (strcmp(key, "general.architecture") == 0) {
                    // This is actually a string in newer versions
                } else if (strcmp(key, "llama.context_length") == 0 ||
                           strcmp(key, "qwen2.context_length") == 0 ||
                           strcmp(key, "phi3.context_length") == 0) {
                    out_info->context_length = val;
                } else if (strcmp(key, "llama.embedding_length") == 0 ||
                           strcmp(key, "qwen2.embedding_length") == 0 ||
                           strcmp(key, "phi3.embedding_length") == 0) {
                    out_info->embedding_length = val;
                } else if (strcmp(key, "llama.block_count") == 0 ||
                           strcmp(key, "qwen2.block_count") == 0 ||
                           strcmp(key, "phi3.block_count") == 0) {
                    out_info->num_layers = val;
                } else if (strcmp(key, "llama.attention.head_count") == 0 ||
                           strcmp(key, "qwen2.attention.head_count") == 0 ||
                           strcmp(key, "phi3.attention.head_count") == 0) {
                    out_info->num_heads = val;
                } else if (strcmp(key, "llama.attention.head_count_kv") == 0 ||
                           strcmp(key, "qwen2.attention.head_count_kv") == 0 ||
                           strcmp(key, "phi3.attention.head_count_kv") == 0) {
                    out_info->num_kv_heads = val;
                } else if (strcmp(key, "llama.vocab_size") == 0 ||
                           strcmp(key, "qwen2.vocab_size") == 0 ||
                           strcmp(key, "phi3.vocab_size") == 0) {
                    out_info->vocab_size = val;
                } else if (strcmp(key, "llama.feed_forward_length") == 0 ||
                           strcmp(key, "qwen2.feed_forward_length") == 0) {
                    out_info->feed_forward_length = val;
                }
                break;
            }
            case GGUF_TYPE_INT32: {
                int32_t val;
                fread(&val, 4, 1, f);
                break;
            }
            case GGUF_TYPE_FLOAT32: {
                float val;
                fread(&val, 4, 1, f);
                break;
            }
            case GGUF_TYPE_UINT64: {
                uint64_t val;
                fread(&val, 8, 1, f);
                break;
            }
            case GGUF_TYPE_INT64: {
                int64_t val;
                fread(&val, 8, 1, f);
                break;
            }
            case GGUF_TYPE_FLOAT64: {
                double val;
                fread(&val, 8, 1, f);
                break;
            }
            case GGUF_TYPE_BOOL: {
                uint8_t val;
                fread(&val, 1, 1, f);
                break;
            }
            case GGUF_TYPE_STRING: {
                char str[512];
                ReadString(f, str, sizeof(str));
                
                if (strcmp(key, "general.architecture") == 0) {
                    strncpy(out_info->architecture, str, sizeof(out_info->architecture) - 1);
                } else if (strcmp(key, "general.name") == 0) {
                    strncpy(out_info->model_name, str, sizeof(out_info->model_name) - 1);
                } else if (strcmp(key, "general.author") == 0) {
                    strncpy(out_info->author, str, sizeof(out_info->author) - 1);
                } else if (strcmp(key, "general.version") == 0) {
                    strncpy(out_info->version, str, sizeof(out_info->version) - 1);
                } else if (strcmp(key, "general.license") == 0 ||
                           strcmp(key, "general.license.name") == 0) {
                    strncpy(out_info->license, str, sizeof(out_info->license) - 1);
                } else if (strcmp(key, "general.description") == 0) {
                    strncpy(out_info->description, str, sizeof(out_info->description) - 1);
                } else if (strcmp(key, "general.url") == 0 ||
                           strcmp(key, "general.source.url") == 0) {
                    strncpy(out_info->url, str, sizeof(out_info->url) - 1);
                }
                break;
            }
            case GGUF_TYPE_ARRAY: {
                uint64_t arr_type = ReadVarInt(f);
                uint64_t arr_count = ReadVarInt(f);
                
                // Skip array data
                for (uint64_t j = 0; j < arr_count; j++) {
                    switch (arr_type) {
                        case GGUF_TYPE_UINT8:  fseek(f, 1, SEEK_CUR); break;
                        case GGUF_TYPE_INT8:   fseek(f, 1, SEEK_CUR); break;
                        case GGUF_TYPE_UINT16: fseek(f, 2, SEEK_CUR); break;
                        case GGUF_TYPE_INT16:  fseek(f, 2, SEEK_CUR); break;
                        case GGUF_TYPE_UINT32: fseek(f, 4, SEEK_CUR); break;
                        case GGUF_TYPE_INT32:  fseek(f, 4, SEEK_CUR); break;
                        case GGUF_TYPE_FLOAT32:fseek(f, 4, SEEK_CUR); break;
                        case GGUF_TYPE_UINT64: fseek(f, 8, SEEK_CUR); break;
                        case GGUF_TYPE_INT64:  fseek(f, 8, SEEK_CUR); break;
                        case GGUF_TYPE_FLOAT64:fseek(f, 8, SEEK_CUR); break;
                        case GGUF_TYPE_BOOL:   fseek(f, 1, SEEK_CUR); break;
                        case GGUF_TYPE_STRING: {
                            char skip[256];
                            ReadString(f, skip, sizeof(skip));
                            break;
                        }
                        default: break;
                    }
                }
                break;
            }
            default:
                break;
        }
    }
    
    // Read tensor info
    out_info->tensor_count = (uint32_t)header.tensor_count;
    
    for (uint64_t i = 0; i < header.tensor_count; i++) {
        char name[MAX_TENSOR_NAME];
        if (ReadString(f, name, sizeof(name)) != 0) break;
        
        // Read dimensions
        uint64_t n_dims = ReadVarInt(f);
        for (uint64_t d = 0; d < n_dims; d++) {
            ReadVarInt(f);  // Skip dimension sizes
        }
        
        // Read tensor type
        uint64_t tensor_type = ReadVarInt(f);
        if (tensor_type < GGML_TYPE_COUNT) {
            quant_types_found[tensor_type]++;
            
            // Track dominant quantization (largest tensors)
            // Simplified: just count occurrences
            if (quant_types_found[tensor_type] > quant_types_found[dominant_quant]) {
                dominant_quant = (int)tensor_type;
            }
        }
        
        // Read offset
        ReadVarInt(f);
    }
    
    fclose(f);
    
    // Determine quantization
    out_info->quant_type = MapGgmlTypeToQuant((GgmlType)dominant_quant);
    strncpy(out_info->quantization, GetQuantNameFromGgmlType((GgmlType)dominant_quant), 
            sizeof(out_info->quantization) - 1);
    
    // Count tensor types
    for (int i = 0; i < GGML_TYPE_COUNT; i++) {
        if (quant_types_found[i] > 0) {
            if (i == GGML_TYPE_F32 || i == GGML_TYPE_F16) {
                out_info->float_tensors += quant_types_found[i];
            } else {
                out_info->quantized_tensors += quant_types_found[i];
            }
        }
    }
    
    // Estimate parameter count
    // Rough estimate: file_size / (bits_per_weight / 8)
    float bits_per_weight = GetBitsPerWeightFromGgmlType((GgmlType)dominant_quant);
    if (bits_per_weight > 0) {
        out_info->parameter_count = (uint64_t)((out_info->file_size * 8.0f) / bits_per_weight);
    }
    
    // Set defaults if not found
    if (out_info->context_length == 0) out_info->context_length = 4096;
    if (out_info->embedding_length == 0) out_info->embedding_length = 4096;
    if (out_info->num_layers == 0) out_info->num_layers = 32;
    if (out_info->num_heads == 0) out_info->num_heads = 32;
    if (out_info->vocab_size == 0) out_info->vocab_size = 32000;
    
    out_info->detection_success = 1;
    
    return 0;
}

int GGUFDetector_GetQuantization(const char* file_path, char* out_quant, size_t out_size) {
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) != 0) {
        return -1;
    }
    
    strncpy(out_quant, info.quantization, out_size - 1);
    out_quant[out_size - 1] = '\0';
    
    return 0;
}

int GGUFDetector_GetParameterCount(const char* file_path, uint64_t* out_params) {
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) != 0) {
        return -1;
    }
    
    *out_params = info.parameter_count;
    return 0;
}

int GGUFDetector_GetContextLength(const char* file_path, uint32_t* out_length) {
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) != 0) {
        return -1;
    }
    
    *out_length = info.context_length;
    return 0;
}

//==============================================================================
// Quantization Utilities
//==============================================================================

const char* GGUFDetector_QuantTypeToString(QuantizationType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].quant_type == type) {
            return g_quant_map[i].name;
        }
    }
    return "UNKNOWN";
}

QuantizationType GGUFDetector_StringToQuantType(const char* str) {
    if (!str) return QUANT_UNKNOWN;
    
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (_stricmp(g_quant_map[i].name, str) == 0) {
            return g_quant_map[i].quant_type;
        }
    }
    
    return QUANT_UNKNOWN;
}

float GGUFDetector_GetBitsPerWeight(QuantizationType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].quant_type == type) {
            return g_quant_map[i].bits_per_weight;
        }
    }
    return 16.0f;
}

int GGUFDetector_GetQualityScore(QuantizationType type) {
    for (size_t i = 0; i < sizeof(g_quant_map) / sizeof(g_quant_map[0]); i++) {
        if (g_quant_map[i].quant_type == type) {
            return g_quant_map[i].quality_score;
        }
    }
    return 50;
}

const char* GGUFDetector_GetRecommendedUse(QuantizationType type) {
    switch (type) {
        case QUANT_F32:
        case QUANT_F16:
            return "Training, highest quality inference";
        case QUANT_Q8_0:
        case QUANT_Q8_1:
        case QUANT_Q8_K:
            return "Production inference, minimal quality loss";
        case QUANT_Q6_K:
        case QUANT_Q5_K:
        case QUANT_Q5_K_M:
            return "Balanced quality and speed";
        case QUANT_Q4_K:
        case QUANT_Q4_K_M:
        case QUANT_Q4_K_S:
        case QUANT_IQ4_XS:
            return "Fast inference, good quality (recommended)";
        case QUANT_Q5_0:
        case QUANT_Q5_1:
        case QUANT_Q4_0:
        case QUANT_Q4_1:
            return "Legacy formats, consider K-quants";
        case QUANT_Q3_K:
        case QUANT_Q3_K_M:
        case QUANT_Q3_K_S:
        case QUANT_IQ3_XXS:
        case QUANT_IQ3_S:
            return "Low memory, acceptable quality";
        case QUANT_Q2_K:
        case QUANT_IQ2_XXS:
        case QUANT_IQ2_XS:
            return "Minimal memory, reduced quality";
        default:
            return "Unknown quantization type";
    }
}

int GGUFDetector_IsKQuant(QuantizationType type) {
    return (type >= QUANT_Q2_K && type <= QUANT_Q8_K) ||
           (type >= QUANT_Q4_K_M && type <= QUANT_Q3_K_S);
}

int GGUFDetector_IsIQQuant(QuantizationType type) {
    return type >= QUANT_IQ2_XXS && type <= QUANT_IQ4_XS;
}

//==============================================================================
// Memory Estimation
//==============================================================================

uint64_t GGUFDetector_EstimateMemoryRequired(const DetectedModelInfo* info) {
    if (!info) return 0;
    
    // Base model size (from file)
    uint64_t base_size = info->file_size;
    
    // KV cache estimate: 2 * num_layers * context * embedding * 2 bytes (FP16)
    uint64_t kv_cache = 2ULL * info->num_layers * info->context_length * 
                        info->embedding_length * 2;
    
    // Activation memory estimate
    uint64_t activation = info->context_length * info->embedding_length * 4;
    
    // Overhead (20%)
    uint64_t overhead = (base_size + kv_cache + activation) / 5;
    
    return base_size + kv_cache + activation + overhead;
}

uint64_t GGUFDetector_EstimateMemoryForParams(uint64_t params, QuantizationType type) {
    float bits_per_weight = GGUFDetector_GetBitsPerWeight(type);
    return (uint64_t)((params * bits_per_weight) / 8.0f);
}

//==============================================================================
// Architecture Detection
//==============================================================================

const char* GGUFDetector_GetModelFamily(const char* architecture) {
    if (!architecture) return "unknown";
    
    if (_stricmp(architecture, "llama") == 0 ||
        _stricmp(architecture, "llama2") == 0 ||
        _stricmp(architecture, "llama3") == 0) {
        return "llama";
    } else if (_stricmp(architecture, "qwen2") == 0 ||
               _stricmp(architecture, "qwen") == 0) {
        return "qwen";
    } else if (_stricmp(architecture, "phi3") == 0 ||
               _stricmp(architecture, "phi") == 0) {
        return "phi";
    } else if (_stricmp(architecture, "mistral") == 0) {
        return "mistral";
    } else if (_stricmp(architecture, "mixtral") == 0) {
        return "mixtral";
    } else if (_stricmp(architecture, "gemma") == 0 ||
               _stricmp(architecture, "gemma2") == 0) {
        return "gemma";
    } else if (_stricmp(architecture, "falcon") == 0) {
        return "falcon";
    }
    
    return architecture;
}

unsigned int GGUFDetector_GetDefaultCapabilities(const char* architecture) {
    const char* family = GGUFDetector_GetModelFamily(architecture);
    
    if (_stricmp(family, "llama") == 0) {
        return CAP_CODE_GENERATION | CAP_CODE_FIXING | CAP_CHAT | CAP_REASONING;
    } else if (_stricmp(family, "qwen") == 0) {
        return CAP_CODE_GENERATION | CAP_CODE_FIXING | CAP_CHAT | CAP_MULTILINGUAL | CAP_REASONING;
    } else if (_stricmp(family, "phi") == 0) {
        return CAP_CODE_GENERATION | CAP_CHAT | CAP_REASONING;
    } else if (_stricmp(family, "mistral") == 0 || _stricmp(family, "mixtral") == 0) {
        return CAP_CODE_GENERATION | CAP_CODE_FIXING | CAP_CHAT | CAP_REASONING;
    } else if (_stricmp(family, "gemma") == 0) {
        return CAP_CHAT | CAP_REASONING | CAP_MULTILINGUAL;
    }
    
    // Default: basic capabilities
    return CAP_CHAT;
}

int GGUFDetector_ArchitectureSupports(const char* architecture, const char* feature) {
    unsigned int caps = GGUFDetector_GetDefaultCapabilities(architecture);
    
    if (_stricmp(feature, "code") == 0) {
        return (caps & CAP_CODE_GENERATION) != 0;
    } else if (_stricmp(feature, "chat") == 0) {
        return (caps & CAP_CHAT) != 0;
    } else if (_stricmp(feature, "multilingual") == 0) {
        return (caps & CAP_MULTILINGUAL) != 0;
    } else if (_stricmp(feature, "reasoning") == 0) {
        return (caps & CAP_REASONING) != 0;
    }
    
    return 0;
}

//==============================================================================
// Validation
//==============================================================================

int GGUFDetector_ValidateFile(const char* file_path, char* out_error, size_t error_size) {
    DetectedModelInfo info;
    int result = GGUFDetector_AnalyzeFile(file_path, &info);
    
    if (result != 0) {
        if (out_error && error_size > 0) {
            strncpy(out_error, info.error_message, error_size - 1);
            out_error[error_size - 1] = '\0';
        }
        return -1;
    }
    
    return 0;
}

int GGUFDetector_IsValidGGUF(const char* file_path) {
    FILE* f = fopen(file_path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    int valid = (fread(&magic, 4, 1, f) == 1 && magic == GGUF_MAGIC);
    fclose(f);
    
    return valid;
}

int GGUFDetector_GetFileVersion(const char* file_path, uint32_t* out_version) {
    FILE* f = fopen(file_path, "rb");
    if (!f) return -1;
    
    uint32_t magic, version;
    if (fread(&magic, 4, 1, f) != 1 || magic != GGUF_MAGIC) {
        fclose(f);
        return -1;
    }
    
    if (fread(&version, 4, 1, f) != 1) {
        fclose(f);
        return -1;
    }
    
    fclose(f);
    
    *out_version = version;
    return 0;
}
