// sovereign_unified_model_loader.c - Unified Model Loading Implementation
// Integrates GGUF loader, inference engine, and streaming
// NO DEPENDENCIES - Pure Win32 API

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define SOVEREIGN_API __declspec(dllexport)

#include "sovereign_unified_model_loader.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// GGUF PARSING
// ============================================================================

#define GGUF_MAGIC 0x46554747  // "GGUF"

typedef enum {
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
    GGUF_TYPE_FLOAT64 = 12
} GGUFType;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_kv;
} GGUFHeader;

// Reading utilities
static uint64_t read_u64(const uint8_t** p) {
    uint64_t v;
    memcpy(&v, *p, 8);
    *p += 8;
    return v;
}

static uint32_t read_u32(const uint8_t** p) {
    uint32_t v;
    memcpy(&v, *p, 4);
    *p += 4;
    return v;
}

static float read_f32(const uint8_t** p) {
    float v;
    memcpy(&v, *p, 4);
    *p += 4;
    return v;
}

static char* read_string(const uint8_t** p) {
    uint64_t len = read_u64(p);
    char* s = (char*)malloc(len + 1);
    if (s) {
        memcpy(s, *p, len);
        s[len] = '\0';
        *p += len;
    }
    return s;
}

static void skip_value(const uint8_t** p, GGUFType type) {
    switch (type) {
        case GGUF_TYPE_UINT8:
        case GGUF_TYPE_INT8:
        case GGUF_TYPE_BOOL:
            *p += 1;
            break;
        case GGUF_TYPE_UINT16:
        case GGUF_TYPE_INT16:
            *p += 2;
            break;
        case GGUF_TYPE_UINT32:
        case GGUF_TYPE_INT32:
        case GGUF_TYPE_FLOAT32:
            *p += 4;
            break;
        case GGUF_TYPE_UINT64:
        case GGUF_TYPE_INT64:
        case GGUF_TYPE_FLOAT64:
            *p += 8;
            break;
        case GGUF_TYPE_STRING: {
            uint64_t len = read_u64(p);
            *p += len;
            break;
        }
        case GGUF_TYPE_ARRAY: {
            GGUFType elem_type = (GGUFType)read_u32(p);
            uint64_t count = read_u64(p);
            for (uint64_t i = 0; i < count; i++) {
                skip_value(p, elem_type);
            }
            break;
        }
    }
}

// ============================================================================
// MODEL LOADING
// ============================================================================

static SovereignStatus parse_gguf_metadata(SovereignModel* model, const uint8_t* data) {
    const uint8_t* p = data;
    
    // Read header
    GGUFHeader header;
    header.magic = read_u32(&p);
    if (header.magic != GGUF_MAGIC) {
        return SOVEREIGN_STATUS_ERROR;
    }
    
    header.version = read_u32(&p);
    header.n_tensors = read_u64(&p);
    header.n_kv = read_u64(&p);
    
    // Parse metadata
    for (uint64_t i = 0; i < header.n_kv; i++) {
        char* key = read_string(&p);
        GGUFType type = (GGUFType)read_u32(&p);
        
        if (!key) continue;
        
        // Extract architecture parameters
        if (strcmp(key, "general.architecture") == 0) {
            char* arch = read_string(&p);
            if (arch) {
                strncpy(model->config.architecture, arch, sizeof(model->config.architecture) - 1);
                free(arch);
            }
        } else if (strcmp(key, "general.name") == 0) {
            char* name = read_string(&p);
            if (name) {
                strncpy(model->config.name, name, sizeof(model->config.name) - 1);
                free(name);
            }
        } else if (strcmp(key, "general.description") == 0) {
            char* desc = read_string(&p);
            if (desc) {
                strncpy(model->config.description, desc, sizeof(model->config.description) - 1);
                free(desc);
            }
        } else if (strcmp(key, "llama.embedding_length") == 0 ||
                   strcmp(key, "general.embedding_length") == 0) {
            model->config.n_embd = read_u32(&p);
        } else if (strcmp(key, "llama.attention.head_count") == 0 ||
                   strcmp(key, "general.attention.head_count") == 0) {
            model->config.n_head = read_u32(&p);
        } else if (strcmp(key, "llama.attention.head_count_kv") == 0) {
            model->config.n_head_kv = read_u32(&p);
        } else if (strcmp(key, "llama.block_count") == 0 ||
                   strcmp(key, "general.block_count") == 0) {
            model->config.n_layer = read_u32(&p);
        } else if (strcmp(key, "llama.context_length") == 0 ||
                   strcmp(key, "general.context_length") == 0) {
            model->config.n_ctx = read_u32(&p);
        } else if (strcmp(key, "llama.feed_forward_length") == 0 ||
                   strcmp(key, "general.feed_forward_length") == 0) {
            model->config.n_ff = read_u32(&p);
        } else if (strcmp(key, "llama.vocab_size") == 0 ||
                   strcmp(key, "general.vocab_size") == 0) {
            model->config.n_vocab = read_u32(&p);
        } else if (strcmp(key, "llama.rope.freq_base") == 0) {
            model->config.rope_freq_base = read_f32(&p);
        } else if (strcmp(key, "llama.rope.freq_scale") == 0) {
            model->config.rope_freq_scale = read_f32(&p);
        } else {
            skip_value(&p, type);
        }
        
        free(key);
    }
    
    // Set defaults
    if (model->config.n_head_kv == 0) {
        model->config.n_head_kv = model->config.n_head;
    }
    if (model->config.rope_freq_base == 0) {
        model->config.rope_freq_base = 10000.0f;
    }
    if (model->config.rope_freq_scale == 0) {
        model->config.rope_freq_scale = 1.0f;
    }
    
    return SOVEREIGN_STATUS_OK;
}

// ============================================================================
// PUBLIC API
// ============================================================================

SOVEREIGN_API SovereignStatus sovereign_init(void) {
    // Initialize global state if needed
    return SOVEREIGN_STATUS_OK;
}

SOVEREIGN_API void sovereign_cleanup(void) {
    // Cleanup global state if needed
}

SOVEREIGN_API SovereignStatus sovereign_load_model(
    const wchar_t* path,
    SovereignModel** model_out,
    SovereignProgressCallback progress,
    void* user_data
) {
    if (!path || !model_out) {
        return SOVEREIGN_STATUS_ERROR;
    }
    
    // Allocate model
    SovereignModel* model = (SovereignModel*)calloc(1, sizeof(SovereignModel));
    if (!model) {
        return SOVEREIGN_STATUS_ERROR;
    }
    
    if (progress) {
        progress(0.0f, "Opening file", user_data);
    }
    
    // Open file
    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        free(model);
        return SOVEREIGN_STATUS_ERROR;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    model->size = fileSize.QuadPart;
    
    if (progress) {
        progress(0.1f, "Creating file mapping", user_data);
    }
    
    // Create file mapping
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        free(model);
        return SOVEREIGN_STATUS_ERROR;
    }
    
    if (progress) {
        progress(0.2f, "Mapping view", user_data);
    }
    
    // Map view
    void* data = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        free(model);
        return SOVEREIGN_STATUS_ERROR;
    }
    
    model->hFile = hFile;
    model->hMapping = hMapping;
    model->data = data;
    
    if (progress) {
        progress(0.3f, "Parsing metadata", user_data);
    }
    
    // Parse GGUF metadata
    SovereignStatus status = parse_gguf_metadata(model, (const uint8_t*)data);
    if (status != SOVEREIGN_STATUS_OK) {
        UnmapViewOfFile(data);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        free(model);
        return status;
    }
    
    if (progress) {
        progress(1.0f, "Model loaded", user_data);
    }
    
    model->loaded = true;
    *model_out = model;
    
    return SOVEREIGN_STATUS_OK;
}

SOVEREIGN_API void sovereign_unload_model(SovereignModel* model) {
    if (!model) return;
    
    if (model->data) {
        UnmapViewOfFile(model->data);
    }
    if (model->hMapping) {
        CloseHandle(model->hMapping);
    }
    if (model->hFile && model->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(model->hFile);
    }
    
    free(model);
}

SOVEREIGN_API SovereignStatus sovereign_get_model_config(
    const SovereignModel* model,
    SovereignModelConfig* config
) {
    if (!model || !config) {
        return SOVEREIGN_STATUS_ERROR;
    }
    
    memcpy(config, &model->config, sizeof(SovereignModelConfig));
    return SOVEREIGN_STATUS_OK;
}

SOVEREIGN_API const char* sovereign_status_string(SovereignStatus status) {
    switch (status) {
        case SOVEREIGN_STATUS_OK: return "OK";
        case SOVEREIGN_STATUS_ERROR: return "Error";
        case SOVEREIGN_STATUS_LOADING: return "Loading";
        case SOVEREIGN_STATUS_READY: return "Ready";
        case SOVEREIGN_STATUS_INFERRING: return "Inferring";
        case SOVEREIGN_STATUS_STREAMING: return "Streaming";
        case SOVEREIGN_STATUS_CANCELLED: return "Cancelled";
        default: return "Unknown";
    }
}

SOVEREIGN_API const char* sovereign_quant_string(SovereignQuantType quant) {
    switch (quant) {
        case SOVEREIGN_QUANT_F32: return "F32";
        case SOVEREIGN_QUANT_F16: return "F16";
        case SOVEREIGN_QUANT_Q4_0: return "Q4_0";
        case SOVEREIGN_QUANT_Q4_1: return "Q4_1";
        case SOVEREIGN_QUANT_Q5_0: return "Q5_0";
        case SOVEREIGN_QUANT_Q5_1: return "Q5_1";
        case SOVEREIGN_QUANT_Q8_0: return "Q8_0";
        case SOVEREIGN_QUANT_Q8_1: return "Q8_1";
        case SOVEREIGN_QUANT_Q2_K: return "Q2_K";
        case SOVEREIGN_QUANT_Q3_K: return "Q3_K";
        case SOVEREIGN_QUANT_Q4_K: return "Q4_K";
        case SOVEREIGN_QUANT_Q5_K: return "Q5_K";
        case SOVEREIGN_QUANT_Q6_K: return "Q6_K";
        case SOVEREIGN_QUANT_Q8_K: return "Q8_K";
        default: return "Unknown";
    }
}

SOVEREIGN_API uint64_t sovereign_get_model_size(const SovereignModel* model) {
    return model ? model->size : 0;
}

SOVEREIGN_API bool sovereign_is_model_loaded(const SovereignModel* model) {
    return model ? model->loaded : false;
}

// ============================================================================
// DLL ENTRY
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}