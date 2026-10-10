// dll_teacher_forced_test.cpp
// Test program to run teacher-forced inference through RawrXDCore.dll
// and compare logits with standalone executor

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <direct.h>
#include "ModelGenieRuntime.h"

// RawrXDCore.h types (copied to avoid missing export header)
typedef enum RawrXDLogLevel {
    RAWXD_LOG_TRACE = 0,
    RAWXD_LOG_DEBUG = 1,
    RAWXD_LOG_INFO  = 2,
    RAWXD_LOG_WARN  = 3,
    RAWXD_LOG_ERROR = 4,
    RAWXD_LOG_FATAL = 5
} RawrXDLogLevel;

typedef void (*RawrXDLogCallback)(RawrXDLogLevel level, const char* message, void* userData);

typedef struct RawrXDConfig {
    bool enableVulkan;
    bool enableMASM;
    bool enableTelemetry;
    int  workerThreadCount;
    size_t maxMemoryMB;
    const char* modelCachePath;
    const char* logFilePath;
} RawrXDConfig;

typedef struct RawrXDInferenceParams {
    int maxTokens;
    float temperature;
    float topP;
    int topK;
    float repeatPenalty;
    unsigned int seed;
    bool useGPU;
    int gpuDeviceId;
} RawrXDInferenceParams;

typedef void* RawrXDModel;
typedef void* RawrXDInferenceContext;
typedef int (*RawrXDTokenCallback)(int tokenId, const char* tokenText, void* userData);

typedef enum RawrXDError {
    RAWXD_OK = 0,
    RAWXD_ERROR_INVALID_ARGUMENT = -1,
    RAWXD_ERROR_OUT_OF_MEMORY = -2,
    RAWXD_ERROR_MODEL_NOT_FOUND = -3,
    RAWXD_ERROR_MODEL_CORRUPT = -4,
    RAWXD_ERROR_GPU_UNAVAILABLE = -5,
    RAWXD_ERROR_VULKAN_UNSUPPORTED = -6,
    RAWXD_ERROR_NOT_INITIALIZED = -7,
    RAWXD_ERROR_ALREADY_INITIALIZED = -8,
    RAWXD_ERROR_INTERNAL = -9
} RawrXDError;

// Function pointer types for DLL functions
typedef const char* (*RawrXDCore_GetVersion_t)(void);
typedef bool (*RawrXDCore_Initialize_t)(void);
typedef void (*RawrXDCore_Shutdown_t)(void);
typedef RawrXDModel* (*RawrXDCore_LoadModel_t)(const char*);
typedef void (*RawrXDCore_UnloadModel_t)(RawrXDModel*);
typedef RawrXDInferenceContext* (*RawrXDCore_CreateContext_t)(RawrXDModel*);
typedef void (*RawrXDCore_DestroyContext_t)(RawrXDInferenceContext*);
typedef int (*RawrXDCore_RunInference_t)(RawrXDInferenceContext*, const char*, const RawrXDInferenceParams*, RawrXDTokenCallback, void*);
typedef void (*RawrXDCore_GetDefaultInferenceParams_t)(RawrXDInferenceParams*);
typedef size_t (*RawrXDCore_Tokenize_t)(const RawrXDModel*, const char*, int*, size_t);
typedef RawrXDError (*RawrXDCore_GetLastError_t)(void);
typedef const char* (*RawrXDCore_GetErrorString_t)(RawrXDError);

struct DLLHandles {
    HMODULE coreDll = NULL;
    HMODULE mgRuntimeDll = NULL;
    
    RawrXDCore_GetVersion_t GetVersion = NULL;
    RawrXDCore_Initialize_t Initialize = NULL;
    RawrXDCore_Shutdown_t Shutdown = NULL;
    RawrXDCore_LoadModel_t LoadModel = NULL;
    RawrXDCore_UnloadModel_t UnloadModel = NULL;
    RawrXDCore_CreateContext_t CreateContext = NULL;
    RawrXDCore_DestroyContext_t DestroyContext = NULL;
    RawrXDCore_RunInference_t RunInference = NULL;
    RawrXDCore_GetDefaultInferenceParams_t GetDefaultInferenceParams = NULL;
    RawrXDCore_Tokenize_t Tokenize = NULL;
    RawrXDCore_GetLastError_t GetLastError = NULL;
    RawrXDCore_GetErrorString_t GetErrorString = NULL;
    
    // ModelGenieRuntime functions (from the same DLL or linked library)
    mg_error_t (*mg_model_load)(const char*, const mg_model_config_t*, mg_model_t**) = NULL;
    void (*mg_model_free)(mg_model_t*) = NULL;
    mg_error_t (*mg_context_create)(mg_model_t*, mg_context_t**) = NULL;
    void (*mg_context_free)(mg_context_t*) = NULL;
    mg_error_t (*mg_context_eval_buffer)(mg_context_t*, const uint32_t*, size_t, float*, size_t*) = NULL;
    mg_error_t (*mg_context_eval)(mg_context_t*, uint32_t, float*, size_t*) = NULL;
    mg_error_t (*mg_context_generate)(mg_context_t*, const uint32_t*, size_t, const mg_generation_config_t*, mg_token_callback_t, void*) = NULL;
    mg_error_t (*mg_context_capture_tokens)(mg_context_t*, const uint32_t*, size_t, uint32_t, uint32_t*, size_t, size_t*) = NULL;
    mg_error_t (*mg_model_tokenize)(mg_model_t*, const char*, uint32_t*, size_t*) = NULL;
    mg_error_t (*mg_context_reset)(mg_context_t*) = NULL;
    uint32_t (*mg_model_bos_token_id)(const mg_model_t*) = NULL;
    uint32_t (*mg_model_eos_token_id)(const mg_model_t*) = NULL;
    size_t (*mg_model_vocab_size)(const mg_model_t*) = NULL;
    
    bool LoadCoreDll(const char* path) {
        printf("Loading DLL: %s\n", path);
        fflush(stdout);
        coreDll = LoadLibraryA(path);
        if (!coreDll) {
            printf("Failed to load %s: %lu\n", path, GetLastError());
            return false;
        }
        printf("DLL loaded, getting exports...\n");
        fflush(stdout);
        
        GetVersion = (RawrXDCore_GetVersion_t)GetProcAddress(coreDll, "RawrXDCore_GetVersion");
        printf("GetVersion: %p\n", GetVersion); fflush(stdout);
        Initialize = (RawrXDCore_Initialize_t)GetProcAddress(coreDll, "RawrXDCore_Initialize");
        printf("Initialize: %p\n", Initialize); fflush(stdout);
        GetVersion = (RawrXDCore_GetVersion_t)GetProcAddress(coreDll, "RawrXDCore_GetVersion");
        printf("GetVersion: %p\n", GetVersion); fflush(stdout);
        Initialize = (RawrXDCore_Initialize_t)GetProcAddress(coreDll, "RawrXDCore_Initialize");
        printf("Initialize: %p\n", Initialize); fflush(stdout);
        Shutdown = (RawrXDCore_Shutdown_t)GetProcAddress(coreDll, "RawrXDCore_Shutdown");
        printf("Shutdown: %p\n", Shutdown); fflush(stdout);
        LoadModel = (RawrXDCore_LoadModel_t)GetProcAddress(coreDll, "RawrXDCore_LoadModel");
        printf("LoadModel: %p\n", LoadModel); fflush(stdout);
        UnloadModel = (RawrXDCore_UnloadModel_t)GetProcAddress(coreDll, "RawrXDCore_UnloadModel");
        printf("UnloadModel: %p\n", UnloadModel); fflush(stdout);
        CreateContext = (RawrXDCore_CreateContext_t)GetProcAddress(coreDll, "RawrXDCore_CreateContext");
        printf("CreateContext: %p\n", CreateContext); fflush(stdout);
        DestroyContext = (RawrXDCore_DestroyContext_t)GetProcAddress(coreDll, "RawrXDCore_DestroyContext");
        printf("DestroyContext: %p\n", DestroyContext); fflush(stdout);
        RunInference = (RawrXDCore_RunInference_t)GetProcAddress(coreDll, "RawrXDCore_RunInference");
        printf("RunInference: %p\n", RunInference); fflush(stdout);
        GetDefaultInferenceParams = (RawrXDCore_GetDefaultInferenceParams_t)GetProcAddress(coreDll, "RawrXDCore_GetDefaultInferenceParams");
        printf("GetDefaultInferenceParams: %p\n", GetDefaultInferenceParams); fflush(stdout);
        Tokenize = (RawrXDCore_Tokenize_t)GetProcAddress(coreDll, "RawrXDCore_Tokenize");
        printf("Tokenize: %p\n", Tokenize); fflush(stdout);
        GetLastError = (RawrXDCore_GetLastError_t)GetProcAddress(coreDll, "RawrXDCore_GetLastError");
        printf("GetLastError: %p\n", GetLastError); fflush(stdout);
        GetErrorString = (RawrXDCore_GetErrorString_t)GetProcAddress(coreDll, "RawrXDCore_GetErrorString");
        printf("GetErrorString: %p\n", GetErrorString); fflush(stdout);
        
        // ModelGenieRuntime functions (also exported from RawrXDCore.dll)
        mg_model_load = (mg_error_t (*)(const char*, const mg_model_config_t*, mg_model_t**))GetProcAddress(coreDll, "mg_model_load");
        mg_model_free = (void (*)(mg_model_t*))GetProcAddress(coreDll, "mg_model_free");
        mg_context_create = (mg_error_t (*)(mg_model_t*, mg_context_t**))GetProcAddress(coreDll, "mg_context_create");
        mg_context_free = (void (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_free");
        mg_context_eval_buffer = (mg_error_t (*)(mg_context_t*, const uint32_t*, size_t, float*, size_t*))GetProcAddress(coreDll, "mg_context_eval_buffer");
        mg_context_eval = (mg_error_t (*)(mg_context_t*, uint32_t, float*, size_t*))GetProcAddress(coreDll, "mg_context_eval");
        mg_context_generate = (mg_error_t (*)(mg_context_t*, const uint32_t*, size_t, const mg_generation_config_t*, mg_token_callback_t, void*))GetProcAddress(coreDll, "mg_context_generate");
        mg_context_capture_tokens = (mg_error_t (*)(mg_context_t*, const uint32_t*, size_t, uint32_t, uint32_t*, size_t, size_t*))GetProcAddress(coreDll, "mg_context_capture_tokens");
        mg_model_tokenize = (mg_error_t (*)(mg_model_t*, const char*, uint32_t*, size_t*))GetProcAddress(coreDll, "mg_model_tokenize");
        mg_context_reset = (mg_error_t (*)(mg_context_t*))GetProcAddress(coreDll, "mg_context_reset");
        mg_model_bos_token_id = (uint32_t (*)(const mg_model_t*))GetProcAddress(coreDll, "mg_model_bos_token_id");
        mg_model_eos_token_id = (uint32_t (*)(const mg_model_t*))GetProcAddress(coreDll, "mg_model_eos_token_id");
        mg_model_vocab_size = (size_t (*)(const mg_model_t*))GetProcAddress(coreDll, "mg_model_vocab_size");
        
        if (!GetVersion || !Initialize || !LoadModel || !CreateContext || !mg_context_eval_buffer || !mg_model_tokenize) {
            printf("Missing required DLL exports:\n");
            printf("  GetVersion: %p\n", GetVersion);
            printf("  Initialize: %p\n", Initialize);
            printf("  LoadModel: %p\n", LoadModel);
            printf("  CreateContext: %p\n", CreateContext);
            printf("  mg_context_eval_buffer: %p\n", mg_context_eval_buffer);
            printf("  mg_model_tokenize: %p\n", mg_model_tokenize);
            return false;
        }
        
        printf("Core DLL loaded: %s\n", GetVersion());
        return true;
    }
    
    void Free() {
        if (coreDll) FreeLibrary(coreDll);
        if (mgRuntimeDll) FreeLibrary(mgRuntimeDll);
    }
};

const int VOCAB_SIZE = 102400;
const int NUM_POSITIONS = 65;

// 65 teacher-forced tokens
const int teacher_forced_tokens[NUM_POSITIONS] = {
    1, 185, 16, 15, 15, 15, 15, 15, 15, 15, 12, 384, 2, 16, 24, 207, 71955, 1392, 13, 1002, 
    6, 95, 3882, 124, 2, 16, 146, 24, 151, 384, 37, 1827, 253, 16, 24, 92, 1024, 1827, 253, 
    16, 24, 92, 12, 22, 738, 30840, 4399, 4633, 15, 23, 0, 626, 726, 1628, 2285, 966, 6, 4, 0, 
    82, 10, 113, 4647, 1075, 2
};

void save_logits(const char* dir, int pos, const float* logits, int vocab_size) {
    char path[512];
    sprintf(path, "%s/dll_logits_pos%d.bin", dir, pos);
    FILE* f = fopen(path, "wb");
    if (f) {
        fwrite(logits, sizeof(float), vocab_size, f);
        fclose(f);
        printf("Saved dll_logits_pos%d.bin\n", pos);
    } else {
        printf("Failed to save dll_logits_pos%d.bin\n", pos);
    }
}

bool compare_logits(const char* native_dir, const char* dll_dir, int pos) {
    char native_path[512], dll_path[512];
    sprintf(native_path, "%s/native_tf_logits_pos%d.bin", native_dir, pos);
    sprintf(dll_path, "%s/dll_logits_pos%d.bin", dll_dir, pos);
    
    FILE* fn = fopen(native_path, "rb");
    FILE* fd = fopen(dll_path, "rb");
    if (!fn || !fd) {
        if (fn) fclose(fn);
        if (fd) fclose(fd);
        return false;
    }
    
    float* native = new float[VOCAB_SIZE];
    float* dll = new float[VOCAB_SIZE];
    fread(native, sizeof(float), VOCAB_SIZE, fn);
    fread(dll, sizeof(float), VOCAB_SIZE, fd);
    fclose(fn);
    fclose(fd);
    
    // Compare
    double sum_diff2 = 0, max_diff = 0;
    double dot = 0, norm_n = 0, norm_d = 0;
    for (int i = 0; i < VOCAB_SIZE; i++) {
        double diff = native[i] - dll[i];
        sum_diff2 += diff * diff;
        if (fabs(diff) > max_diff) max_diff = fabs(diff);
        dot += native[i] * dll[i];
        norm_n += native[i] * native[i];
        norm_d += dll[i] * dll[i];
    }
    double rmse = sqrt(sum_diff2 / VOCAB_SIZE);
    double cos = dot / (sqrt(norm_n) * sqrt(norm_d));
    
    int native_argmax = 0, dll_argmax = 0;
    for (int i = 1; i < VOCAB_SIZE; i++) {
        if (native[i] > native[native_argmax]) native_argmax = i;
        if (dll[i] > dll[dll_argmax]) dll_argmax = i;
    }
    
    printf("Pos %2d: argmax native=%d dll=%d match=%s cos=%.8f rmse=%.6f max=%.6f\n", 
           pos, native_argmax, dll_argmax, native_argmax == dll_argmax ? "YES" : "NO", cos, rmse, max_diff);
    
    delete[] native;
    delete[] dll;
    
    return native_argmax == dll_argmax;
}

int main() {
    printf("=== RAWRXD_DEEP2_DLL_EQUIVALENCE_001 ===\n");
    fflush(stdout);
    printf("Testing DLL vs Standalone executor equivalence\n\n");
    fflush(stdout);
    
    // Load Core DLL
    DLLHandles dll;
    if (!dll.LoadCoreDll("F:\\rawrxd\\build_cert\\bin\\Release\\RawrXDCore.dll")) {
        printf("Failed to load Core DLL\n");
        return 1;
    }
    
    // Initialize
    printf("Initializing Core DLL...\n");
    fflush(stdout);
    bool init_result = dll.Initialize();
    printf("Initialize returned: %d\n", init_result);
    fflush(stdout);
    if (!init_result) {
        printf("Failed to initialize: %s\n", dll.GetErrorString(dll.GetLastError()));
        fflush(stdout);
        return 1;
    }
    printf("Core DLL initialized\n");
    fflush(stdout);
    
    // Load model
    const char* model_path = "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    printf("Loading model: %s\n", model_path);
    fflush(stdout);
    RawrXDModel* model = dll.LoadModel(model_path);
    if (!model) {
        printf("Failed to load model: %s\n", dll.GetErrorString(dll.GetLastError()));
        fflush(stdout);
        return 1;
    }
    printf("Model loaded via RawrXDCore\n");
    fflush(stdout);
    
    // Create context
    printf("Creating context...\n");
    fflush(stdout);
    RawrXDInferenceContext* ctx = dll.CreateContext(model);
    if (!ctx) {
        printf("Failed to create context: %s\n", dll.GetErrorString(dll.GetLastError()));
        fflush(stdout);
        return 1;
    }
    printf("Context created\n");
    fflush(stdout);
    
    // Get the underlying mg_model_t and mg_context_t from the DLL
    // The DLL uses mg_model_t* and mg_context_t* internally
    // We need to access them - but they're opaque handles in the DLL
    // Let's try to get them via the ModelGenieRuntime API
    
    // Actually, the RawrXDCore uses mg_model_load internally. We need to 
    // either use the same mg_model_t or access the one the DLL created.
    // Let's load the model directly via mg_model_load for our test.
    
    mg_model_config_t mgConfig{};
    mgConfig.max_seq_len = 1024;
    mgConfig.use_kv_cache = true;
    mgConfig.num_threads = 4;
    
    mg_model_t* mgModel = NULL;
    printf("Loading model via mg_model_load...\n");
    fflush(stdout);
    mg_error_t rc = dll.mg_model_load(model_path, &mgConfig, &mgModel);
    if (rc != MG_SUCCESS || !mgModel) {
        printf("Failed to load model via mg_model_load: %d\n", rc);
        fflush(stdout);
        return 1;
    }
    
    mg_context_t* mgContext = NULL;
    printf("Creating mg_context...\n");
    fflush(stdout);
    rc = dll.mg_context_create(mgModel, &mgContext);
    if (rc != MG_SUCCESS || !mgContext) {
        printf("Failed to create mg_context: %d\n", rc);
        fflush(stdout);
        return 1;
    }
    
    printf("Model loaded via ModelGenieRuntime, vocab size: %zu\n", dll.mg_model_vocab_size(mgModel));
    fflush(stdout);
    
    // Create output directory
    printf("Creating output directory...\n");
    fflush(stdout);
    _mkdir("F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001");
    
    // Run teacher-forced evaluation at each position
    // For each position i, we feed tokens[0..i] and capture logits
    float* logits = new float[VOCAB_SIZE];
    
    int matches = 0, total = 0;
    
    for (int pos = 0; pos < NUM_POSITIONS; pos++) {
        printf("Processing position %d...\n", pos);
        fflush(stdout);
        
        // Reset context for clean evaluation
        dll.mg_context_reset(mgContext);
        
        // Build token sequence up to position pos
        std::vector<uint32_t> prompt_tokens;
        for (int i = 0; i <= pos; i++) {
            prompt_tokens.push_back(teacher_forced_tokens[i]);
        }
        
        // Evaluate buffer to get logits at this position
        size_t logits_count = VOCAB_SIZE;
        rc = dll.mg_context_eval_buffer(mgContext, prompt_tokens.data(), prompt_tokens.size(), logits, &logits_count);
        
        if (rc != MG_SUCCESS) {
            printf("mg_context_eval_buffer failed at pos %d: %d\n", pos, rc);
            fflush(stdout);
            continue;
        }
        
        if (logits_count != VOCAB_SIZE) {
            printf("Warning: pos %d logits_count=%zu expected %d\n", pos, logits_count, VOCAB_SIZE);
        }
        
        // Save logits
        save_logits("F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001", pos, logits, VOCAB_SIZE);
        
        // Compare with native
        if (compare_logits("F:\\rawrxd\\evidence\\RAWRXD_CORE_DLL_NATIVE_E2E_001", 
                          "F:\\rawrxd\\evidence\\RAWRXD_DEEP2_DLL_EQUIVALENCE_001", pos)) {
            matches++;
        }
        total++;
    }
    
    printf("\n=== SUMMARY ===\n");
    printf("Matches: %d/%d (%.1f%%)\n", matches, total, 100.0 * matches / total);
    
    // Cleanup
    delete[] logits;
    dll.mg_context_free(mgContext);
    dll.mg_model_free(mgModel);
    dll.DestroyContext(ctx);
    dll.UnloadModel(model);
    dll.Shutdown();
    dll.Free();
    
    return 0;
}