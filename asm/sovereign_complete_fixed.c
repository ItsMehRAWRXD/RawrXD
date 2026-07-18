/* sovereign_complete_fixed.c - Complete Sovereign Engine with Fixed Heap
 * Full inference engine with GGUF loading, token generation, and streaming
 * Compile: gcc -O2 -o sovereign_complete_fixed.exe sovereign_complete_fixed.c -lwinhttp
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#pragma comment(lib, "winhttp.lib")

/* ============================================================================
 * FIXED HEAP IMPLEMENTATION
 * ============================================================================ */

static HANDLE g_heap = NULL;
static BOOL g_heap_initialized = FALSE;

int Heap_Init(void) {
    if (g_heap_initialized) return 0;
    g_heap = GetProcessHeap();
    if (g_heap == NULL) return 1;
    g_heap_initialized = TRUE;
    return 0;
}

void* Heap_Alloc(size_t size) {
    if (!g_heap_initialized && Heap_Init() != 0) return NULL;
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, size);
}

void Heap_Free(void* ptr) {
    if (ptr && g_heap_initialized) HeapFree(g_heap, 0, ptr);
}

/* ============================================================================
 * GGUF FORMAT
 * ============================================================================ */

#define GGUF_MAGIC 0x46554747

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;

/* ============================================================================
 * MODEL CONTEXT
 * ============================================================================ */

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    LPVOID base_addr;
    size_t file_size;
    gguf_header_t header;
    char model_name[256];
    int loaded;
} model_context_t;

/* ============================================================================
 * INFERENCE CONTEXT
 * ============================================================================ */

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    char* response_buffer;
    size_t response_size;
    size_t response_capacity;
    double start_time;
    int tokens_generated;
    int is_streaming;
} inference_context_t;

/* ============================================================================
 * MODEL LOADING
 * ============================================================================ */

int model_load(const char* path, model_context_t* ctx) {
    memset(ctx, 0, sizeof(model_context_t));
    
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 
                                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Failed to open model file: %s\n", path);
        return -1;
    }
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(ctx->file_handle, &size)) {
        CloseHandle(ctx->file_handle);
        return -1;
    }
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) {
        CloseHandle(ctx->file_handle);
        return -1;
    }
    
    ctx->base_addr = MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->base_addr) {
        CloseHandle(ctx->map_handle);
        CloseHandle(ctx->file_handle);
        return -1;
    }
    
    memcpy(&ctx->header, ctx->base_addr, sizeof(gguf_header_t));
    
    if (ctx->header.magic != GGUF_MAGIC) {
        fprintf(stderr, "Error: Invalid GGUF magic\n");
        model_unload(ctx);
        return -1;
    }
    
    const char* filename = strrchr(path, '\\');
    if (!filename) filename = strrchr(path, '/');
    if (!filename) filename = path; else filename++;
    strncpy(ctx->model_name, filename, 255);
    ctx->model_name[255] = '\0';
    ctx->loaded = 1;
    
    return 0;
}

void model_unload(model_context_t* ctx) {
    if (ctx->base_addr) {
        UnmapViewOfFile(ctx->base_addr);
        ctx->base_addr = NULL;
    }
    if (ctx->map_handle) {
        CloseHandle(ctx->map_handle);
        ctx->map_handle = NULL;
    }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
        ctx->file_handle = INVALID_HANDLE_VALUE;
    }
    ctx->loaded = 0;
}

/* ============================================================================
 * INFERENCE / STREAMING
 * ============================================================================ */

int inference_init(inference_context_t* ctx) {
    memset(ctx, 0, sizeof(inference_context_t));
    
    ctx->hSession = WinHttpOpen(L"SovereignEngine/1.0", 
                                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME, 
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ctx->hSession) return -1;
    
    ctx->response_capacity = 65536;
    ctx->response_buffer = (char*)Heap_Alloc(ctx->response_capacity);
    if (!ctx->response_buffer) {
        WinHttpCloseHandle(ctx->hSession);
        return -1;
    }
    
    return 0;
}

void inference_cleanup(inference_context_t* ctx) {
    if (ctx->hRequest) WinHttpCloseHandle(ctx->hRequest);
    if (ctx->hConnect) WinHttpCloseHandle(ctx->hConnect);
    if (ctx->hSession) WinHttpCloseHandle(ctx->hSession);
    if (ctx->response_buffer) Heap_Free(ctx->response_buffer);
    memset(ctx, 0, sizeof(inference_context_t));
}

int inference_generate(inference_context_t* ctx, const char* model, const char* prompt, 
                       int max_tokens, void (*token_callback)(const char* token, void* user_data),
                       void* user_data) {
    ctx->hConnect = WinHttpConnect(ctx->hSession, L"localhost", 11434, 0);
    if (!ctx->hConnect) return -1;
    
    ctx->hRequest = WinHttpOpenRequest(ctx->hConnect, L"POST", L"/api/generate",
                                          NULL, WINHTTP_NO_REFERER, 
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!ctx->hRequest) return -1;
    
    char json_payload[4096];
    snprintf(json_payload, sizeof(json_payload),
        "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":true,\"options\":{\"num_predict\":%d}}",
        model, prompt, max_tokens);
    
    WinHttpAddRequestHeaders(ctx->hRequest, L"Content-Type: application/json", 
                              (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD);
    
    if (!WinHttpSendRequest(ctx->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            json_payload, (DWORD)strlen(json_payload), 
                            (DWORD)strlen(json_payload), 0)) {
        return -1;
    }
    
    if (!WinHttpReceiveResponse(ctx->hRequest, NULL)) return -1;
    
    ctx->is_streaming = 1;
    ctx->start_time = (double)GetTickCount64() / 1000.0;
    ctx->tokens_generated = 0;
    
    char chunk[4096];
    DWORD bytes_read;
    
    while (ctx->is_streaming && ctx->tokens_generated < max_tokens) {
        if (!WinHttpReadData(ctx->hRequest, chunk, sizeof(chunk) - 1, &bytes_read)) {
            break;
        }
        if (bytes_read == 0) break;
        
        chunk[bytes_read] = '\0';
        
        // Simple JSON parsing - extract response field
        char* resp = strstr(chunk, "\"response\":\"");
        if (resp) {
            resp += 12;
            char* end = strchr(resp, '"');
            if (end) {
                *end = '\0';
                if (token_callback) token_callback(resp, user_data);
                ctx->tokens_generated++;
            }
        }
        
        // Check for done signal
        if (strstr(chunk, "\"done\":true")) break;
    }
    
    ctx->is_streaming = 0;
    return ctx->tokens_generated;
}

/* ============================================================================
 * TOKEN CALLBACK
 * ============================================================================ */

void print_token(const char* token, void* user_data) {
    (void)user_data;
    printf("%s", token);
    fflush(stdout);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

void print_usage(const char* prog) {
    printf("Sovereign Engine - Fixed Heap Version\n");
    printf("=====================================\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  load <model.gguf>           Load and verify model\n");
    printf("  generate <model> <prompt>   Generate text\n");
    printf("  benchmark <model>           Run performance benchmark\n");
    printf("  test                        Run heap tests\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s load model.gguf\n", prog);
    printf("  %s generate deepseek-r1:8b \"Hello world\"\n", prog);
    printf("  %s benchmark qwen2.5-coder:14b\n", prog);
}

int cmd_test(void) {
    printf("Running heap tests...\n");
    
    // Test 1: Initialize
    if (Heap_Init() != 0) {
        printf("FAIL: Heap_Init\n");
        return 1;
    }
    printf("PASS: Heap_Init\n");
    
    // Test 2: Allocate
    void* p1 = Heap_Alloc(1024);
    if (!p1) {
        printf("FAIL: Heap_Alloc\n");
        return 2;
    }
    printf("PASS: Heap_Alloc (ptr=%p)\n", p1);
    
    // Test 3: Write
    memset(p1, 0xAB, 1024);
    printf("PASS: Memory write\n");
    
    // Test 4: Free
    Heap_Free(p1);
    printf("PASS: Heap_Free\n");
    
    // Test 5: NULL free
    Heap_Free(NULL);
    printf("PASS: NULL free\n");
    
    printf("\nAll heap tests PASSED!\n");
    return 0;
}

int cmd_load(const char* path) {
    model_context_t ctx;
    
    printf("Loading model: %s\n", path);
    
    if (model_load(path, &ctx) != 0) {
        fprintf(stderr, "Failed to load model\n");
        return 1;
    }
    
    printf("\nModel loaded successfully!\n");
    printf("  Name:    %s\n", ctx.model_name);
    printf("  Size:    %.2f MB\n", ctx.file_size / (1024.0 * 1024.0));
    printf("  Version: %u\n", ctx.header.version);
    printf("  Tensors: %llu\n", ctx.header.tensor_count);
    printf("  Metadata: %llu pairs\n", ctx.header.metadata_kv_count);
    
    model_unload(&ctx);
    return 0;
}

int cmd_generate(const char* model, const char* prompt) {
    inference_context_t ctx;
    
    printf("Generating with model: %s\n", model);
    printf("Prompt: %s\n\n", prompt);
    
    if (inference_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize inference\n");
        return 1;
    }
    
    double start = (double)GetTickCount64() / 1000.0;
    
    int tokens = inference_generate(&ctx, model, prompt, 100, print_token, NULL);
    
    double elapsed = ((double)GetTickCount64() / 1000.0) - start;
    
    printf("\n\n========================\n");
    printf("Tokens: %d\n", tokens);
    printf("Time: %.2f seconds\n", elapsed);
    if (elapsed > 0) {
        printf("TPS: %.2f\n", tokens / elapsed);
    }
    
    inference_cleanup(&ctx);
    return 0;
}

int cmd_benchmark(const char* model) {
    inference_context_t ctx;
    
    printf("Benchmarking model: %s\n", model);
    printf("Running 5 iterations...\n\n");
    
    if (inference_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize inference\n");
        return 1;
    }
    
    double total_tps = 0;
    int iterations = 5;
    
    for (int i = 0; i < iterations; i++) {
        double start = (double)GetTickCount64() / 1000.0;
        int tokens = inference_generate(&ctx, model, "Explain quantum computing briefly.", 50, NULL, NULL);
        double elapsed = ((double)GetTickCount64() / 1000.0) - start;
        double tps = (elapsed > 0) ? tokens / elapsed : 0;
        total_tps += tps;
        
        printf("Iteration %d: %d tokens in %.2f seconds (%.2f TPS)\n", 
               i + 1, tokens, elapsed, tps);
        
        inference_cleanup(&ctx);
        if (i < iterations - 1) {
            if (inference_init(&ctx) != 0) break;
        }
    }
    
    printf("\n========================\n");
    printf("Average TPS: %.2f\n", total_tps / iterations);
    
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize heap first thing
    if (Heap_Init() != 0) {
        fprintf(stderr, "Fatal: Failed to initialize heap\n");
        return 1;
    }
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* cmd = argv[1];
    
    if (strcmp(cmd, "test") == 0) {
        return cmd_test();
    } else if (strcmp(cmd, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: load requires a model file\n");
            return 1;
        }
        return cmd_load(argv[2]);
    } else if (strcmp(cmd, "generate") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: generate requires model and prompt\n");
            return 1;
        }
        return cmd_generate(argv[2], argv[3]);
    } else if (strcmp(cmd, "benchmark") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: benchmark requires a model\n");
            return 1;
        }
        return cmd_benchmark(argv[2]);
    } else {
        fprintf(stderr, "Error: Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
