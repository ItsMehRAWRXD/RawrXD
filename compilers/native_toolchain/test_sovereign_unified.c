// test_sovereign_unified.c - Test harness for unified model loader
// Tests all GGUF models on F:\OllamaModels

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <dirent.h>
#include "sovereign_unified_model_loader.h"

#define MAX_MODELS 128
#define MAX_PATH_LEN 1024

typedef struct {
    char path[MAX_PATH_LEN];
    char name[256];
    uint64_t size;
    bool loaded;
    SovereignModelConfig config;
} ModelInfo;

static int g_tests_passed = 0;
static int g_tests_failed = 0;
static int g_tests_total = 0;

#define TEST(name) printf("  [TEST] %-60s ", name);
#define PASS() do { printf("PASS\n"); g_tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); g_tests_failed++; } while(0)

// Progress callback
static void progress_callback(float progress, const char* status, void* user_data) {
    (void)user_data;
    printf("\r  [LOAD] %.1f%% - %s", progress * 100.0f, status);
    fflush(stdout);
    if (progress >= 1.0f) {
        printf("\n");
    }
}

// Find all GGUF models
static int find_models(const char* directory, ModelInfo* models, int max_models) {
    DIR* dir = opendir(directory);
    if (!dir) {
        printf("  [ERROR] Cannot open directory: %s\n", directory);
        return 0;
    }
    
    int count = 0;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) != NULL && count < max_models) {
        // Check if file ends with .gguf
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, ".gguf") == 0) {
            snprintf(models[count].path, MAX_PATH_LEN, "%s/%s", directory, entry->d_name);
            strncpy(models[count].name, entry->d_name, sizeof(models[count].name) - 1);
            
            // Get file size
            WIN32_FILE_ATTRIBUTE_DATA fad;
            wchar_t wpath[MAX_PATH_LEN];
            MultiByteToWideChar(CP_UTF8, 0, models[count].path, -1, wpath, MAX_PATH_LEN);
            if (GetFileAttributesExW(wpath, GetFileExInfoStandard, &fad)) {
                ULARGE_INTEGER ul;
                ul.HighPart = fad.nFileSizeHigh;
                ul.LowPart = fad.nFileSizeLow;
                models[count].size = ul.QuadPart;
            }
            
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

// Test model loading
static bool test_model_load(ModelInfo* model) {
    wchar_t wpath[MAX_PATH_LEN];
    MultiByteToWideChar(CP_UTF8, 0, model->path, -1, wpath, MAX_PATH_LEN);
    
    SovereignModel* sovereign_model = NULL;
    SovereignStatus status = sovereign_load_model(wpath, &sovereign_model, progress_callback, NULL);
    
    if (status != SOVEREIGN_STATUS_OK) {
        printf("  [ERROR] Failed to load model: %s\n", model->name);
        return false;
    }
    
    // Get config
    status = sovereign_get_model_config(sovereign_model, &model->config);
    if (status != SOVEREIGN_STATUS_OK) {
        printf("  [ERROR] Failed to get model config: %s\n", model->name);
        sovereign_unload_model(sovereign_model);
        return false;
    }
    
    model->loaded = true;
    
    // Print model info
    printf("  [INFO] Model: %s\n", model->config.name);
    printf("  [INFO] Architecture: %s\n", model->config.architecture);
    printf("  [INFO] Context: %u, Embedding: %u, Heads: %u, Layers: %u\n",
           model->config.n_ctx, model->config.n_embd, model->config.n_head, model->config.n_layer);
    printf("  [INFO] Vocab: %u, FFN: %u\n", model->config.n_vocab, model->config.n_ff);
    
    sovereign_unload_model(sovereign_model);
    return true;
}

// Format file size
static const char* format_size(uint64_t size) {
    static char buf[64];
    if (size < 1024) {
        snprintf(buf, sizeof(buf), "%llu B", size);
    } else if (size < 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f KB", size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f MB", size / (1024.0 * 1024.0));
    } else {
        snprintf(buf, sizeof(buf), "%.2f GB", size / (1024.0 * 1024.0 * 1024.0));
    }
    return buf;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Sovereign Unified Model Loader Test\n");
    printf("========================================\n\n");
    
    // Initialize
    TEST("Initialize sovereign");
    SovereignStatus status = sovereign_init();
    if (status == SOVEREIGN_STATUS_OK) {
        PASS();
    } else {
        FAIL("Failed to initialize sovereign");
        return 1;
    }
    
    // Find models
    const char* models_dir = "F:\\OllamaModels";
    if (argc > 1) {
        models_dir = argv[1];
    }
    
    printf("\n[INFO] Scanning directory: %s\n", models_dir);
    
    ModelInfo* models = (ModelInfo*)calloc(MAX_MODELS, sizeof(ModelInfo));
    if (!models) {
        printf("[ERROR] Failed to allocate model array\n");
        return 1;
    }
    
    int num_models = find_models(models_dir, models, MAX_MODELS);
    printf("[INFO] Found %d GGUF models\n\n", num_models);
    
    if (num_models == 0) {
        printf("[WARN] No models found in %s\n", models_dir);
        free(models);
        return 0;
    }
    
    // Test each model
    for (int i = 0; i < num_models; i++) {
        printf("========================================\n");
        printf("Model %d/%d: %s\n", i + 1, num_models, models[i].name);
        printf("========================================\n");
        printf("  [INFO] Size: %s\n", format_size(models[i].size));
        
        char test_name[256];
        snprintf(test_name, sizeof(test_name), "Load %s", models[i].name);
        
        TEST(test_name);
        g_tests_total++;
        
        if (test_model_load(&models[i])) {
            PASS();
        } else {
            FAIL("Load failed");
        }
        
        printf("\n");
    }
    
    // Cleanup
    TEST("Cleanup sovereign");
    sovereign_cleanup();
    PASS();
    
    // Summary
    printf("========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total:  %d\n", g_tests_total);
    printf("Passed: %d\n", g_tests_passed);
    printf("Failed: %d\n", g_tests_failed);
    printf("========================================\n");
    
    free(models);
    return g_tests_failed > 0 ? 1 : 0;
}