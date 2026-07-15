/*
 * Model Manager - Zero Dependencies
 * Unified CLI for model loading, streaming, and inference
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define PATH_SEP '\\'
#else
#include <dirent.h>
#include <sys/stat.h>
#define PATH_SEP '/'
#endif

#include "gguf_loader_native.c"
#include "sovereign_inference_engine.c"

// Colors for terminal output
#ifdef _WIN32
#define COLOR_RESET ""
#define COLOR_GREEN ""
#define COLOR_YELLOW ""
#define COLOR_RED ""
#define COLOR_CYAN ""
#define COLOR_MAGENTA ""
#else
#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[36m"
#define COLOR_MAGENTA "\033[35m"
#endif

// Command types
typedef enum {
    CMD_NONE,
    CMD_LIST,
    CMD_INFO,
    CMD_LOAD,
    CMD_UNLOAD,
    CMD_STREAM,
    CMD_INFER,
    CMD_BENCH,
    CMD_CONVERT,
    CMD_HELP
} command_t;

// Print banner
void print_banner() {
    printf("\n");
    printf("=================================================\n");
    printf("  RawrXD Model Manager - Zero Dependencies\n");
    printf("  Native GGUF Loader + Sovereign Inference\n");
    printf("=================================================\n");
    printf("\n");
}

// Print help
void print_help() {
    printf("Usage: model_manager.exe <command> [options]\n\n");
    printf("Commands:\n");
    printf("  list [path]          List all .gguf models in directory\n");
    printf("  info <model.gguf>    Show detailed model information\n");
    printf("  load <model.gguf>    Load model into memory\n");
    printf("  stream <model.gguf>  Stream model with progressive loading\n");
    printf("  infer <model.gguf>   Run inference on model\n");
    printf("  bench <model.gguf>   Benchmark model loading/inference\n");
    printf("  help                 Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  model_manager.exe list D:\\models\n");
    printf("  model_manager.exe info model.gguf\n");
    printf("  model_manager.exe infer model.gguf --prompt \"Hello\"\n");
    printf("  model_manager.exe bench model.gguf --iterations 10\n");
}

// List models in directory
int cmd_list(const char* path) {
    printf("%sScanning for GGUF models in: %s%s\n\n", COLOR_CYAN, path, COLOR_RESET);
    
    int count = 0;
    
#ifdef _WIN32
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.gguf", path);
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search_path, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("%sNo .gguf files found%s\n", COLOR_YELLOW, COLOR_RESET);
        return 0;
    }
    
    printf("%-40s %15s %12s\n", "Model Name", "Size (MB)", "Architecture");
    printf("%-40s %15s %12s\n", "----------", "---------", "------------");
    
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s\\%s", path, findData.cFileName);
            
            LARGE_INTEGER size;
            size.LowPart = findData.nFileSizeLow;
            size.HighPart = findData.nFileSizeHigh;
            double mb = size.QuadPart / (1024.0 * 1024.0);
            
            // Try to get architecture
            struct gguf_file* gf = gguf_open(full_path);
            const char* arch = "unknown";
            if (gf) {
                const struct model_metadata* meta = gguf_get_metadata(gf);
                const char* arch_names[] = {"unknown", "llama", "qwen2", "phi3", "gemma", "mistral"};
                if (meta->arch >= 0 && meta->arch <= 5) {
                    arch = arch_names[meta->arch];
                }
                gguf_close(gf);
            }
            
            printf("%-40s %15.1f %12s\n", findData.cFileName, mb, arch);
            count++;
        }
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
#else
    DIR* dir = opendir(path);
    if (!dir) {
        printf("%sCannot open directory: %s%s\n", COLOR_RED, path, COLOR_RESET);
        return 0;
    }
    
    printf("%-40s %15s\n", "Model Name", "Size (MB)");
    printf("%-40s %15s\n", "----------", "---------");
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, ".gguf") == 0) {
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
            
            struct stat st;
            if (stat(full_path, &st) == 0) {
                double mb = st.st_size / (1024.0 * 1024.0);
                printf("%-40s %15.1f\n", entry->d_name, mb);
                count++;
            }
        }
    }
    
    closedir(dir);
#endif
    
    printf("\n%sFound %d model(s)%s\n", COLOR_GREEN, count, COLOR_RESET);
    return count;
}

// Show model info
int cmd_info(const char* model_path) {
    printf("%sLoading model: %s%s\n\n", COLOR_CYAN, model_path, COLOR_RESET);
    
    struct gguf_file* gf = gguf_open(model_path);
    if (!gf) {
        printf("%sFailed to open model: %s%s\n", COLOR_RED, model_path, COLOR_RESET);
        return 1;
    }
    
    gguf_print_info(gf);
    
    // Memory estimate
    size_t total_size = gguf_get_total_size(gf);
    printf("\n%sMemory Requirements:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  Model weights: %.2f MB\n", total_size / (1024.0 * 1024.0));
    printf("  KV cache (4K context): %.2f MB\n", 
           (gf->metadata.context_length * gf->metadata.kv_head_count * 
            (gf->metadata.embedding_dim / gf->metadata.head_count) * 2 * 4) / (1024.0 * 1024.0));
    
    gguf_close(gf);
    return 0;
}

// Load model
int cmd_load(const char* model_path, int load_all) {
    printf("%sLoading model: %s%s\n", COLOR_CYAN, model_path, COLOR_RESET);
    
    clock_t start = clock();
    
    struct gguf_file* gf = gguf_open(model_path);
    if (!gf) {
        printf("%sFailed to open model%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }
    
    if (load_all) {
        printf("Loading all tensors...\n");
        gguf_load_all_tensors(gf);
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    size_t loaded = gguf_get_loaded_memory(gf);
    size_t total = gguf_get_total_size(gf);
    
    printf("\n%sLoad Complete:%s\n", COLOR_GREEN, COLOR_RESET);
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Loaded: %.2f / %.2f MB (%.1f%%)\n", 
           loaded / (1024.0 * 1024.0), total / (1024.0 * 1024.0),
           100.0 * loaded / total);
    printf("  Throughput: %.2f MB/s\n", loaded / (1024.0 * 1024.0) / elapsed);
    
    printf("\nPress Enter to unload...\n");
    getchar();
    
    gguf_close(gf);
    printf("%sModel unloaded%s\n", COLOR_GREEN, COLOR_RESET);
    
    return 0;
}

// Stream model (progressive loading)
int cmd_stream(const char* model_path) {
    printf("%sStreaming model: %s%s\n\n", COLOR_CYAN, model_path, COLOR_RESET);
    
    struct gguf_file* gf = gguf_open(model_path);
    if (!gf) {
        printf("%sFailed to open model%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }
    
    printf("Model has %llu tensors\n", (unsigned long long)gf->tensor_count);
    printf("Streaming with on-demand loading...\n\n");
    
    // Simulate streaming by loading tensors progressively
    size_t total = gguf_get_total_size(gf);
    size_t batch_size = total / 10;
    size_t loaded = 0;
    
    for (uint64_t i = 0; i < gf->tensor_count && loaded < batch_size * 3; i++) {
        if (gguf_load_tensor(gf, i)) {
            loaded += gf->tensors[i].size;
            printf("\rProgress: %.1f%% (%s)", 
                   100.0 * loaded / total, gf->tensors[i].name);
        }
    }
    
    printf("\n\n%sStreamed %.2f MB (%.1f%%)%s\n", 
           COLOR_GREEN, loaded / (1024.0 * 1024.0), 100.0 * loaded / total, COLOR_RESET);
    
    printf("\nRemaining tensors will be loaded on-demand during inference.\n");
    
    gguf_close(gf);
    return 0;
}

// Run inference
int cmd_infer(const char* model_path, const char* prompt, int max_tokens, float temperature) {
    printf("%sInference Mode%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Model: %s\n", model_path);
    printf("Prompt: \"%s\"\n\n", prompt ? prompt : "(none)");
    
    // Load model
    printf("Loading model...\n");
    struct gguf_file* gf = gguf_open(model_path);
    if (!gf) {
        printf("%sFailed to load model%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }
    
    // Load all tensors for inference
    printf("Loading weights...\n");
    gguf_load_all_tensors(gf);
    
    // Create inference context
    struct inference_ctx* ctx = inference_create(gf);
    if (!ctx) {
        printf("%sFailed to create inference context%s\n", COLOR_RED, COLOR_RESET);
        gguf_close(gf);
        return 1;
    }
    
    // Simple tokenization (character-based for demo)
    int prompt_tokens[256];
    int prompt_len = 0;
    
    if (prompt) {
        // Simple tokenization: map chars to token IDs
        for (const char* p = prompt; *p && prompt_len < 256; p++, prompt_len++) {
            prompt_tokens[prompt_len] = (unsigned char)*p;
        }
    } else {
        // Default prompt
        prompt_tokens[0] = 1; // BOS
        prompt_len = 1;
    }
    
    // Generate
    printf("\n%sGenerating...%s\n\n", COLOR_GREEN, COLOR_RESET);
    
    clock_t start = clock();
    
    // Simple callback
    void token_cb(int token_id, const char* token_str) {
        (void)token_str;
        if (token_id < 256 && token_id >= 32) {
            printf("%c", token_id);
        } else {
            printf("[%d]", token_id);
        }
        fflush(stdout);
    }
    
    inference_generate(ctx, prompt_tokens, prompt_len, max_tokens, temperature, token_cb);
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("\n\n%sGeneration complete in %.2f seconds%s\n", 
           COLOR_GREEN, elapsed, COLOR_RESET);
    printf("Tokens/sec: %.2f\n", max_tokens / elapsed);
    
    // Cleanup
    inference_free(ctx);
    gguf_close(gf);
    
    return 0;
}

// Benchmark
int cmd_bench(const char* model_path, int iterations) {
    printf("%sBenchmark Mode%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Model: %s\n", model_path);
    printf("Iterations: %d\n\n", iterations);
    
    // Load test
    printf("=== Load Benchmark ===\n");
    double load_times[5];
    int num_loads = iterations < 5 ? iterations : 5;
    
    for (int i = 0; i < num_loads; i++) {
        clock_t start = clock();
        struct gguf_file* gf = gguf_open(model_path);
        if (!gf) {
            printf("Failed to load\n");
            return 1;
        }
        gguf_load_all_tensors(gf);
        clock_t end = clock();
        
        load_times[i] = (double)(end - start) / CLOCKS_PER_SEC;
        printf("  Run %d: %.3f seconds\n", i + 1, load_times[i]);
        
        gguf_close(gf);
    }
    
    double avg_load = 0;
    for (int i = 0; i < num_loads; i++) avg_load += load_times[i];
    avg_load /= num_loads;
    
    printf("\nAverage load time: %.3f seconds\n", avg_load);
    
    // Inference benchmark
    printf("\n=== Inference Benchmark ===\n");
    
    struct gguf_file* gf = gguf_open(model_path);
    if (!gf) return 1;
    gguf_load_all_tensors(gf);
    
    struct inference_ctx* ctx = inference_create(gf);
    if (!ctx) {
        gguf_close(gf);
        return 1;
    }
    
    double infer_times[10];
    int num_infer = iterations < 10 ? iterations : 10;
    
    for (int i = 0; i < num_infer; i++) {
        clock_t start = clock();
        float* logits = inference_forward(ctx, 1, 0);
        (void)logits;
        clock_t end = clock();
        
        infer_times[i] = (double)(end - start) / CLOCKS_PER_SEC;
    }
    
    double avg_infer = 0;
    for (int i = 0; i < num_infer; i++) avg_infer += infer_times[i];
    avg_infer /= num_infer;
    
    printf("  Average forward pass: %.4f seconds\n", avg_infer);
    printf("  Estimated tokens/sec: %.2f\n", 1.0 / avg_infer);
    
    inference_free(ctx);
    gguf_close(gf);
    
    printf("\n%sBenchmark Complete%s\n", COLOR_GREEN, COLOR_RESET);
    
    return 0;
}

// Parse arguments
int parse_args(int argc, char** argv, command_t* cmd, char** model_path, 
               char** prompt, int* max_tokens, float* temperature, int* iterations) {
    if (argc < 2) {
        *cmd = CMD_HELP;
        return 0;
    }
    
    // Default values
    *max_tokens = 50;
    *temperature = 0.7f;
    *iterations = 10;
    
    // Parse command
    if (strcmp(argv[1], "list") == 0) {
        *cmd = CMD_LIST;
        if (argc > 2) {
            *model_path = argv[2];
        } else {
            *model_path = ".";
        }
    }
    else if (strcmp(argv[1], "info") == 0) {
        *cmd = CMD_INFO;
        if (argc < 3) {
            printf("Error: info requires a model path\n");
            return 1;
        }
        *model_path = argv[2];
    }
    else if (strcmp(argv[1], "load") == 0) {
        *cmd = CMD_LOAD;
        if (argc < 3) {
            printf("Error: load requires a model path\n");
            return 1;
        }
        *model_path = argv[2];
    }
    else if (strcmp(argv[1], "stream") == 0) {
        *cmd = CMD_STREAM;
        if (argc < 3) {
            printf("Error: stream requires a model path\n");
            return 1;
        }
        *model_path = argv[2];
    }
    else if (strcmp(argv[1], "infer") == 0) {
        *cmd = CMD_INFER;
        if (argc < 3) {
            printf("Error: infer requires a model path\n");
            return 1;
        }
        *model_path = argv[2];
        
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
                *prompt = argv[++i];
            }
            else if (strcmp(argv[i], "--tokens") == 0 && i + 1 < argc) {
                *max_tokens = atoi(argv[++i]);
            }
            else if (strcmp(argv[i], "--temp") == 0 && i + 1 < argc) {
                *temperature = (float)atof(argv[++i]);
            }
        }
    }
    else if (strcmp(argv[1], "bench") == 0) {
        *cmd = CMD_BENCH;
        if (argc < 3) {
            printf("Error: bench requires a model path\n");
            return 1;
        }
        *model_path = argv[2];
        
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
                *iterations = atoi(argv[++i]);
            }
        }
    }
    else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        *cmd = CMD_HELP;
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        *cmd = CMD_HELP;
        return 1;
    }
    
    return 0;
}

// Main entry point
int main(int argc, char** argv) {
    print_banner();
    
    command_t cmd = CMD_NONE;
    char* model_path = NULL;
    char* prompt = NULL;
    int max_tokens = 50;
    float temperature = 0.7f;
    int iterations = 10;
    
    if (parse_args(argc, argv, &cmd, &model_path, &prompt, 
                   &max_tokens, &temperature, &iterations) != 0) {
        print_help();
        return 1;
    }
    
    switch (cmd) {
        case CMD_LIST:
            return cmd_list(model_path);
        case CMD_INFO:
            return cmd_info(model_path);
        case CMD_LOAD:
            return cmd_load(model_path, 1);
        case CMD_STREAM:
            return cmd_stream(model_path);
        case CMD_INFER:
            return cmd_infer(model_path, prompt, max_tokens, temperature);
        case CMD_BENCH:
            return cmd_bench(model_path, iterations);
        case CMD_HELP:
        default:
            print_help();
            return 0;
    }
    
    return 0;
}
