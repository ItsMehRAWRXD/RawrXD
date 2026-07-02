// Sovereign SDK Example Application
// Demonstrates basic SDK usage for IDE integration

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Include the SDK header
#include "sovereign_sdk.h"

// Link against the SDK import library
#pragma comment(lib, "libsovereign.lib")

// Callback for task progress
void OnTaskProgress(uint32_t tokens_generated, uint32_t total_tokens, void* user_data) {
    printf("Progress: %u/%u tokens\n", tokens_generated, total_tokens);
}

// Callback for task completion
void OnTaskComplete(const char* result, size_t result_len, void* user_data) {
    printf("\n=== Task Complete ===\n");
    printf("Result: %.*s\n", (int)result_len, result);
    printf("=====================\n\n");
}

// Callback for logging
void OnLogMessage(int level, const char* message, void* user_data) {
    const char* level_str[] = { "DEBUG", "INFO", "WARNING", "ERROR" };
    printf("[%s] %s\n", level_str[level], message);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Sovereign SDK Example Application\n");
    printf("Version: %s\n", Sovereign_GetVersion());
    printf("========================================\n\n");
    
    // =========================================================================
    // Hardware Detection
    // =========================================================================
    
    printf("Hardware Capabilities:\n");
    printf("  AVX-512: %s\n", Sovereign_HasAVX512() ? "Yes" : "No");
    printf("  AMX:     %s\n", Sovereign_HasAMX() ? "Yes" : "No");
    
    uint32_t optimal_threads = Sovereign_GetOptimalThreadCount();
    printf("  Optimal Threads: %u\n", optimal_threads);
    
    uint64_t total_mem, available_mem;
    Sovereign_GetMemoryInfo(&total_mem, &available_mem);
    printf("  Memory: %.1f GB total, %.1f GB available\n",
        total_mem / (1024.0 * 1024 * 1024),
        available_mem / (1024.0 * 1024 * 1024));
    printf("\n");
    
    // =========================================================================
    // Initialize Sovereign Engine
    // =========================================================================
    
    printf("Initializing Sovereign Engine...\n");
    
    SovereignNodeConfig config = {
        .node_id = 0,
        .total_nodes = 1,
        .is_head = true,
        .enable_gpu = true,
        .enable_amx = Sovereign_HasAMX(),
        .thread_pool_size = optimal_threads,
        .kv_cache_size = 8ULL * 1024 * 1024 * 1024,  // 8GB
        .head_node_ip = "127.0.0.1",
        .router_port = 5555,
        .pub_port = 5556
    };
    
    SovereignHandle engine = Sovereign_Init(&config);
    if (!engine) {
        printf("ERROR: Failed to initialize engine: %s\n", 
            Sovereign_GetErrorString(Sovereign_GetLastError()));
        return 1;
    }
    
    printf("Engine initialized successfully!\n\n");
    
    // Set up logging
    Sovereign_SetLogCallback(OnLogMessage, NULL);
    Sovereign_SetLogLevel(1); // INFO level
    
    // =========================================================================
    // Get Engine Status
    // =========================================================================
    
    SovereignStatus status;
    if (Sovereign_GetStatus(engine, &status) == 0) {
        printf("Engine Status:\n");
        printf("  Flags: 0x%08X\n", status.flags);
        printf("    AVX-512: %s\n", (status.flags & SOVEREIGN_CAP_AVX512) ? "Yes" : "No");
        printf("    AMX:     %s\n", (status.flags & SOVEREIGN_CAP_AMX) ? "Yes" : "No");
        printf("    GPU:     %s\n", (status.flags & SOVEREIGN_CAP_GPU) ? "Yes" : "No");
        printf("    Ring:    %s\n", (status.flags & SOVEREIGN_CAP_RING) ? "Yes" : "No");
        printf("  Active Nodes: %u\n", status.active_nodes);
        printf("  Tasks Queued: %u\n", status.tasks_queued);
        printf("  Memory: %.1f GB used / %.1f GB available\n",
            status.memory_used / (1024.0 * 1024 * 1024),
            status.memory_available / (1024.0 * 1024 * 1024));
        printf("  Throughput: %.1f t/s\n", status.throughput_tps);
        printf("  Latency: %.1f ms\n", status.avg_latency_ms);
        printf("\n");
    }
    
    // =========================================================================
    // Load Model (Example)
    // =========================================================================
    
    printf("Loading model...\n");
    
    SovereignModelConfig model_config = {
        .model_path = "models/llama-7b-q4.gguf",
        .quantization = SOVEREIGN_QUANT_Q4_0,
        .memory_map = true,
        .lazy_load = true,
        .max_context = 4096
    };
    
    SovereignModelHandle model = Sovereign_LoadModel(engine, &model_config);
    if (!model) {
        printf("WARNING: Failed to load model: %s\n",
            Sovereign_GetErrorString(Sovereign_GetLastError()));
        printf("Continuing in demo mode...\n\n");
    } else {
        printf("Model loaded successfully!\n\n");
    }
    
    // =========================================================================
    // Submit Task (Example)
    // =========================================================================
    
    printf("Submitting inference task...\n");
    
    const char* prompt = "Explain the concept of ring attention in distributed LLM inference.";
    
    SovereignTaskParams task_params = {
        .type = SOVEREIGN_TASK_INFERENCE,
        .input = prompt,
        .input_len = strlen(prompt),
        .max_tokens = 256,
        .temperature = 0.7f,
        .user_data = NULL,
        .on_progress = OnTaskProgress,
        .on_complete = OnTaskComplete
    };
    
    SovereignTaskHandle task = Sovereign_SubmitTask(engine, model, &task_params);
    if (!task) {
        printf("WARNING: Failed to submit task: %s\n",
            Sovereign_GetErrorString(Sovereign_GetLastError()));
    } else {
        printf("Task submitted successfully!\n");
        
        // Wait for completion (in real app, this would be async)
        printf("Waiting for task completion...\n");
        int result = Sovereign_WaitForTask(engine, task, 30000); // 30 second timeout
        
        if (result == 0) {
            printf("Task completed successfully!\n");
        } else if (result == 1) {
            printf("Task timed out.\n");
        } else {
            printf("Task failed: %s\n", Sovereign_GetErrorString(Sovereign_GetLastError()));
        }
    }
    
    printf("\n");
    
    // =========================================================================
    // Semantic Graph Example (IDE Feature)
    // =========================================================================
    
    printf("Loading code base for semantic analysis...\n");
    
    SovereignGraphHandle graph = Sovereign_LoadCodeBase(engine, "./src");
    if (!graph) {
        printf("WARNING: Failed to load code base: %s\n",
            Sovereign_GetErrorString(Sovereign_GetLastError()));
    } else {
        printf("Code base loaded successfully!\n");
        
        // Query semantic graph
        const char* query = "Find all functions that handle memory allocation";
        char results[4096];
        size_t results_len = sizeof(results);
        
        if (Sovereign_QuerySemanticGraph(engine, graph, query, results, &results_len) == 0) {
            printf("Query results:\n%.*s\n", (int)results_len, results);
        }
    }
    
    printf("\n");
    
    // =========================================================================
    // Cleanup
    // =========================================================================
    
    printf("Shutting down...\n");
    
    if (model) {
        Sovereign_UnloadModel(engine, model);
    }
    
    Sovereign_Shutdown(engine);
    
    printf("Shutdown complete.\n");
    printf("\n========================================\n");
    printf("Example completed successfully!\n");
    printf("========================================\n");
    
    return 0;
}