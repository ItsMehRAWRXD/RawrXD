// =============================================================================
// RawrXD Native Inference Benchmark — Real llama.cpp path with profiler
// =============================================================================
#include "inference/RawrXD_LlamaNative.h"
#include "inference_profiler_simple.h"
#include "Sovereign_Memory_Manager.h"
#include <cstdio>
#include <chrono>
#include <string>
#include <windows.h>

int main(int argc, char* argv[]) {
    printf("[DEBUG] Starting NativeBench...\n");
    
    // Initialize profiler
    printf("[DEBUG] Initializing profiler...\n");
    Profiler_Initialize();
    printf("[DEBUG] Profiler initialized\n");
    
    // Verify Sovereign Arena
    printf("[DEBUG] Initializing Sovereign Arena...\n");
    if (!SovereignArena_Initialize(0)) {
        printf("ERROR: Failed to initialize Sovereign Arena\n");
        return 1;
    }
    printf("[DEBUG] Sovereign Arena initialized: %zu MB\n", SovereignArena_GetSize() / (1024*1024));
    
    const char* modelPathA = (argc > 1) ? argv[1] : "F:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    const char* prompt = (argc > 2) ? argv[2] : "The quick brown fox";
    int maxTokens = (argc > 3) ? std::atoi(argv[3]) : 64;
    
    // Convert to wide string for Windows API
    std::wstring modelPathW;
    int len = MultiByteToWideChar(CP_UTF8, 0, modelPathA, -1, nullptr, 0);
    if (len > 0) {
        modelPathW.resize(len - 1);
        MultiByteToWideChar(CP_UTF8, 0, modelPathA, -1, &modelPathW[0], len);
    }
    
    printf("RawrXD Native Inference Benchmark\n");
    printf("=================================\n");
    printf("Model: %s\n", modelPathA);
    printf("Prompt: %s\n", prompt);
    printf("Max tokens: %d\n\n", maxTokens);
    
    // Initialize bridge - pass DLL directory explicitly
    printf("[DEBUG] Initializing llama bridge...\n");
    {
        PROFILE_BLOCK("bridge_init");
        // Get executable directory
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring exeDir = exePath;
        size_t lastSlash = exeDir.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            exeDir = exeDir.substr(0, lastSlash);
        }
        printf("[DEBUG] Loading DLLs from: %ls\n", exeDir.c_str());
        
        if (!GetLlamaBridge().Initialize(exeDir.c_str())) {
            printf("ERROR: Failed to initialize llama bridge: %s\n", 
                   GetLlamaBridge().GetLastError());
            return 1;
        }
    }
    printf("[DEBUG] Bridge initialized\n");
    
    // Load model
    printf("Loading model...\n");
    {
        PROFILE_BLOCK("total_load_model");
        if (!GetLlamaBridge().LoadModel(modelPathW.c_str(), -1, 4096)) {
            printf("ERROR: Failed to load model\n");
            return 1;
        }
    }
    printf("Model loaded successfully\n\n");
    
    // Run generation
    printf("Generating...\n");
    auto start = std::chrono::high_resolution_clock::now();
    
    auto result = GetLlamaBridge().Generate(prompt, maxTokens, 0.7f, 0.9f, 40);
    
    auto end = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Print results
    printf("\n=================================\n");
    printf("RESULTS\n");
    printf("=================================\n");
    if (result.success) {
        printf("Generated text: %s\n", result.text.c_str());
        printf("\n");
        printf("Prompt tokens:    %d\n", result.prompt_tokens);
        printf("Generated tokens: %d\n", result.tokens_generated);
        printf("Prompt time:      %.2f ms\n", result.t_prompt_ms);
        printf("Generation time:  %.2f ms\n", result.t_gen_ms);
        printf("Total time:       %.2f ms\n", totalMs);
        printf("Throughput:       %.2f tok/s\n", 
               result.tokens_generated > 0 ? (result.tokens_generated * 1000.0 / result.t_gen_ms) : 0);
    } else {
        printf("ERROR: %s\n", result.error.c_str());
    }
    
    // Dump profiler report
    printf("\n");
    rxdn::prof_dump();
    
    return result.success ? 0 : 1;
}
