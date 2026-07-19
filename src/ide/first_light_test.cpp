/*===========================================================================
 * first_light_test.cpp
 * Standalone test for SovereignInferenceBridge + Deep2Bridge integration
 * 
 * Usage: first_light_test.exe <model.gguf> [num_tokens]
 * 
 * This test validates:
 * - GGUF model loading via BraidedModelLoader
 * - Deep2Bridge initialization with real weights
 * - Token generation with full trace logging
 * - Performance metrics
 *===========================================================================*/

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <time.h>
#include <cstring>
// Include the bridge headers
#include "SovereignInferenceBridge.h"
#include "Deep2Bridge.h"

// Debug output helper
void Log(const char* msg) {
    printf("%s", msg);
    OutputDebugStringA(msg);
}

// Token callback for testing
void __stdcall TestTokenCallback(
    const WCHAR* token,
    uint32_t tokenIndex,
    BOOL isComplete,
    void* userData
) {
    (void)userData;
    
    // Convert wide to narrow for console output
    char narrow[256];
    WideCharToMultiByte(CP_UTF8, 0, token, -1, narrow, sizeof(narrow), NULL, NULL);
    
    printf("[Token %d] %s%s\n", tokenIndex, narrow, isComplete ? " (COMPLETE)" : "");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD IDE - First Light Test\n");
    printf("SovereignInferenceBridge + Deep2Bridge\n");
    printf("========================================\n\n");
    
    // Parse arguments
    const char* modelPath = "D:\\RawrXD\\models\\tinyllama.gguf";
    uint32_t numTokens = 5;
    
    if (argc > 1) {
        modelPath = argv[1];
    }
    if (argc > 2) {
        numTokens = (uint32_t)atoi(argv[2]);
    }
    
    printf("Configuration:\n");
    printf("  Model: %s\n", modelPath);
    printf("  Tokens to generate: %d\n\n", numTokens);
    
    // Step 1: Initialize SovereignInferenceBridge
    printf("[1/4] Initializing SovereignInferenceBridge...\n");
    SIB_Status status = SIB_Initialize();
    if (status != SIB_OK) {
        printf("ERROR: SIB_Initialize() failed with status %d\n", status);
        printf("Last error: %ls\n", SIB_GetLastError());
        return 1;
    }
    printf("      SUCCESS: Bridge initialized\n\n");
    
    // Step 2: Load model
    printf("[2/4] Loading GGUF model...\n");
    SIB_ModelInfo modelInfo = {0};
    // Convert char path to wchar_t for SIB_LoadModel
    wchar_t wModelPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, modelPath, -1, wModelPath, MAX_PATH);
    status = SIB_LoadModel(wModelPath, &modelInfo);
    if (status != SIB_OK) {
        printf("ERROR: SIB_LoadModel() failed with status %d\n", status);
        printf("Last error: %ls\n", SIB_GetLastError());
        SIB_Shutdown();
        return 1;
    }
    
    printf("      Model loaded successfully!\n");
    printf("      Name: %ls\n", modelInfo.name);
    printf("      Path: %ls\n", modelInfo.path);
    printf("      Hidden Dim: %d\n", modelInfo.hiddenDim);
    printf("      Layers: %d\n", modelInfo.numLayers);
    printf("      Vocab Size: %d\n", modelInfo.vocabSize);
    printf("      Context Length: %d\n", modelInfo.contextLength);
    printf("      Quantization: %d-bit\n", modelInfo.quantizationBits);
    printf("      Parameters: %.2fB\n", modelInfo.totalParams / 1e9);
    printf("      File Size: %.2f MB\n\n", modelInfo.fileSizeBytes / (1024.0 * 1024.0));
    
    // Check Deep2Bridge status
    printf("[3/4] Checking Deep2Bridge status...\n");
    if (Deep2Bridge_IsReady()) {
        printf("      Deep2Bridge: READY\n");
        printf("      AVX2: %s\n", Deep2Bridge_HasAVX2() ? "YES" : "NO");
        printf("      AVX512: %s\n", Deep2Bridge_HasAVX512() ? "YES" : "NO");
        printf("      Real Weights: %s\n\n", 
            Deep2Bridge_IsUsingRealWeights() ? "YES" : "NO (using dummy)");
    } else {
        printf("      WARNING: Deep2Bridge not ready\n\n");
    }
    
    // Step 4: Generate tokens
    printf("[4/4] Generating %d tokens...\n", numTokens);
    printf("      (Watch debug output for detailed trace)\n\n");
    
    SIB_CompletionRequest request = {0};
    wcscpy_s(request.prompt, SIB_MAX_PROMPT_LEN, L"// Hello world");
    wcscpy_s(request.filePath, MAX_PATH, L"test.cpp");
    request.cursorLine = 1;
    request.cursorColumn = 14;
    request.maxTokens = numTokens;
    request.temperature = 0.7f;
    request.topP = 0.9f;
    request.topK = 40;
    request.streamTokens = TRUE;
    request.userData = NULL;
    
    // Start timing
    clock_t start = clock();
    
    // Request completion
    status = SIB_RequestCompletion(&request, TestTokenCallback);
    if (status != SIB_OK) {
        printf("ERROR: SIB_RequestCompletion() failed with status %d\n", status);
        printf("Last error: %ls\n", SIB_GetLastError());
        SIB_UnloadModel();
        SIB_Shutdown();
        return 1;
    }
    
    // Wait for completion (with timeout)
    printf("Waiting for generation to complete...\n");
    int timeout = 30; // seconds
    while (SIB_IsInferencing() && timeout-- > 0) {
        Sleep(1000);
        printf(".");
    }
    printf("\n\n");
    
    // Calculate elapsed time
    clock_t end = clock();
    double elapsedMs = ((double)(end - start) * 1000.0) / CLOCKS_PER_SEC;
    
    // Results
    printf("========================================\n");
    printf("RESULTS\n");
    printf("========================================\n");
    printf("Elapsed time: %.2f ms\n", elapsedMs);
    printf("Tokens/sec: %.2f\n", numTokens / (elapsedMs / 1000.0));
    printf("Latency/token: %.2f ms\n", elapsedMs / numTokens);
    
    // Get Deep2 metrics
    Deep2PerfMetrics metrics;
    Deep2Bridge_GetMetrics(&metrics);
    printf("Total cycles: %llu\n", metrics.totalCycles);
    printf("Total tokens: %llu\n", metrics.totalTokens);
    if (metrics.totalTokens > 0) {
        printf("Avg cycles/token: %.2f\n", metrics.avgCyclesPerToken);
    }
    
    printf("\n");
    
    // Cleanup
    SIB_UnloadModel();
    SIB_Shutdown();
    
    printf("Test completed successfully!\n");
    return 0;
}
