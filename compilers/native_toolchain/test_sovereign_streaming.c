// test_sovereign_streaming.c - Test Sovereign Streaming Engine
// Tests model loading and streaming inference

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Import from DLL
__declspec(dllimport) int Sovereign_LoadModel(const wchar_t* path);
__declspec(dllimport) int Sovereign_InitInference(int model_id);
__declspec(dllimport) int Sovereign_StreamGenerate(const char* prompt, int max_tokens, 
                                                    void* on_token, 
                                                    void* on_progress,
                                                    void* user_data);
__declspec(dllimport) void Sovereign_FreeInference(void);
__declspec(dllimport) void Sovereign_UnloadModel(int model_id);
__declspec(dllimport) const char* Sovereign_GetModelInfo(int model_id, int* tensor_count, int* metadata_count);

// Callback for token streaming
void on_token(const char* token, void* user_data) {
    printf("%s", token);
    fflush(stdout);
}

// Callback for progress
void on_progress(float progress, void* user_data) {
    static int last_percent = -1;
    int percent = (int)(progress * 100);
    if (percent != last_percent) {
        printf("\rProgress: %d%%", percent);
        fflush(stdout);
        last_percent = percent;
    }
}

int main(int argc, char** argv) {
    printf("========================================\n");
    printf("Sovereign Streaming Engine Test\n");
    printf("========================================\n\n");
    
    // Check arguments
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        printf("\nTesting with default model path...\n");
        
        // Try default path
        const char* default_path = "F:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";
        printf("Loading: %s\n", default_path);
        
        // Convert to wide string
        wchar_t wpath[1024];
        MultiByteToWideChar(CP_UTF8, 0, default_path, -1, wpath, 1024);
        
        // Load model
        int model_id = Sovereign_LoadModel(wpath);
        if (model_id < 0) {
            printf("Failed to load model: %d\n", model_id);
            printf("Error codes:\n");
            printf("  -1: Invalid handle\n");
            printf("  -2: CreateFileMapping failed\n");
            printf("  -3: MapViewOfFile failed\n");
            printf("  -4: Invalid GGUF magic\n");
            printf("  -5: Unsupported GGUF version\n");
            printf("  -6: Memory allocation failed\n");
            printf("  -7: Metadata allocation failed\n");
            return 1;
        }
        
        printf("Model loaded successfully (ID: %d)\n", model_id);
        
        // Get model info
        int tensor_count, metadata_count;
        const char* info = Sovereign_GetModelInfo(model_id, &tensor_count, &metadata_count);
        if (info) {
            printf("Model info: %s\n", info);
            printf("  Tensors: %d\n", tensor_count);
            printf("  Metadata: %d\n", metadata_count);
        }
        
        // Initialize inference
        printf("\nInitializing inference...\n");
        if (Sovereign_InitInference(model_id) < 0) {
            printf("Failed to initialize inference\n");
            Sovereign_UnloadModel(model_id);
            return 1;
        }
        
        // Generate tokens
        printf("\nGenerating tokens...\n");
        printf("Output: ");
        
        int result = Sovereign_StreamGenerate("Hello", 50, on_token, on_progress, NULL);
        
        printf("\n\nGeneration complete (result: %d)\n", result);
        
        // Cleanup
        Sovereign_FreeInference();
        Sovereign_UnloadModel(model_id);
        
        printf("\n========================================\n");
        printf("Test completed successfully!\n");
        printf("========================================\n");
        
        return 0;
    }
    
    // Use provided model path
    printf("Loading: %s\n", argv[1]);
    
    // Convert to wide string
    wchar_t wpath[1024];
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wpath, 1024);
    
    // Load model
    int model_id = Sovereign_LoadModel(wpath);
    if (model_id < 0) {
        printf("Failed to load model: %d\n", model_id);
        return 1;
    }
    
    printf("Model loaded successfully (ID: %d)\n", model_id);
    
    // Get model info
    int tensor_count, metadata_count;
    const char* info = Sovereign_GetModelInfo(model_id, &tensor_count, &metadata_count);
    if (info) {
        printf("Model info: %s\n", info);
        printf("  Tensors: %d\n", tensor_count);
        printf("  Metadata: %d\n", metadata_count);
    }
    
    // Initialize inference
    printf("\nInitializing inference...\n");
    if (Sovereign_InitInference(model_id) < 0) {
        printf("Failed to initialize inference\n");
        Sovereign_UnloadModel(model_id);
        return 1;
    }
    
    // Generate tokens
    printf("\nGenerating tokens...\n");
    printf("Output: ");
    
    int result = Sovereign_StreamGenerate("Hello", 100, on_token, on_progress, NULL);
    
    printf("\n\nGeneration complete (result: %d)\n", result);
    
    // Cleanup
    Sovereign_FreeInference();
    Sovereign_UnloadModel(model_id);
    
    printf("\n========================================\n");
    printf("Test completed successfully!\n");
    printf("========================================\n");
    
    return 0;
}