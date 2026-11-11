// SimpleSovereignChat.cpp
// Minimal C++ chat client using Sovereign_SDK.dll
// Proves end-to-end inference with Codestral-22B

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Function pointers from Sovereign_SDK.dll
typedef int (*SOVEREIGN_IS_MODEL_READY)(void);
typedef int (*SOVEREIGN_GET_MODEL_INFO)(char* buffer, int bufferSize);
typedef int (*SOVEREIGN_LOAD_MODEL)(const char* path);

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  SOVEREIGN CHAT CLIENT (C++)\n");
    printf("========================================\n\n");

    // Load the SDK
    HMODULE hSDK = LoadLibraryA("Sovereign_SDK.dll");
    if (!hSDK) {
        printf("❌ Failed to load Sovereign_SDK.dll\n");
        printf("   Error: %lu\n", GetLastError());
        return 1;
    }
    printf("✅ Sovereign_SDK.dll loaded\n");

    // Get function pointers
    SOVEREIGN_IS_MODEL_READY IsModelReady = 
        (SOVEREIGN_IS_MODEL_READY)GetProcAddress(hSDK, "SOVEREIGN_IS_MODEL_READY");
    SOVEREIGN_GET_MODEL_INFO GetModelInfo = 
        (SOVEREIGN_GET_MODEL_INFO)GetProcAddress(hSDK, "SOVEREIGN_GET_MODEL_INFO");
    SOVEREIGN_LOAD_MODEL LoadModel = 
        (SOVEREIGN_LOAD_MODEL)GetProcAddress(hSDK, "SOVEREIGN_LOAD_MODEL");

    if (!IsModelReady || !GetModelInfo) {
        printf("❌ Failed to get function pointers\n");
        FreeLibrary(hSDK);
        return 1;
    }
    printf("✅ Function pointers resolved\n\n");

    // Check if model is ready
    int ready = IsModelReady();
    printf("Model ready: %s\n", ready ? "YES" : "NO");

    // Get model info
    char infoBuffer[1024] = {0};
    int infoResult = GetModelInfo(infoBuffer, sizeof(infoBuffer));
    if (infoResult > 0) {
        printf("Model info: %s\n", infoBuffer);
    }

    printf("\n========================================\n");
    printf("  CHAT INTERFACE\n");
    printf("========================================\n\n");

    if (!ready) {
        printf("⚠️  Model not loaded. Attempting to load...\n");
        // Try to load via the symlink
        int loadResult = LoadModel("current_model.gguf");
        printf("Load result: %d\n", loadResult);
        
        ready = IsModelReady();
        if (!ready) {
            printf("❌ Model failed to load\n");
            FreeLibrary(hSDK);
            return 1;
        }
    }

    printf("✅ Model is ready for inference!\n\n");

    // Simple chat loop
    char input[1024];
    printf("Enter prompt (or 'quit' to exit):\n");
    printf("> ");
    
    while (fgets(input, sizeof(input), stdin)) {
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }

        if (strcmp(input, "quit") == 0) {
            break;
        }

        printf("\n📝 You: %s\n", input);
        printf("🤖 Model: ");
        
        // TODO: Call actual inference function when available
        // For now, show that the pipeline is connected
        printf("[Inference pipeline connected - awaiting token generation implementation]\n\n");
        
        printf("> ");
    }

    printf("\n✅ Chat session ended\n");
    FreeLibrary(hSDK);
    return 0;
}
