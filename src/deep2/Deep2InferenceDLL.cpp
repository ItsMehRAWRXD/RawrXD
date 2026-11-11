// ============================================================================
// Deep2InferenceDLL.cpp - Clean C API DLL for Deep2 inference
// Exports: Deep2_CreateEngine, Deep2_DestroyEngine, Deep2_LoadModel, Deep2_GenerateStream
// ============================================================================

#define RAWRXD_BUILD_WIN32IDE ON
#define LOCAL_ONLY_001 1
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>

// Include the inference engine headers
#include "cpu_inference_engine.h"

namespace RawrXD {
    extern "C" {
        // =========================================================================
        // Engine handle - opaque pointer to CPUInferenceEngine
        // =========================================================================
        
        __declspec(dllexport) void* Deep2_CreateEngine() {
            try {
                // Use the existing singleton pattern
                CPUInferenceEngine* engine = CPUInferenceEngine::getInstance();
                if (!engine) {
                    fprintf(stderr, "[Deep2InferenceDLL] Failed to get engine instance\n");
                    return nullptr;
                }
                return static_cast<void*>(engine);
            } catch (const std::exception& ex) {
                fprintf(stderr, "[Deep2InferenceDLL] CreateEngine exception: %s\n", ex.what());
                return nullptr;
            } catch (...) {
                fprintf(stderr, "[Deep2InferenceDLL] CreateEngine unknown exception\n");
                return nullptr;
            }
        }
        
        __declspec(dllexport) void Deep2_DestroyEngine(void* engine) {
            // CPUInferenceEngine is a singleton - don't actually destroy it
            // Just clear its state
            if (engine) {
                try {
                    CPUInferenceEngine* eng = static_cast<CPUInferenceEngine*>(engine);
                    eng->ClearCache();
                } catch (...) {
                    // Ignore cleanup errors
                }
            }
        }
        
        __declspec(dllexport) int Deep2_LoadModel(void* engine, const char* modelPath) {
            if (!engine || !modelPath || !modelPath[0]) {
                return -1;  // Invalid arguments
            }
            
            try {
                CPUInferenceEngine* eng = static_cast<CPUInferenceEngine*>(engine);
                
                if (!eng->LoadModel(std::string(modelPath))) {
                    fprintf(stderr, "[Deep2InferenceDLL] LoadModel failed for: %s\n", modelPath);
                    return -2;
                }
                
                fprintf(stderr, "[Deep2InferenceDLL] Model loaded successfully: %s\n", modelPath);
                return 0;
            } catch (const std::exception& ex) {
                fprintf(stderr, "[Deep2InferenceDLL] LoadModel exception: %s\n", ex.what());
                return -3;
            } catch (...) {
                fprintf(stderr, "[Deep2InferenceDLL] LoadModel unknown exception\n");
                return -4;
            }
        }
        
        __declspec(dllexport) int Deep2_UnloadModel(void* engine) {
            if (!engine) return -1;
            try {
                CPUInferenceEngine* eng = static_cast<CPUInferenceEngine*>(engine);
                eng->ClearCache();
                return 0;
            } catch (...) {
                return -2;
            }
        }
        
        // Callback type for streaming tokens
        using TokenCallback = void (__cdecl*)(const char* utf8Fragment, int isLast, void* userData);
        
        __declspec(dllexport) int Deep2_GenerateStream(
            void* engine,
            const char* promptUtf8,
            int maxTokens,
            TokenCallback onToken,
            void* userData
        ) {
            if (!engine || !promptUtf8 || !onToken) {
                return -1;  // Invalid arguments
            }
            
            try {
                CPUInferenceEngine* eng = static_cast<CPUInferenceEngine*>(engine);
                
                if (!eng->IsModelLoaded()) {
                    fprintf(stderr, "[Deep2InferenceDLL] No model loaded\n");
                    return -2;
                }
                
                std::string prompt = promptUtf8 ? std::string(promptUtf8) : std::string();
                if (prompt.empty()) {
                    onToken("", 1, userData);
                    return 0;
                }
                
                int mt = maxTokens > 0 ? maxTokens : 256;
                
                // Tokenize the prompt
                std::vector<int32_t> tokens = eng->Tokenize(prompt);
                if (tokens.empty()) {
                    fprintf(stderr, "[Deep2InferenceDLL] Tokenization produced empty result\n");
                    onToken("", 1, userData);
                    return 0;
                }
                
                // Streaming generation
                eng->GenerateStreaming(
                    tokens,
                    mt,
                    [&](const std::string& piece) {
                        if (!piece.empty()) {
                            onToken(piece.c_str(), 0, userData);
                        }
                    },
                    [&]() {
                        onToken("", 1, userData);
                    },
                    nullptr  // No token ID callback needed
                );
                
                return 0;
            } catch (const std::exception& ex) {
                fprintf(stderr, "[Deep2InferenceDLL] GenerateStream exception: %s\n", ex.what());
                return -3;
            } catch (...) {
                fprintf(stderr, "[Deep2InferenceDLL] GenerateStream unknown exception\n");
                return -4;
            }
        }
        
        __declspec(dllexport) int Deep2_GenerateBlocking(
            void* engine,
            const char* promptUtf8,
            int maxTokens,
            char* outputBuffer,
            unsigned int outputBufferSize,
            unsigned int* outputRequired
        ) {
            if (!engine || !promptUtf8 || !outputBuffer || outputBufferSize == 0) {
                return -1;
            }
            
            try {
                CPUInferenceEngine* eng = static_cast<CPUInferenceEngine*>(engine);
                
                if (!eng->IsModelLoaded()) {
                    return -2;
                }
                
                std::string prompt = promptUtf8 ? std::string(promptUtf8) : std::string();
                if (prompt.empty()) {
                    if (outputRequired) *outputRequired = 1;
                    outputBuffer[0] = '\0';
                    return 0;
                }
                
                int mt = maxTokens > 0 ? maxTokens : 256;
                std::vector<int32_t> tokens = eng->Tokenize(prompt);
                
                std::string accumulated;
                std::mutex accum_mutex;
                std::atomic<bool> done{false};
                
                eng->GenerateStreaming(
                    tokens,
                    mt,
                    [&](const std::string& piece) {
                        std::lock_guard<std::mutex> lock(accum_mutex);
                        accumulated += piece;
                    },
                    [&]() {
                        done = true;
                    },
                    nullptr
                );
                
                // Wait for completion (with timeout)
                int wait_count = 0;
                while (!done && wait_count < 300) {  // 30 second timeout
                    Sleep(100);
                    wait_count++;
                }
                
                if (!done) {
                    fprintf(stderr, "[Deep2InferenceDLL] Generation timeout\n");
                    return -3;
                }
                
                unsigned int required = static_cast<unsigned int>(accumulated.size() + 1);
                if (outputRequired) *outputRequired = required;
                
                size_t copy_len = std::min<size_t>(accumulated.size(), outputBufferSize - 1);
                if (copy_len > 0) {
                    std::memcpy(outputBuffer, accumulated.c_str(), copy_len);
                }
                outputBuffer[copy_len] = '\0';
                
                return (required <= outputBufferSize) ? 0 : 1;
            } catch (const std::exception& ex) {
                fprintf(stderr, "[Deep2InferenceDLL] GenerateBlocking exception: %s\n", ex.what());
                return -4;
            } catch (...) {
                return -5;
            }
        }
        
        __declspec(dllexport) int Deep2_GetVersion() {
            return 1;
        }
        
        __declspec(dllexport) const char* Deep2_GetEngineName() {
            return "Deep2InferenceDLL/1.0 (CPUInferenceEngine wrapper)";
        }
        
    } // extern "C"
    
} // namespace RawrXD

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}