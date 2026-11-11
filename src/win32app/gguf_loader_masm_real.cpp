// ============================================================================
// gguf_loader_masm_real.cpp — Win32IDE GGUF Loader (REAL Implementation)
// ============================================================================
// Connects Win32IDE to the actual GGUFLoader implementation
// Replaces: gguf_loader_masm.cpp (stub implementation)
// ============================================================================

#include "../../include/gguf_loader.h"
#include <windows.h>
#include <string>
#include <memory>

// Global loader instance
static std::unique_ptr<CPUInference::GGUFLoader> g_ggufLoader;
static std::string g_lastError;
static bool g_modelLoaded = false;

extern "C" {
    // Initialize the GGUF loader
    __declspec(dllexport) bool Win32IDE_InitGGUFLoader() {
        if (!g_ggufLoader) {
            g_ggufLoader = std::make_unique<CPUInference::GGUFLoader>();
        }
        OutputDebugStringA("[GGUF] Loader initialized\n");
        return true;
    }
    
    // Load a GGUF model file
    __declspec(dllexport) bool Win32IDE_LoadGGUFModel(const char* path) {
        if (!path || !*path) {
            g_lastError = "Invalid path";
            return false;
        }
        
        if (!g_ggufLoader) {
            Win32IDE_InitGGUFLoader();
        }
        
        OutputDebugStringA("[GGUF] Loading model: ");
        OutputDebugStringA(path);
        OutputDebugStringA("\n");
        
        // Close any previously loaded model
        if (g_modelLoaded) {
            g_ggufLoader->Close();
            g_modelLoaded = false;
        }
        
        // Open the new model
        if (!g_ggufLoader->Open(path)) {
            g_lastError = "Failed to open GGUF file: " + std::string(path);
            OutputDebugStringA("[GGUF] Failed to open file\n");
            return false;
        }
        
        // Parse header
        if (!g_ggufLoader->ParseHeader()) {
            g_lastError = "Failed to parse GGUF header";
            g_ggufLoader->Close();
            OutputDebugStringA("[GGUF] Failed to parse header\n");
            return false;
        }
        
        // Parse metadata
        if (!g_ggufLoader->ParseMetadata()) {
            g_lastError = "Failed to parse GGUF metadata";
            g_ggufLoader->Close();
            OutputDebugStringA("[GGUF] Failed to parse metadata\n");
            return false;
        }
        
        // Build tensor index
        if (!g_ggufLoader->BuildTensorIndex()) {
            g_lastError = "Failed to build tensor index";
            g_ggufLoader->Close();
            OutputDebugStringA("[GGUF] Failed to build tensor index\n");
            return false;
        }
        
        g_modelLoaded = true;
        OutputDebugStringA("[GGUF] Model loaded successfully\n");
        return true;
    }
    
    // Validate the currently loaded model
    __declspec(dllexport) bool Win32IDE_ValidateGGUFModel() {
        if (!g_modelLoaded || !g_ggufLoader) {
            g_lastError = "No model loaded";
            return false;
        }
        
        auto header = g_ggufLoader->GetHeader();
        
        // Check magic number (GGUF = 0x46554747)
        if (header.magic != 0x46554747) {
            g_lastError = "Invalid GGUF magic number";
            return false;
        }
        
        // Check version (should be 3 for current GGUF)
        if (header.version != 3) {
            g_lastError = "Unsupported GGUF version: " + std::to_string(header.version);
            return false;
        }
        
        // Check tensor count
        if (header.tensor_count == 0) {
            g_lastError = "No tensors in model";
            return false;
        }
        
        OutputDebugStringA("[GGUF] Model validation passed\n");
        return true;
    }
    
    // Get the size of the loaded model in bytes
    __declspec(dllexport) size_t Win32IDE_GetGGUFModelSize() {
        if (!g_modelLoaded || !g_ggufLoader) {
            return 0;
        }
        return static_cast<size_t>(g_ggufLoader->GetFileSize());
    }
    
    // Get model metadata as JSON string
    __declspec(dllexport) int Win32IDE_GetGGUFMetadata(char* buffer, int bufferSize) {
        if (!g_modelLoaded || !g_ggufLoader || !buffer || bufferSize <= 0) {
            return -1;
        }
        
        auto metadata = g_ggufLoader->GetMetadata();
        
        // Build simple JSON
        std::string json = "{";
        json += "\"architecture\":\"" + metadata.kv_pairs["general.architecture"] + "\",";
        json += "\"layer_count\":" + std::to_string(metadata.layer_count) + ",";
        json += "\"head_count\":" + std::to_string(metadata.head_count) + ",";
        json += "\"context_length\":" + std::to_string(metadata.context_length) + ",";
        json += "\"embedding_dim\":" + std::to_string(metadata.embedding_dim) + ",";
        json += "\"vocab_size\":" + std::to_string(metadata.vocab_size);
        json += "}";
        
        if ((int)json.length() >= bufferSize) {
            return -2; // Buffer too small
        }
        
        strcpy_s(buffer, bufferSize, json.c_str());
        return (int)json.length();
    }
    
    // Get tensor count
    __declspec(dllexport) int Win32IDE_GetGGUFTensorCount() {
        if (!g_modelLoaded || !g_ggufLoader) {
            return 0;
        }
        auto tensors = g_ggufLoader->GetTensorInfo();
        return (int)tensors.size();
    }
    
    // Get last error message
    __declspec(dllexport) const char* Win32IDE_GetGGUFLastError() {
        return g_lastError.c_str();
    }
    
    // Unload the current model
    __declspec(dllexport) void Win32IDE_UnloadGGUFModel() {
        if (g_ggufLoader) {
            g_ggufLoader->Close();
        }
        g_modelLoaded = false;
        g_lastError.clear();
        OutputDebugStringA("[GGUF] Model unloaded\n");
    }
    
    // Check if a model is loaded
    __declspec(dllexport) bool Win32IDE_IsGGUFModelLoaded() {
        return g_modelLoaded;
    }
}
