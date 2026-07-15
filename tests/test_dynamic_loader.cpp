// ============================================================================
// test_dynamic_loader.cpp
// Standalone test harness for DynamicModelLoader
// Usage: test_dynamic_loader.exe [model_path]
// ============================================================================

#include "../src/dynamic_model_loader.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    using namespace RawrXD;
    
    std::cout << "=== RawrXD Dynamic Model Loader Test ===" << std::endl;
    
    auto& loader = DynamicModelLoader::instance();
    
    // Set memory limits
    loader.setMaxVRAMMB(16000);
    loader.setMaxRAMMB(64000);
    
    // Set callbacks
    loader.setOnLoadComplete([](const LoadResult& result) {
        std::cout << "[Callback] Load complete: " << (result.success ? "SUCCESS" : "FAILED") << std::endl;
        if (result.success) {
            std::cout << "  Backend: " << result.backend_used << std::endl;
            std::cout << "  Time: " << result.load_time_ms << "ms" << std::endl;
            std::cout << "  VRAM: " << result.vram_used_mb << " MB" << std::endl;
            std::cout << "  RAM: " << result.ram_used_mb << " MB" << std::endl;
        } else {
            std::cout << "  Error: " << result.error << std::endl;
        }
    });
    
    loader.setOnUnloadComplete([]() {
        std::cout << "[Callback] Model unloaded" << std::endl;
    });
    
    // Determine model path
    std::string model_path;
    if (argc > 1) {
        model_path = argv[1];
    } else {
        // Try environment variable
        const char* env_path = std::getenv("RAWRXD_TINY_MODEL_PATH");
        if (env_path) {
            model_path = env_path;
        } else {
            model_path = "F:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";
        }
    }
    
    std::cout << "Target model: " << model_path << std::endl;
    
    // Probe model
    std::cout << "\n--- Probing Model ---" << std::endl;
    auto cap = loader.probeModel(model_path);
    std::cout << "Name: " << cap.name << std::endl;
    std::cout << "Size: " << (cap.size_bytes / (1024.0 * 1024.0)) << " MB" << std::endl;
    std::cout << "Context Length: " << cap.context_length << std::endl;
    std::cout << "Supports GPU: " << (cap.supports_gpu ? "Yes" : "No") << std::endl;
    std::cout << "Supports Medusa: " << (cap.supports_medusa ? "Yes" : "No") << std::endl;
    std::cout << "Est. VRAM: " << cap.estimated_vram_mb << " MB" << std::endl;
    std::cout << "Est. RAM: " << cap.estimated_ram_mb << " MB" << std::endl;
    
    // Check if it fits
    std::cout << "\n--- Memory Check ---" << std::endl;
    std::cout << "Available VRAM: " << loader.getAvailableVRAMMB() << " MB" << std::endl;
    std::cout << "Available RAM: " << loader.getAvailableRAMMB() << " MB" << std::endl;
    std::cout << "Can fit: " << (loader.canFitModel(cap) ? "Yes" : "No") << std::endl;
    
    // Load model
    std::cout << "\n--- Loading Model ---" << std::endl;
    auto result = loader.loadModel(model_path, LoadBackend::Auto);
    
    if (result.success) {
        std::cout << "\nModel loaded successfully!" << std::endl;
        std::cout << "Current model: " << loader.currentModelPath() << std::endl;
        std::cout << "Is loaded: " << (loader.isModelLoaded() ? "Yes" : "No") << std::endl;
        
        // Test speculative decoding
        std::cout << "\n--- Speculative Decoding ---" << std::endl;
        if (loader.enableSpeculativeDecoding(4)) {
            std::cout << "Speculative decoding enabled (4 draft tokens)" << std::endl;
            std::cout << "Is speculative: " << (loader.isSpeculativeEnabled() ? "Yes" : "No") << std::endl;
        }
        
        // Unload
        std::cout << "\n--- Unloading ---" << std::endl;
        loader.unloadModel();
        std::cout << "Is loaded after unload: " << (loader.isModelLoaded() ? "Yes" : "No") << std::endl;
        
        // Test auto-load tiny
        std::cout << "\n--- Auto-load Tiny ---" << std::endl;
        loader.setTinyModelPath(model_path);
        auto tiny_result = loader.loadTinyModel();
        if (tiny_result.success) {
            std::cout << "Tiny model auto-loaded!" << std::endl;
            loader.unloadModel();
        } else {
            std::cout << "Auto-load failed: " << tiny_result.error << std::endl;
        }
        
    } else {
        std::cout << "\nLoad failed: " << result.error << std::endl;
        return 1;
    }
    
    std::cout << "\n=== Test Complete ===" << std::endl;
    return 0;
}
