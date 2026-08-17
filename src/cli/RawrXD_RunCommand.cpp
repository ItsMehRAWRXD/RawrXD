//==============================================================================
// RawrXD_RunCommand.cpp
// Unified `rawrxd run <model> "<prompt>"` command
// Supports ALL model formats: GGUF, Ollama blobs, HuggingFace, local paths
// Phase 15B: Deep2 Engine Integration + Codex/Reverse Engineering
//==============================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>

// Deep2 Engine
#include "../deep2/Deep2Engine.h"
#include "../deep2/Deep2InferenceGateway.h"

// Codex / Reverse Engineering
#include "../codex/CodexCLI.cpp"  // Header-less implementation
#include "../reverse_engineering/pe_analyzer.h"
#include "../reverse_engineering/disassembler.h"

// Model Loading
#include "../model_loader/ModelLoader.hpp"
#include "../model_loader/enhanced_model_loader.cpp"  // Header-less implementation

namespace fs = std::filesystem;

//==============================================================================
// Model Format Detection
//==============================================================================
enum class ModelFormat {
    UNKNOWN,
    GGUF,           // .gguf files
    OLLAMA_BLOB,    // Ollama sha256-* blobs
    OLLAMA_MANIFEST,// Ollama manifests
    HUGGINGFACE,    // HF repo ID (user/model)
    LOCAL_PATH,     // Direct file path
    PYTORCH,        // .pt, .pth, .bin
    SAFETENSORS,    // .safetensors
    ONNX,           // .onnx
    TENSORFLOW,     // .pb, .savedmodel
};

struct ModelInfo {
    std::string path;
    std::string name;
    ModelFormat format;
    size_t size;
    bool exists;
};

//==============================================================================
// Detect model format from path/name
//==============================================================================
static ModelFormat DetectFormat(const std::string& path) {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.ends_with(".gguf")) return ModelFormat::GGUF;
    if (lower.starts_with("sha256-") || lower.find("/blobs/sha256-") != std::string::npos)
        return ModelFormat::OLLAMA_BLOB;
    if (lower.find("/manifests/") != std::string::npos || lower.ends_with(".json"))
        return ModelFormat::OLLAMA_MANIFEST;
    if (lower.ends_with(".pt") || lower.ends_with(".pth") || lower.ends_with(".bin"))
        return ModelFormat::PYTORCH;
    if (lower.ends_with(".safetensors")) return ModelFormat::SAFETENSORS;
    if (lower.ends_with(".onnx")) return ModelFormat::ONNX;
    if (lower.find("/") != std::string::npos && lower.find(".") == std::string::npos)
        return ModelFormat::HUGGINGFACE;  // user/repo format
    if (fs::exists(path)) return ModelFormat::LOCAL_PATH;
    
    return ModelFormat::UNKNOWN;
}

//==============================================================================
// Resolve model path from various formats
//==============================================================================
static ModelInfo ResolveModel(const std::string& modelSpec) {
    ModelInfo info;
    info.name = modelSpec;
    info.format = DetectFormat(modelSpec);
    info.exists = false;
    
    // Check Ollama models directory
    std::string ollamaModels = "F:\\OllamaModels\\models";
    std::string ollamaBlobs = "F:\\OllamaModels\\blobs";
    
    switch (info.format) {
        case ModelFormat::GGUF:
            // Direct GGUF path
            if (fs::exists(modelSpec)) {
                info.path = modelSpec;
                info.exists = true;
            } else {
                // Try common locations
                std::vector<std::string> searchPaths = {
                    "F:\\OllamaModels\\models\\" + modelSpec,
                    "D:\\models\\" + modelSpec,
                    "C:\\models\\" + modelSpec,
                    modelSpec,
                };
                for (const auto& p : searchPaths) {
                    if (fs::exists(p)) {
                        info.path = p;
                        info.exists = true;
                        break;
                    }
                }
            }
            break;
            
        case ModelFormat::OLLAMA_BLOB:
            // Ollama blob reference
            info.path = ollamaBlobs + "\\" + modelSpec;
            info.exists = fs::exists(info.path);
            break;
            
        case ModelFormat::HUGGINGFACE:
            // HuggingFace repo - will need download
            info.path = "hf://" + modelSpec;
            info.exists = false;  // Requires download
            break;
            
        case ModelFormat::LOCAL_PATH:
            info.path = modelSpec;
            info.exists = fs::exists(modelSpec);
            if (info.exists) {
                info.size = fs::file_size(modelSpec);
            }
            break;
            
        default:
            // Try as Ollama model name
            std::string ollamaPath = ollamaModels + "\\" + modelSpec;
            if (fs::exists(ollamaPath)) {
                info.path = ollamaPath;
                info.format = ModelFormat::OLLAMA_MANIFEST;
                info.exists = true;
            } else {
                // Search for any matching file
                for (const auto& entry : fs::directory_iterator(ollamaModels)) {
                    if (entry.path().filename().string().find(modelSpec) != std::string::npos) {
                        info.path = entry.path().string();
                        info.exists = true;
                        break;
                    }
                }
            }
            break;
    }
    
    return info;
}

//==============================================================================
// Load model into Deep2 engine
//==============================================================================
static bool LoadModelIntoEngine(const ModelInfo& info) {
    std::cout << "[RunCommand] Loading model: " << info.name << std::endl;
    std::cout << "[RunCommand] Format: ";
    
    switch (info.format) {
        case ModelFormat::GGUF: std::cout << "GGUF"; break;
        case ModelFormat::OLLAMA_BLOB: std::cout << "Ollama Blob"; break;
        case ModelFormat::OLLAMA_MANIFEST: std::cout << "Ollama Manifest"; break;
        case ModelFormat::HUGGINGFACE: std::cout << "HuggingFace"; break;
        case ModelFormat::PYTORCH: std::cout << "PyTorch"; break;
        case ModelFormat::SAFETENSORS: std::cout << "Safetensors"; break;
        case ModelFormat::ONNX: std::cout << "ONNX"; break;
        case ModelFormat::LOCAL_PATH: std::cout << "Local"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;
    
    if (!info.exists) {
        std::cerr << "[RunCommand] ERROR: Model not found: " << info.path << std::endl;
        return false;
    }
    
    // Use Deep2 inference gateway
    auto& gateway = Deep2::Deep2InferenceGateway::Instance();
    
    if (!gateway.IsInitialized()) {
        std::cout << "[RunCommand] Initializing Deep2 inference gateway..." << std::endl;
        if (!gateway.Initialize()) {
            std::cerr << "[RunCommand] ERROR: Failed to initialize inference gateway" << std::endl;
            return false;
        }
    }
    
    // Load the model
    std::cout << "[RunCommand] Loading model file: " << info.path << std::endl;
    if (!gateway.LoadModel(info.path)) {
        std::cerr << "[RunCommand] ERROR: Failed to load model" << std::endl;
        return false;
    }
    
    std::cout << "[RunCommand] Model loaded successfully!" << std::endl;
    std::cout << "[RunCommand] Model: " << gateway.GetModelName() << std::endl;
    std::cout << "[RunCommand] Parameters: " << gateway.GetModelParameterCount() << std::endl;
    
    return true;
}

//==============================================================================
// Execute prompt with optional codex/reverse engineering context
//==============================================================================
static std::string ExecutePrompt(const std::string& prompt, bool useCodex = false) {
    auto& gateway = Deep2::Deep2InferenceGateway::Instance();
    
    Deep2::AIRequest request;
    request.operation = Deep2::AIRequest::OpComplete;
    request.prefix = prompt;
    request.maxTokens = 2048;
    request.temperature = 0.7f;
    request.topP = 0.9f;
    
    // If prompt mentions audit/analysis/reverse, enable codex context
    std::string lowerPrompt = prompt;
    std::transform(lowerPrompt.begin(), lowerPrompt.end(), lowerPrompt.begin(), ::tolower);
    
    if (lowerPrompt.find("audit") != std::string::npos ||
        lowerPrompt.find("analyze") != std::string::npos ||
        lowerPrompt.find("reverse") != std::string::npos ||
        lowerPrompt.find("disassembl") != std::string::npos ||
        lowerPrompt.find("decompil") != std::string::npos ||
        lowerPrompt.find("patch") != std::string::npos) {
        useCodex = true;
    }
    
    if (useCodex) {
        std::cout << "[RunCommand] Codex/RE context detected - enabling reverse engineering tools" << std::endl;
        // Add codex context to prompt
        request.prefix = "[CODEX MODE: Reverse Engineering & Binary Analysis Enabled]\n\n" + prompt;
    }
    
    std::cout << "[RunCommand] Generating response..." << std::endl;
    
    auto response = gateway.ProcessRequest(request);
    
    if (!response.success) {
        return "ERROR: " + response.error;
    }
    
    return response.text;
}

//==============================================================================
// Main `rawrxd run` entry point
//==============================================================================
extern "C" int RawrXD_RunCommand(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: rawrxd run <model> \"<prompt>\"" << std::endl;
        std::cerr << std::endl;
        std::cerr << "Model formats supported:" << std::endl;
        std::cerr << "  - GGUF files:           rawrxd run model.gguf \"hello\"" << std::endl;
        std::cerr << "  - Ollama models:        rawrxd run llama3.1 \"hello\"" << std::endl;
        std::cerr << "  - Ollama blobs:         rawrxd run sha256-abc123 \"hello\"" << std::endl;
        std::cerr << "  - HuggingFace repos:    rawrxd run user/model \"hello\"" << std::endl;
        std::cerr << "  - Local paths:          rawrxd run D:\\models\\model.gguf \"hello\"" << std::endl;
        std::cerr << std::endl;
        std::cerr << "Special prompts (auto-enable Codex/RE tools):" << std::endl;
        std::cerr << "  rawrxd run model \"audit my IDE on D:\\"" << std::endl;
        std::cerr << "  rawrxd run model \"disassemble binary.exe\"" << std::endl;
        std::cerr << "  rawrxd run model \"decompile this function\"" << std::endl;
        return 1;
    }
    
    std::string modelSpec = argv[1];
    std::string prompt = argv[2];
    
    // Handle quoted prompts with spaces
    if (argc > 3) {
        for (int i = 3; i < argc; i++) {
            prompt += " ";
            prompt += argv[i];
        }
    }
    
    std::cout << "========================================" << std::endl;
    std::cout << "  RAWRXD RUN COMMAND" << std::endl;
    std::cout << "  Model: " << modelSpec << std::endl;
    std::cout << "  Prompt: " << prompt << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Resolve model
    ModelInfo info = ResolveModel(modelSpec);
    
    if (!info.exists && info.format == ModelFormat::UNKNOWN) {
        std::cerr << "[RunCommand] ERROR: Cannot resolve model: " << modelSpec << std::endl;
        std::cerr << "[RunCommand] Searched: F:\\OllamaModels\\models\\" << std::endl;
        std::cerr << "[RunCommand] Searched: D:\\models\\" << std::endl;
        return 1;
    }
    
    // Load model
    if (!LoadModelIntoEngine(info)) {
        return 1;
    }
    
    // Execute prompt
    std::string response = ExecutePrompt(prompt);
    
    // Output result
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  RESPONSE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << response << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Performance metrics
    auto& gateway = Deep2::Deep2InferenceGateway::Instance();
    std::cout << "Tokens/sec: " << gateway.GetAverageTokensPerSecond() << std::endl;
    std::cout << "Peak TPS:   " << gateway.GetPeakTokensPerSecond() << std::endl;
    
    return 0;
}

//==============================================================================
// C API for CLI integration
//==============================================================================
extern "C" {

__declspec(dllexport) int rawrxd_run_model(const char* model, const char* prompt) {
    char* argv[] = { (char*)"rawrxd", (char*)model, (char*)prompt };
    return RawrXD_RunCommand(3, argv);
}

} // extern "C"
