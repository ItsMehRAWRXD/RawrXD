//==============================================================================
// UnifiedRunCommand.cpp
// Universal model runner for ALL formats: GGUF, Ollama blobs, HuggingFace, etc.
// Phase 15B: Deep2 + Codex + Moonshot Integration
//
// Usage: rawrxd run <model> "<prompt>"
//   rawrxd run phi3-mini "please audit my IDE on D:\"
//   rawrxd run qwen2.5-coder-7b "optimize this function"
//   rawrxd run F:\OllamaModels\models\qwen2.5-coder-7b "hello"
//   rawrxd run https://huggingface.co/Qwen/Qwen2.5-Coder-7B "code review"
//==============================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>

// Deep2 Engine
#include "../deep2/Deep2Engine.h"
#include "../deep2/Deep2InferenceGateway.h"

// Codex CLI (Ollama/cloud)
#include "../codex/CodexCLI.hpp"

// ASM Bridge
extern "C" {
    ULONG64 __cdecl RawrXD_Host_Engine_Pipeline_Core(
        ULONG64 targetTierIndex,
        LPVOID  payloadStateContext
    );
}

namespace RawrXD {
namespace CLI {

//==============================================================================
// Model Format Detection
//==============================================================================
enum class ModelFormat {
    Unknown,
    GGUF,           // *.gguf files
    OllamaBlob,     // F:\OllamaModels\blobs\sha256-*
    OllamaModel,    // F:\OllamaModels\models\*
    HuggingFace,    // https://huggingface.co/...
    LocalFolder,    // D:\models\some-model
    Deep2Engine,    // Already loaded in Deep2
};

struct ModelInfo {
    std::string path;
    std::string name;
    ModelFormat format;
    size_t parameterCount;
    std::string quantization;
    bool isLocal;
};

//==============================================================================
// Model Registry - Auto-discovers all available models
//==============================================================================
class ModelRegistry {
public:
    static ModelRegistry& Instance() {
        static ModelRegistry instance;
        return instance;
    }
    
    // Scan all known model locations
    void ScanAllLocations() {
        models_.clear();
        
        // 1. Scan F:\OllamaModels\models
        ScanOllamaModels("F:\\OllamaModels\\models");
        
        // 2. Scan F:\OllamaModels\blobs
        ScanOllamaBlobs("F:\\OllamaModels\\blobs");
        
        // 3. Scan D:\models (if exists)
        if (std::filesystem::exists("D:\\models")) {
            ScanLocalFolder("D:\\models");
        }
        
        // 4. Scan current directory for .gguf files
        ScanLocalFolder(".");
        
        // 5. Check Deep2 engine loaded models
        ScanDeep2Engine();
        
        printf("[ModelRegistry] Discovered %zu models\n", models_.size());
    }
    
    // Find model by name (partial match)
    ModelInfo* FindModel(const std::string& query) {
        // Exact match first
        for (auto& [name, info] : models_) {
            if (_stricmp(name.c_str(), query.c_str()) == 0) {
                return &info;
            }
        }
        
        // Partial match
        for (auto& [name, info] : models_) {
            if (name.find(query) != std::string::npos || 
                query.find(name) != std::string::npos) {
                return &info;
            }
        }
        
        // Check if it's a direct path
        if (std::filesystem::exists(query)) {
            ModelInfo info;
            info.path = query;
            info.name = std::filesystem::path(query).stem().string();
            info.isLocal = true;
            
            if (query.ends_with(".gguf")) {
                info.format = ModelFormat::GGUF;
            } else {
                info.format = ModelFormat::LocalFolder;
            }
            
            models_[info.name] = info;
            return &models_[info.name];
        }
        
        return nullptr;
    }
    
    // List all models
    void ListModels() {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  AVAILABLE MODELS                                              ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        for (const auto& [name, info] : models_) {
            const char* fmt = FormatToString(info.format);
            printf("  %-30s [%s] %s\n", name.c_str(), fmt, 
                   info.isLocal ? info.path.c_str() : "(remote)");
        }
        
        if (models_.empty()) {
            printf("  No models found. Place .gguf files in current directory\n");
            printf("  or set OLLAMA_MODELS environment variable.\n");
        }
        printf("\n");
    }
    
private:
    std::map<std::string, ModelInfo> models_;
    
    void ScanOllamaModels(const std::string& basePath) {
        if (!std::filesystem::exists(basePath)) return;
        
        for (const auto& entry : std::filesystem::directory_iterator(basePath)) {
            if (entry.is_directory()) {
                std::string name = entry.path().filename().string();
                ModelInfo info;
                info.name = name;
                info.path = entry.path().string();
                info.format = ModelFormat::OllamaModel;
                info.isLocal = true;
                models_[name] = info;
            }
        }
    }
    
    void ScanOllamaBlobs(const std::string& basePath) {
        if (!std::filesystem::exists(basePath)) return;
        
        int blobCount = 0;
        for (const auto& entry : std::filesystem::directory_iterator(basePath)) {
            if (entry.is_regular_file()) {
                blobCount++;
            }
        }
        
        // Blobs are raw data, need manifest to identify
        // For now, just count them
        if (blobCount > 0) {
            ModelInfo info;
            info.name = "ollama-blobs-" + std::to_string(blobCount);
            info.path = basePath;
            info.format = ModelFormat::OllamaBlob;
            info.isLocal = true;
            models_[info.name] = info;
        }
    }
    
    void ScanLocalFolder(const std::string& path) {
        if (!std::filesystem::exists(path)) return;
        
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            if (entry.is_regular_file() && entry.path().extension() == ".gguf") {
                std::string name = entry.path().stem().string();
                ModelInfo info;
                info.name = name;
                info.path = entry.path().string();
                info.format = ModelFormat::GGUF;
                info.isLocal = true;
                models_[name] = info;
            }
        }
    }
    
    void ScanDeep2Engine() {
        if (Deep2::Deep2InferenceGateway::Instance().IsInitialized() &&
            Deep2::Deep2InferenceGateway::Instance().IsModelLoaded()) {
            ModelInfo info;
            info.name = Deep2::Deep2InferenceGateway::Instance().GetModelName();
            info.path = "(Deep2 Engine)";
            info.format = ModelFormat::Deep2Engine;
            info.isLocal = true;
            models_[info.name] = info;
        }
    }
    
    static const char* FormatToString(ModelFormat fmt) {
        switch (fmt) {
            case ModelFormat::GGUF: return "GGUF";
            case ModelFormat::OllamaBlob: return "Ollama Blob";
            case ModelFormat::OllamaModel: return "Ollama";
            case ModelFormat::HuggingFace: return "HuggingFace";
            case ModelFormat::LocalFolder: return "Local";
            case ModelFormat::Deep2Engine: return "Deep2";
            default: return "Unknown";
        }
    }
};

//==============================================================================
// Unified Run Command
//==============================================================================
class UnifiedRunCommand {
public:
    // Main entry point: rawrxd run <model> "<prompt>"
    static int Execute(int argc, char* argv[]) {
        if (argc < 3) {
            PrintUsage();
            return 1;
        }
        
        std::string modelQuery = argv[1];
        std::string prompt;
        
        // Combine remaining args into prompt
        for (int i = 2; i < argc; i++) {
            if (i > 2) prompt += " ";
            prompt += argv[i];
        }
        
        // Strip quotes if present
        if (prompt.front() == '"' && prompt.back() == '"') {
            prompt = prompt.substr(1, prompt.length() - 2);
        }
        
        printf("[Run] Model: %s\n", modelQuery.c_str());
        printf("[Run] Prompt: %s\n", prompt.c_str());
        
        // Initialize model registry
        ModelRegistry::Instance().ScanAllLocations();
        
        // Find the model
        ModelInfo* model = ModelRegistry::Instance().FindModel(modelQuery);
        if (!model) {
            printf("[ERROR] Model not found: %s\n", modelQuery.c_str());
            printf("[INFO] Available models:\n");
            ModelRegistry::Instance().ListModels();
            return 1;
        }
        
        printf("[Run] Found model: %s (%s)\n", model->name.c_str(), 
               model->path.c_str());
        
        // Route to appropriate backend
        switch (model->format) {
            case ModelFormat::GGUF:
                return RunGGUF(*model, prompt);
                
            case ModelFormat::OllamaModel:
            case ModelFormat::OllamaBlob:
                return RunOllama(*model, prompt);
                
            case ModelFormat::Deep2Engine:
                return RunDeep2(*model, prompt);
                
            case ModelFormat::HuggingFace:
                return RunHuggingFace(*model, prompt);
                
            default:
                printf("[ERROR] Unsupported model format\n");
                return 1;
        }
    }
    
private:
    static void PrintUsage() {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  rawrxd run - Universal Model Runner                         ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        printf("Usage: rawrxd run <model> \"<prompt>\"\n\n");
        printf("Examples:\n");
        printf("  rawrxd run phi3-mini           \"please audit my IDE on D:\\"\n");
        printf("  rawrxd run qwen2.5-coder-7b    \"optimize this function\"\n");
        printf("  rawrxd run model.gguf          \"explain this code\"\n");
        printf("  rawrxd run F:\\models\\qwen    \"hello world\"\n");
        printf("  rawrxd run --list              # List all available models\n");
        printf("\n");
        printf("Supported formats:\n");
        printf("  - GGUF files (*.gguf)\n");
        printf("  - Ollama models (F:\\OllamaModels\\models\\*)\n");
        printf("  - Ollama blobs (F:\\OllamaModels\\blobs\\*)\n");
        printf("  - Deep2 engine (already loaded)\n");
        printf("  - HuggingFace URLs\n");
        printf("\n");
    }
    
    // Run GGUF via Deep2 engine
    static int RunGGUF(const ModelInfo& model, const std::string& prompt) {
        printf("[Run] Loading GGUF model: %s\n", model.path.c_str());
        
        Deep2::Deep2Engine engine;
        if (!engine.LoadModel(model.path)) {
            printf("[ERROR] Failed to load GGUF model\n");
            return 1;
        }
        
        printf("[Run] Model loaded: %s (%zu params)\n", 
               engine.GetModelName().c_str(),
               engine.GetParameterCount());
        
        Deep2::SamplingConfig config;
        config.maxTokens = 2048;
        config.temperature = 0.7f;
        
        printf("[Run] Generating...\n\n");
        auto result = engine.Generate(prompt, config);
        
        if (result.success) {
            printf("%s\n", result.tokens.data()->text.c_str());
            printf("\n[Stats] Tokens: %llu, TPS: %.2f, TTFT: %.2fms\n",
                   result.totalTokens,
                   result.tokensPerSecond,
                   result.timeToFirstToken);
            return 0;
        } else {
            printf("[ERROR] Generation failed: %s\n", result.error.c_str());
            return 1;
        }
    }
    
    // Run via Ollama API
    static int RunOllama(const ModelInfo& model, const std::string& prompt) {
        printf("[Run] Using Ollama backend: %s\n", model.name.c_str());
        
        RawrXD::Codex::CodexCLI codex;
        RawrXD::Codex::CodexCLI::Config config;
        config.provider = RawrXD::Codex::Provider::Ollama;
        config.model = model.name;
        config.baseUrl = "http://localhost:11434";
        
        if (!codex.Initialize(config)) {
            printf("[ERROR] Failed to initialize Ollama client\n");
            printf("[INFO] Make sure Ollama is running: ollama serve\n");
            return 1;
        }
        
        printf("[Run] Generating...\n\n");
        std::string response = codex.Complete(prompt);
        
        if (!response.empty()) {
            printf("%s\n", response.c_str());
            return 0;
        } else {
            printf("[ERROR] Ollama generation failed\n");
            return 1;
        }
    }
    
    // Run via Deep2 engine (already loaded)
    static int RunDeep2(const ModelInfo& model, const std::string& prompt) {
        printf("[Run] Using Deep2 engine: %s\n", model.name.c_str());
        
        Deep2::AIRequest request;
        request.operation = Deep2::AIRequest::OpComplete;
        request.prefix = prompt;
        request.maxTokens = 2048;
        request.temperature = 0.7f;
        
        auto response = Deep2::Deep2InferenceGateway::Instance().ProcessRequest(request);
        
        if (response.success) {
            printf("%s\n", response.text.c_str());
            printf("\n[Stats] Tokens: %d, TPS: %.2f, Latency: %.2fms\n",
                   response.tokensGenerated,
                   response.tokensPerSecond,
                   response.latencyMs);
            return 0;
        } else {
            printf("[ERROR] Deep2 generation failed: %s\n", response.error.c_str());
            return 1;
        }
    }
    
    // Run via HuggingFace (download + run)
    static int RunHuggingFace(const ModelInfo& model, const std::string& prompt) {
        printf("[Run] HuggingFace models not yet implemented\n");
        printf("[INFO] Please download the model first using:\n");
        printf("  rawrxd pull %s\n", model.path.c_str());
        return 1;
    }
};

} // namespace CLI
} // namespace RawrXD

//==============================================================================
// C API for integration with SovereignCLI_Unified.cpp
//==============================================================================
extern "C" {

__declspec(dllexport) int RawrXD_UnifiedRun(int argc, char* argv[]) {
    return RawrXD::CLI::UnifiedRunCommand::Execute(argc, argv);
}

__declspec(dllexport) void RawrXD_ListModels() {
    RawrXD::CLI::ModelRegistry::Instance().ScanAllLocations();
    RawrXD::CLI::ModelRegistry::Instance().ListModels();
}

} // extern "C"
