// copilot_pipeline.cpp - Implementation of Copilot-like pipeline
// Part of the complete inference system.

#include "copilot_pipeline.h"
#include "../model/ModelLoader.hpp"
#include <algorithm>
#include <fstream>

namespace RawrXD {

bool CopilotPipeline::LoadModel(const std::string& model_name) {
    // Use standalone ModelLoader for GGUF files
    auto loader = std::make_unique<rawrxd::model::ModelLoader>();
    
    // Try common model paths
    std::vector<std::string> paths = {
        "models/" + model_name,
        "models/" + model_name + ".gguf",
        model_name,
        model_name + ".gguf"
    };
    
    // Check RAWRXD_MODEL_PATH environment variable
    const char* env_path = getenv("RAWRXD_MODEL_PATH");
    if (env_path) {
        paths.insert(paths.begin(), env_path);
    }
    
    for (const auto& path : paths) {
        if (loader->Load(path)) {
            current_model_ = model_name;
            model_loaded_ = true;
            model_loader_ = std::move(loader);
            return true;
        }
    }
    
    return false;
}

void CopilotPipeline::UnloadModel() {
    current_model_.clear();
    model_loaded_ = false;
    model_loader_.reset();
    if (streaming_engine_) {
        streaming_engine_->ClearKVCaches();
    }
}

std::vector<std::string> CopilotPipeline::ListModels() const {
    // Scan models directory for .gguf files
    std::vector<std::string> models;
    
    // Try to open models directory
    std::string models_dir = "models/";
    // Note: In production, use filesystem API to scan directory
    // For now, return common model names as hints
    
    models.push_back("llama-2-7b-chat.gguf");
    models.push_back("llama-2-13b-chat.gguf");
    models.push_back("mistral-7b-instruct.gguf");
    models.push_back("ministral-3b.gguf");
    
    return models;
}

void CopilotPipeline::SetStreamingConfig(const StreamingInferenceEngine::Config& config) {
    if (streaming_engine_) {
        streaming_engine_->SetConfig(config);
    }
}

void CopilotPipeline::SetIDEConfig(const IDECompletionBridge::Config& config) {
    ide_bridge_->SetConfig(config);
}

} // namespace RawrXD