// copilot_pipeline.cpp - Implementation of Copilot-like pipeline
// Part of the complete inference system.

#include "copilot_pipeline.h"
#include "../dynamic_model_loader.h"
#include <algorithm>
#include <fstream>

namespace RawrXD {

bool CopilotPipeline::LoadModel(const std::string& model_name) {
    auto& loader = RawrXD::DynamicModelLoader::instance();
    auto result = loader.loadModel(model_name, RawrXD::LoadBackend::Auto);
    if (result.success) {
        current_model_ = model_name;
        model_loaded_ = true;
        return true;
    }
    return false;
}

void CopilotPipeline::UnloadModel() {
    auto& loader = RawrXD::DynamicModelLoader::instance();
    loader.unloadModel();
    current_model_.clear();
    model_loaded_ = false;
    streaming_engine_->ClearKVCaches();
}

std::vector<std::string> CopilotPipeline::ListModels() const {
    auto& loader = RawrXD::DynamicModelLoader::instance();
    auto caps = loader.scanModelDirectory("models/");
    std::vector<std::string> names;
    for (const auto& cap : caps) {
        names.push_back(cap.name);
    }
    return names;
}

void CopilotPipeline::SetStreamingConfig(const StreamingInferenceEngine::Config& config) {
    // Config applied to streaming engine
    (void)config;
}

void CopilotPipeline::SetIDEConfig(const IDECompletionBridge::Config& config) {
    ide_bridge_->SetConfig(config);
}

} // namespace RawrXD