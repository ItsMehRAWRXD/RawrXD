#include "task_classifier.hpp"
#include <algorithm>
#include <cctype>
#include <string>

namespace rawrxd {
namespace runtime {

TaskClassifier::TaskClassifier() {}

TaskClassifier::~TaskClassifier() {}

bool TaskClassifier::isCodeTask(const std::string& task) {
    // Convert to lowercase for case-insensitive comparison
    std::string lowerTask = task;
    std::transform(lowerTask.begin(), lowerTask.end(), lowerTask.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    
    // Check for code-related keywords
    const std::vector<std::string> codeKeywords = {
        "code", "program", "function", "class", "method", "variable", 
        "algorithm", "implement", "code", "script", "compile", "debug",
        "variable", "function", "class", "method", "variable", "array",
        "loop", "condition", "variable", "function", "return", "variable"
    };
    
    for (const auto& keyword : codeKeywords) {
        if (lowerTask.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool TaskClassifier::isReasoningTask(const std::string& task) {
    // Convert to lowercase for case-insensitive comparison
    std::string lowerTask = task;
    std::transform(lowerTask.begin(), lowerTask.end(), lowerTask.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    
    // Check for reasoning-related keywords
    const std::vector<std::string> reasoningKeywords = {
        "explain", "why", "how", "what", "analyze", "reason", "logic",
        "think", "consider", "evaluate", "compare", "contrast", "explain",
        "reason", "logic", "think", "consider", "evaluate", "compare"
    };
    
    for (const auto& keyword : reasoningKeywords) {
        if (lowerTask.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

uint64_t TaskClassifier::estimateRequiredContext(const TaskRequest& request) {
    // Base context on the requested context size, with minimums based on task type
    uint64_t baseContext = request.context_size;
    
    // Ensure minimum context based on task type
    if (isCodeTask(request.task)) {
        // Code tasks typically need more context
        return std::max(baseContext, static_cast<uint64_t>(4096));
    } else if (isReasoningTask(request.task)) {
        #ifdef _WIN32
        // Reasoning tasks benefit from more context
        return std::max(baseContext, static_cast<uint64_t>(2048));
        #else
        // Reasoning tasks benefit from more context
        return std::max(baseContext, static_cast<uint64_t>(2048));
        #endif
    } else {
        // Default minimum context
        return std::max(baseContext, static_cast<uint64_t>(1024));
    }
}

std::string TaskClassifier::selectBestBackend(const ModelManifest& model) {
    // Prefer Vulkan if available, then HIP, then CPU
    if (model.supports_vulkan) {
        return "vulkan";
    } else if (model.supports_hip) {
        return "hip";
    } else {
        return "cpu";
    }
}

RoutingDecision TaskClassifier::classifyTask(
    const TaskRequest& request,
    const std::vector<ModelManifest>& availableModels
) {
    // Default to first available model if none specified
    ModelManifest selectedModel;
    bool modelFound = false;
    
    // If we have a specific model in mind from the request (not implemented in this simple version)
    // For now, we'll select the best model based on task type
    
    // Filter models based on requirements
    std::vector<ModelManifest> suitableModels;
    
    for (const auto& model : availableModels) {
        bool suitable = true;
        
        // Check if model has sufficient context
        if (model.context_length < request.context_size) {
            suitable = false;
        }
        
        // For code tasks, prefer models with coding capabilities
        if (isCodeTask(request.task)) {
            // In a real implementation, we would check model capabilities/tags
            // For now, we'll assume all models can handle code
        }
        
        // For reasoning tasks, prefer models with reasoning capabilities
        if (isReasoningTask(request.task)) {
            // In a real implementation, we would check model capabilities/tags
            // For now, we'll assume all models can handle reasoning
        }
        
        if (suitable) {
            suitableModels.push_back(model);
        }
    }
    
    // If no suitable models found, use the first available model
    if (suitableModels.empty() && !availableModels.empty()) {
        suitableModels = availableModels;
    }
    
    // Select the best model from suitable models
    if (!suitableModels.empty()) {
        // Simple selection: choose the model with the highest parameter count
        // (assuming more capable models have more parameters)
        auto bestModelIt = std::max_element(suitableModels.begin(), suitableModels.end(),
            [](const ModelManifest& a, const ModelManifest& b) {
                return a.parameter_count < b.parameter_count;
            });
        
        selectedModel = *bestModelIt;
        modelFound = true;
    }
    
    // If we still don't have a model, create a default one (should not happen in practice)
    if (!modelFound) {
        selectedModel = ModelManifest(
            "default", 
            "", 
            "unknown", 
            "unknown", 
            0, 
            2048,  // default context
            0, 
            0, 
            false, 
            false, 
            false
        );
    }
    
    // Determine backend
    std::string backend = selectBestBackend(selectedModel);
    
    // Determine context allocation (use model's context length or requested size, whichever is smaller)
    uint64_t contextToAllocate = std::min(selectedModel.context_length, request.context_size);
    if (contextToAllocate == 0) {
        contextToAllocate = estimateRequiredContext(request);
    }
    
    return RoutingDecision(selectedModel, backend, contextToAllocate);
}

} // namespace runtime
} // namespace rawrxd
