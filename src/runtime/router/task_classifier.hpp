#pragma once

#include <string>
#include <vector>
#include "../model_registry/model_manifest.hpp"

namespace rawrxd {
namespace runtime {

struct TaskRequest {
    std::string task;
    uint64_t context_size;
    bool requires_reasoning;
    bool requires_code;
    
    // Constructor
    TaskRequest() : 
        task(""), 
        context_size(0), 
        requires_reasoning(false), 
        requires_code(false) {}
    
    // Constructor with parameters
    TaskRequest(
        const std::string& task,
        uint64_t context_size,
        bool requires_reasoning,
        bool requires_code
    ) : task(task),
        context_size(context_size),
        requires_reasoning(requires_reasoning),
        requires_code(requires_code) {}
};

struct RoutingDecision {
    ModelManifest model;
    // In a real implementation, BackendType would be an enum
    std::string backend;  // e.g., "vulkan", "hip", "cpu"
    uint64_t context;
    
    // Constructor
    RoutingDecision() : 
        context(0) {}
    
    // Constructor with parameters
    RoutingDecision(
        const ModelManifest& model,
        const std::string& backend,
        uint64_t context
    ) : model(model),
        backend(backend),
        context(context) {}
};

class TaskClassifier {
public:
    TaskClassifier();
    ~TaskClassifier();
    
    // Classify a task and return routing decision
    RoutingDecision classifyTask(
        const TaskRequest& request,
        const std::vector<ModelManifest>& availableModels
    );
    
private:
    // Helper methods for classification
    bool isCodeTask(const std::string& task);
    bool isReasoningTask(const std::string& task);
    uint64_t estimateRequiredContext(const TaskRequest& request);
    std::string selectBestBackend(const ModelManifest& model);
};

} // namespace runtime
} // namespace rawrxd