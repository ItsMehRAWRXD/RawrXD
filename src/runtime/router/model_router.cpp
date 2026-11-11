#include "model_router.hpp"
#include <stdexcept>

namespace rawrxd {
namespace runtime {

ModelRouter::ModelRouter(std::shared_ptr<ModelRegistry> registry) : registry_(registry) {}

ModelRouter::~ModelRouter() {}

RoutingDecision ModelRouter::routeTask(const TaskRequest& request) {
    if (!registry_) {
        throw std::runtime_error("Model registry not set in ModelRouter");
    }
    
    // Get the list of available models
    std::vector<ModelManifest> availableModels = registry_->list();
    
    if (availableModels.empty()) {
        throw std::runtime_error("No models available in the registry");
    }
    
    // Classify the task and get a routing decision
    return classifier_.classifyTask(request, availableModels);
}

std::shared_ptr<ModelRegistry> ModelRouter::getRegistry() const {
    return registry_;
}

void ModelRouter::setRegistry(std::shared_ptr<ModelRegistry> registry) {
    registry_ = registry;
}

} // namespace runtime
} // namespace rawrxd
