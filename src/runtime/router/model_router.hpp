#pragma once

#include <string>
#include <vector>
#include <memory>
#include "task_classifier.hpp"
#include "../model_registry/model_registry.hpp"

namespace rawrxd {
namespace runtime {

class ModelRouter {
public:
    ModelRouter(std::shared_ptr<ModelRegistry> registry);
    ~ModelRouter();
    
    // Route a task to the appropriate model and backend
    RoutingDecision routeTask(const TaskRequest& request);
    
    // Get the model registry
    std::shared_ptr<ModelRegistry> getRegistry() const;
    
    // Set the model registry
    void setRegistry(std::shared_ptr<ModelRegistry> registry);
    
private:
    std::shared_ptr<ModelRegistry> registry_;
    TaskClassifier classifier_;
};

} // namespace runtime
} // namespace rawrxd