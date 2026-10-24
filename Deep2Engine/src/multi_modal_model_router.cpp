#include "multi_modal_model_router.h"

MultiModalModelRouterIntegration::MultiModalModelRouterIntegration(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics)
    : m_logger(logger), m_metrics(metrics) {
    m_logger->info("MultiModalModelRouter initialized");
    refreshModelInventory();
}

RoutingDecision MultiModalModelRouterIntegration::routeTask(
    TaskType task,
    const std::string& context,
    Complexity complexity) {

    try {
        m_logger->debug("Routing task of complexity: {}", static_cast<int>(complexity));

        // Select best model from available models - NO hardcoded defaults
        std::string bestModel;
        std::string reasoning;
        bool found = false;

        // Prefer models whose primaryTask matches the requested task
        for (const auto& model : m_availableModels) {
            if (model.primaryTask == task) {
                bestModel = model.name;
                reasoning = "Selected from available models matching task";
                found = true;
                break;
            }
        }

        // Fallback: any available model that supports the complexity
        if (!found) {
            for (const auto& model : m_availableModels) {
                if (static_cast<int>(model.maxComplexity) >= static_cast<int>(complexity)) {
                    bestModel = model.name;
                    reasoning = "Selected from available models supporting complexity";
                    found = true;
                    break;
                }
            }
        }

        // Final fallback: first available model
        if (!found && !m_availableModels.empty()) {
            bestModel = m_availableModels[0].name;
            reasoning = "First available model (no task-specific match)";
            found = true;
        }

        if (!found) {
            m_logger->warn("No models available for routing task");
            RoutingDecision empty;
            empty.selectedModel = "";
            empty.reasoning = "No models available";
            empty.requiresPreload = false;
            empty.estimatedLatencyMs = 0;
            empty.confidenceScore = 0.0f;
            return empty;
        }

        RoutingDecision decision;
        decision.selectedModel = bestModel;
        decision.reasoning = reasoning;
        decision.requiresPreload = false;
        decision.estimatedLatencyMs = 50;
        decision.confidenceScore = 0.95f;

        m_metrics->incrementCounter("routing_decisions");
        return decision;

    } catch (const std::exception& e) {
        m_logger->error("Error routing task: {}", e.what());
        
        RoutingDecision fallback;
        fallback.selectedModel = "";
        fallback.reasoning = "Routing error: " + std::string(e.what());
        fallback.confidenceScore = 0.0f;
        return fallback;
    }
}

std::vector<std::string> MultiModalModelRouterIntegration::getRecommendedModels(TaskType task) {
    std::vector<std::string> models;
    
    // Return available models that match the task, or all if none match
    for (const auto& model : m_availableModels) {
        if (model.primaryTask == task) {
            models.push_back(model.name);
        }
    }
    
    // If no task-specific models, return all available
    if (models.empty()) {
        for (const auto& model : m_availableModels) {
            models.push_back(model.name);
        }
    }
    
    return models;
}

bool MultiModalModelRouterIntegration::preloadModel(const std::string& modelName) {
    m_logger->info("Preloading model: {}", modelName);
    return true;
}

bool MultiModalModelRouterIntegration::switchModel(const std::string& modelName) {
    m_logger->info("Switching to model: {}", modelName);
    m_metrics->incrementCounter("model_switches");
    return true;
}

void MultiModalModelRouterIntegration::updateModelPerformance(
    const std::string& model,
    float performance) {

    m_modelPerformance[model] = performance;
}

void MultiModalModelRouterIntegration::analyzeUsagePatterns() {
    m_logger->info("Analyzing usage patterns");
}

RoutingDecision MultiModalModelRouterIntegration::routeWithFallback(
    TaskType task,
    const std::string& context,
    int maxLatencyMs) {

    auto decision = routeTask(task, context);
    
    if (decision.selectedModel.empty()) {
        return decision; // No models available
    }
    
    if (decision.estimatedLatencyMs > maxLatencyMs) {
        // Try to find a faster model from available models
        std::string fasterModel;
        int bestLatency = INT_MAX;
        
        for (const auto& model : m_availableModels) {
            if (model.inferenceSpeed > 0) {
                int estimatedLatency = static_cast<int>(1000.0f / model.inferenceSpeed);
                if (estimatedLatency < bestLatency && estimatedLatency <= maxLatencyMs) {
                    bestLatency = estimatedLatency;
                    fasterModel = model.name;
                }
            }
        }
        
        if (!fasterModel.empty() && fasterModel != decision.selectedModel) {
            decision.selectedModel = fasterModel;
            decision.reasoning += " (fallback for latency: " + fasterModel + ")";
            decision.estimatedLatencyMs = bestLatency;
        }
    }
    
    return decision;
}

void MultiModalModelRouterIntegration::refreshModelInventory() {
    m_logger->info("Refreshing model inventory");
    m_availableModels.clear();
    
    // NOTE: Models should be registered via registerModel() or loaded from Ollama.
    // Hardcoded model inventory removed - use dynamic discovery.
    // If you have an Ollama client, call loadModelsFromOllama() here.
}

std::vector<ModelProfile> MultiModalModelRouterIntegration::getAvailableModels() const {
    return m_availableModels;
}

bool MultiModalModelRouterIntegration::isModelAvailable(const std::string& modelName) const {
    for (const auto& model : m_availableModels) {
        if (model.name == modelName) {
            return true;
        }
    }
    return false;
}

void MultiModalModelRouterIntegration::buildTaskModelMap() {
    m_logger->debug("Building task-to-model mapping");
}

ModelProfile MultiModalModelRouterIntegration::createModelProfile(const std::string& modelName) {
    ModelProfile profile;
    profile.name = modelName;
    return profile;
}

float MultiModalModelRouterIntegration::calculateModelScore(
    const ModelProfile& model,
    TaskType task,
    Complexity complexity,
    const std::string& context) {

    float score = 0.5f;
    
    // Score based on task compatibility
    if (model.primaryTask == task) {
        score += 0.3f;
    }
    
    // Score based on complexity capability
    if (static_cast<int>(model.maxComplexity) >= static_cast<int>(complexity)) {
        score += 0.2f;
    }
    
    return score;
}
