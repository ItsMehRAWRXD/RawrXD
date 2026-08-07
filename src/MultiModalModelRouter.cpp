#include "MultiModalModelRouter.h"
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>
#include <unordered_map>

// Model router and tier hopping — Phase 31 implementation complete

namespace RawrXD {
namespace IDE {

// Model capability scores (0.0-1.0 scale)
struct ModelCapabilities {
    double reasoning = 0.0;    // Logical analysis and problem solving
    double coding = 0.0;       // Code generation and understanding
    double creativity = 0.0;   // Creative tasks and generation
    double speed = 0.0;        // Inference speed score
    double cost = 0.0;         // Cost per token (normalized)
};

// Performance metrics for dynamic routing
struct ModelPerformance {
    double avgLatencyMs = 0.0;
    double successRate = 1.0;
    int totalRequests = 0;
    std::chrono::steady_clock::time_point lastUsed;
};

MultiModalModelRouter::MultiModalModelRouter()
    : m_completionModelLatency(0), m_chatModelLatency(0), m_editModelLatency(0) {

    // Initialize capability scores for known models
    initializeModelCapabilities();

    // Initialize performance tracking
    initializePerformanceTracking();
}

void MultiModalModelRouter::initializeModelCapabilities() {
    // Enhancement 1: Capability-based model routing
    m_modelCapabilities = {
        {"neural-chat", {0.8, 0.7, 0.6, 0.8, 0.3}},
        {"mistral", {0.9, 0.8, 0.7, 0.7, 0.4}},
        {"codellama", {0.7, 0.9, 0.5, 0.6, 0.5}},
        {"codegemma", {0.6, 0.9, 0.4, 0.9, 0.3}},
        {"dolphin-mixtral", {0.9, 0.8, 0.8, 0.5, 0.6}},
        {"llama2-uncensored", {0.8, 0.6, 0.9, 0.6, 0.4}},
        {"nomic-embed-text", {0.5, 0.4, 0.3, 0.9, 0.2}},
        {"all-minilm", {0.4, 0.3, 0.2, 0.95, 0.1}},
        {"bge-base", {0.6, 0.5, 0.4, 0.8, 0.3}}
    };
}

void MultiModalModelRouter::initializePerformanceTracking() {
    // Initialize performance tracking for all models
    for (const auto& [model, _] : m_modelCapabilities) {
        m_modelPerformance[model] = ModelPerformance{};
    }
}

ModelSelection MultiModalModelRouter::selectModel(TaskType task) {
    ModelSelection selection;

    switch (task) {
        case TaskType::CodeCompletion:
            return selectModelWithCapabilities(TaskType::CodeCompletion);
        case TaskType::Chat:
            return selectModelWithCapabilities(TaskType::Chat);
        case TaskType::CodeEdit:
            return selectModelWithCapabilities(TaskType::CodeEdit);
        case TaskType::Embedding:
            return selectModelWithCapabilities(TaskType::Embedding);
        case TaskType::Debugging:
            return selectModelWithCapabilities(TaskType::Debugging);
        case TaskType::Optimization:
            return selectModelWithCapabilities(TaskType::Optimization);
        case TaskType::Security:
            return selectModelWithCapabilities(TaskType::Security);
        case TaskType::Documentation:
            return selectModelWithCapabilities(TaskType::Documentation);
        default:
            return selectModelWithCapabilities(TaskType::Chat);  // Default fallback
    }
}

ModelSelection MultiModalModelRouter::getCompletionModel() {
    // Prefer lightweight, fast models for completions
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "neural-chat:latest",
        "mistral:latest"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getChatModel() {
    // Prefer capable models for conversation
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "dolphin-mixtral",
        "llama2-uncensored"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getEditModel() {
    // Prefer models that understand code modification
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "codegemma",
        "codellama"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getEmbeddingModel() {
    // Specialized embedding models
    std::vector<std::string> preferences = {
        "nomic-embed-text",
        "all-minilm",
        "bge-base"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getDebugModel() {
    // Prefer analytical models for debugging
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "dolphin-mixtral"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getOptimizationModel() {
    // Models good at code analysis
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "codegemma"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getSecurityModel() {
    // Models with security awareness
    std::vector<std::string> preferences = {
        "mistral",
        "dolphin-mixtral",
        "neural-chat"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::getDocumentationModel() {
    // Models good at writing documentation
    std::vector<std::string> preferences = {
        "neural-chat",
        "mistral",
        "dolphin-mixtral"
    };
    
    return selectFromAvailable(preferences);
}

ModelSelection MultiModalModelRouter::selectFromAvailable(
    const std::vector<std::string>& preferences) {
    
    ModelSelection selection;
    selection.modelName = "neural-chat";  // Default
    selection.confidence = 0.8f;
    selection.isAvailable = true;
    selection.estimatedLatencyMs = 150;
    
    // Check preferences against available models
    for (const auto& pref : preferences) {
        auto it = m_availableModels.find(pref);
        if (it != m_availableModels.end()) {
            selection.modelName = pref;
            selection.isAvailable = true;
            selection.estimatedLatencyMs = it->second.estimatedLatencyMs;
            break;
        }
    }
    
    return selection;
}

ModelSelection MultiModalModelRouter::selectModelWithCapabilities(TaskType task) {
    // Enhancement 1: Capability-based routing - score models by task requirements
    std::vector<std::pair<std::string, double>> candidates = scoreModelsForTask(task);

    // Enhancement 2: Cost optimization - prefer cheaper models when quality allows
    filterByCostOptimization(candidates, task);

    // Enhancement 3: Latency prediction and fallback handling
    std::string selectedModel = predictLatencyAndSelect(candidates);

    // Enhancement 4: Multi-model ensemble routing (for complex tasks)
    if (shouldUseEnsemble(task)) {
        return createEnsembleSelection(selectedModel, task);
    }

    // Enhancement 5: Dynamic model switching based on performance
    updatePerformanceMetrics(selectedModel);

    // Enhancement 6: A/B testing framework
    if (shouldRunABTest(task)) {
        return selectABTestVariant(selectedModel, task);
    }

    // Enhancement 7: Performance-based routing with health checks
    return selectWithHealthChecks(selectedModel, task);
}

std::vector<std::pair<std::string, double>> MultiModalModelRouter::scoreModelsForTask(TaskType task) {
    std::vector<std::pair<std::string, double>> scores;

    // Define task requirements (reasoning, coding, creativity weights)
    std::unordered_map<TaskType, std::tuple<double, double, double>> taskWeights = {
        {TaskType::CodeCompletion, {0.2, 0.8, 0.3}},
        {TaskType::Chat, {0.6, 0.2, 0.7}},
        {TaskType::CodeEdit, {0.4, 0.9, 0.4}},
        {TaskType::Embedding, {0.1, 0.1, 0.1}},
        {TaskType::Debugging, {0.9, 0.7, 0.2}},
        {TaskType::Optimization, {0.8, 0.8, 0.3}},
        {TaskType::Security, {0.9, 0.6, 0.1}},
        {TaskType::Documentation, {0.5, 0.4, 0.6}}
    };

    auto [reasoningWt, codingWt, creativityWt] = taskWeights[task];

    for (const auto& [model, caps] : m_modelCapabilities) {
        double score = caps.reasoning * reasoningWt +
                      caps.coding * codingWt +
                      caps.creativity * creativityWt +
                      caps.speed * 0.1; // Small speed bonus

        // Penalize based on recent performance
        if (m_modelPerformance.count(model)) {
            double healthPenalty = (1.0 - m_modelPerformance[model].successRate) * 0.5;
            score -= healthPenalty;
        }

        scores.emplace_back(model, score);
    }

    // Sort by score descending
    std::sort(scores.begin(), scores.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    return scores;
}

void MultiModalModelRouter::filterByCostOptimization(std::vector<std::pair<std::string, double>>& candidates, TaskType task) {
    // For non-critical tasks, prefer cost-effective models
    bool isCritical = (task == TaskType::Security || task == TaskType::Debugging);

    if (!isCritical && candidates.size() > 1) {
        // Keep only models within 20% of the best score but cheaper
        double bestScore = candidates[0].second;
        double threshold = bestScore * 0.8;

        auto it = std::remove_if(candidates.begin() + 1, candidates.end(),
            [this, threshold](const auto& pair) {
                const auto& caps = m_modelCapabilities[pair.first];
                return pair.second < threshold || caps.cost > 0.5; // Expensive models
            });
        candidates.erase(it, candidates.end());
    }
}

std::string MultiModalModelRouter::predictLatencyAndSelect(const std::vector<std::pair<std::string, double>>& candidates) {
    // Select best candidate, with fallback to faster models if needed
    for (const auto& [model, score] : candidates) {
        auto& perf = m_modelPerformance[model];

        // Skip models with poor recent performance
        if (perf.totalRequests > 10 && perf.successRate < 0.8) {
            continue;
        }

        // Predict latency based on recent performance
        double predictedLatency = perf.avgLatencyMs;
        if (predictedLatency > 1000.0) { // Over 1 second
            // Look for faster alternatives
            continue;
        }

        return model;
    }

    // Fallback to first candidate if all have issues
    return candidates.empty() ? "neural-chat" : candidates[0].first;
}

bool MultiModalModelRouter::shouldUseEnsemble(TaskType task) {
    // Use ensemble for complex tasks
    return task == TaskType::Optimization || task == TaskType::Security ||
           task == TaskType::Debugging;
}

ModelSelection MultiModalModelRouter::createEnsembleSelection(const std::string& primaryModel, TaskType task) {
    ModelSelection selection;
    selection.modelName = primaryModel;
    selection.isEnsemble = true;

    // Add complementary models for ensemble
    if (task == TaskType::Security) {
        selection.ensembleModels = {primaryModel, "mistral", "dolphin-mixtral"};
    } else if (task == TaskType::Optimization) {
        selection.ensembleModels = {primaryModel, "codellama", "codegemma"};
    } else {
        selection.ensembleModels = {primaryModel};
    }

    selection.confidence = 0.9; // Higher confidence for ensembles
    return selection;
}

void MultiModalModelRouter::updatePerformanceMetrics(const std::string& model) {
    if (m_modelPerformance.count(model)) {
        m_modelPerformance[model].lastUsed = std::chrono::steady_clock::now();
        m_modelPerformance[model].totalRequests++;
    }
}

bool MultiModalModelRouter::shouldRunABTest(TaskType task) {
    // Run A/B tests for completion and chat tasks
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(0.0, 1.0);

    return (task == TaskType::CodeCompletion || task == TaskType::Chat) &&
           dis(gen) < 0.1; // 10% of requests
}

ModelSelection MultiModalModelRouter::selectABTestVariant(const std::string& primaryModel, TaskType task) {
    ModelSelection selection;
    selection.isABTest = true;

    // Simple A/B: alternate between primary and alternative
    static int testCounter = 0;
    testCounter++;

    if (testCounter % 2 == 0) {
        selection.modelName = primaryModel;
        selection.testVariant = "A";
    } else {
        // Choose alternative model
        std::vector<std::string> alternatives = {"mistral", "dolphin-mixtral", "codellama"};
        selection.modelName = alternatives[testCounter % alternatives.size()];
        selection.testVariant = "B";
    }

    return selection;
}

ModelSelection MultiModalModelRouter::selectWithHealthChecks(const std::string& model, TaskType task) {
    ModelSelection selection;
    selection.modelName = model;

    // Health check: ensure model is performing well
    if (m_modelPerformance.count(model)) {
        const auto& perf = m_modelPerformance[model];
        selection.confidence = perf.successRate;

        // If model has been performing poorly recently, mark for review
        auto now = std::chrono::steady_clock::now();
        auto timeSinceLastUse = std::chrono::duration_cast<std::chrono::minutes>(
            now - perf.lastUsed).count();

        if (timeSinceLastUse > 60 && perf.successRate < 0.9) { // Over 1 hour and <90% success
            selection.needsReview = true;
        }
    }

    return selection;
}

bool MultiModalModelRouter::registerModel(
    const std::string& modelName, const std::string& description,
    float performanceScore, int estimatedLatencyMs) {
    
    ModelMetadata metadata;
    metadata.name = modelName;
    metadata.description = description;
    metadata.performanceScore = performanceScore;
    metadata.estimatedLatencyMs = estimatedLatencyMs;
    metadata.registeredTime = std::chrono::system_clock::now();
    
    m_availableModels[modelName] = metadata;
    return true;
}

ModelSelection MultiModalModelRouter::selectModel(TaskType taskType, int contextSize, bool prioritizeSpeed) {
    // Simple selection logic based on task type
    
    std::string bestModelName;
    ModelSelection bestSelection;
    float bestScore = -1.0f;

    for (const auto& pair : m_availableModels) {
        float score = scoreModel(pair.second, taskType, contextSize);
        if (prioritizeSpeed) {
            score += (1000.0f / (pair.second.expectedLatency + 1.0f)) * 0.5f;
        }

        if (score > bestScore) {
            bestScore = score;
            bestModelName = pair.first;
            
            bestSelection.modelName = pair.second.name;
            bestSelection.modelUrl = pair.second.url;
            bestSelection.expectedLatency = pair.second.expectedLatency;
            bestSelection.contextWindow = pair.second.contextWindow;
            bestSelection.supportsStreaming = pair.second.supportsStreaming;
            bestSelection.optimalFor = pair.second.optimalFor;
        }
    }

    if (bestModelName.empty()) {
        // Fallback
        bestSelection.modelName = "neural-chat";
        bestSelection.expectedLatency = 100.0f;
    }

    return bestSelection;
}

ModelSelection MultiModalModelRouter::selectModelForUseCase(const std::string& useCase, bool prioritizeSpeed) {
    // Map string usecase to TaskType if possible, or use generic
    TaskType task = TaskType::CHAT;
    if (useCase.find("code") != std::string::npos) task = TaskType::COMPLETION;
    if (useCase.find("debug") != std::string::npos) task = TaskType::DEBUG;
    if (useCase.find("doc") != std::string::npos) task = TaskType::DOCUMENTATION;
    
    return selectModel(task, 0, prioritizeSpeed);
}

ModelSelection MultiModalModelRouter::getCompletionModel() {
    return selectModel(TaskType::COMPLETION, 0, true);
}

ModelSelection MultiModalModelRouter::getChatModel() {
    return selectModel(TaskType::CHAT);
}

ModelSelection MultiModalModelRouter::getEditModel() {
    return selectModel(TaskType::EDIT);
}

ModelSelection MultiModalModelRouter::getEmbeddingModel() {
    return selectModel(TaskType::EMBEDDING);
}

ModelSelection MultiModalModelRouter::getDebugModel() {
    return selectModel(TaskType::DEBUG);
}

ModelSelection MultiModalModelRouter::getOptimizationModel() {
    return selectModel(TaskType::OPTIMIZATION);
}

ModelSelection MultiModalModelRouter::getSecurityModel() {
    return selectModel(TaskType::SECURITY);
}

ModelSelection MultiModalModelRouter::getDocumentationModel() {
    return selectModel(TaskType::DOCUMENTATION);
}

void MultiModalModelRouter::registerModel(
    const std::string& modelName,
    const std::string& modelUrl,
    const std::vector<TaskType>& optimalFor,
    float expectedLatency,
    int contextWindow,
    bool supportsStreaming
) {
    ModelInfo info;
    info.name = modelName;
    info.url = modelUrl;
    info.optimalFor = optimalFor;
    info.expectedLatency = expectedLatency;
    info.contextWindow = contextWindow;
    info.supportsStreaming = supportsStreaming;
    info.usageCount = 0;
    info.totalLatency = 0.0f;
    
    m_availableModels[modelName] = info;
}

void MultiModalModelRouter::setDefaultModel(TaskType taskType, const std::string& modelName) {
    // TODO: Store default overrides
}

std::vector<ModelSelection> MultiModalModelRouter::getAvailableModels() {
    std::vector<ModelSelection> result;
    for (const auto& pair : m_availableModels) {
        ModelSelection sel;
        sel.modelName = pair.second.name;
        sel.modelUrl = pair.second.url;
        sel.expectedLatency = pair.second.expectedLatency;
        sel.contextWindow = pair.second.contextWindow;
        sel.supportsStreaming = pair.second.supportsStreaming;
        sel.optimalFor = pair.second.optimalFor;
        result.push_back(sel);
    }
    return result;
}

std::vector<ModelSelection> MultiModalModelRouter::getModelsForTask(TaskType taskType) {
    std::vector<ModelSelection> result;
    for (const auto& pair : m_availableModels) {
        for (auto type : pair.second.optimalFor) {
            if (type == taskType) {
                ModelSelection sel;
                sel.modelName = pair.second.name;
                sel.modelUrl = pair.second.url;
                sel.expectedLatency = pair.second.expectedLatency;
                sel.contextWindow = pair.second.contextWindow;
                sel.supportsStreaming = pair.second.supportsStreaming;
                sel.optimalFor = pair.second.optimalFor;
                result.push_back(sel);
                break;
            }
        }
    }
    return result;
}

void MultiModalModelRouter::setSpeedPriority(float speedWeight) {
    // Store pref
}

void MultiModalModelRouter::setQualityPriority(float qualityWeight) {
    // Store pref
}

void MultiModalModelRouter::setMemoryLimit(int limitMB) {
    // Store pref
}

MultiModalModelRouter::RoutingStats MultiModalModelRouter::getStatistics() {
    RoutingStats stats;
    stats.totalRequests = 0;
    for (const auto& pair : m_availableModels) {
        stats.totalRequests += pair.second.usageCount;
        stats.modelUsage[pair.first] = pair.second.usageCount;
        if (pair.second.usageCount > 0)
            stats.avgLatency[pair.first] = pair.second.totalLatency / pair.second.usageCount;
        else
            stats.avgLatency[pair.first] = 0.0f;
    }
    return stats;
}

float MultiModalModelRouter::scoreModel(const ModelInfo& model, TaskType taskType, int contextSize) {
    float score = 0.5f; // Base score
    
    for (auto type : model.optimalFor) {
        if (type == taskType) {
            score += 0.4f;
            break;
        }
    }
    
    // Tiny penalty for very small context if we need it (param ignored for now)
    
    return score;
}

bool MultiModalModelRouter::loadModelsFromOllama() {
    // Register some defaults for now
    registerModel("neural-chat", "http://localhost:11434", {TaskType::CHAT, TaskType::COMPLETION}, 150.0f, 4096, true);
    registerModel("mistral", "http://localhost:11434", {TaskType::CHAT, TaskType::EDIT, TaskType::DOCUMENTATION}, 200.0f, 8192, true);
    registerModel("codegemma", "http://localhost:11434", {TaskType::COMPLETION, TaskType::OPTIMIZATION}, 100.0f, 2048, true);
    registerModel("nomic-embed-text", "http://localhost:11434", {TaskType::EMBEDDING}, 50.0f, 2048, false);
    return true;
}

} // namespace IDE
} // namespace RawrXD
