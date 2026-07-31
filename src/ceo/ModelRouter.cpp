// ============================================================================
// ModelRouter.cpp — Intelligent Model Routing Implementation
// ============================================================================
#include "ModelRouter.hpp"
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace CEO {

// ============================================================================
// Constructor / Destructor
// ============================================================================
ModelRouter::ModelRouter() = default;
ModelRouter::~ModelRouter() = default;

// ============================================================================
// Initialization
// ============================================================================
bool ModelRouter::Initialize() {
    // Detect available VRAM (simplified - would query GPU in production)
    m_availableVRAM = 48 * 1024; // Assume 48GB for RX 7800 XT + R9700 AI PRO
    
    // Register default models
    RegisterModel({
        "deep2-22b-q4",
        "models/deep2-22b-q4.gguf",
        32768,
        4.0f,
        14000,
        true,
        true,
        50.0f,
        0.85f
    });
    
    RegisterModel({
        "deep2-22b-q8",
        "models/deep2-22b-q8.gguf",
        32768,
        8.0f,
        24000,
        true,
        true,
        80.0f,
        0.92f
    });
    
    RegisterModel({
        "code-small-3b-q4",
        "models/code-small-3b-q4.gguf",
        8192,
        4.0f,
        2000,
        true,
        true,
        20.0f,
        0.75f
    });
    
    RegisterModel({
        "embedding-small",
        "models/embedding-small.gguf",
        8192,
        4.0f,
        1000,
        false,
        false,
        10.0f,
        0.90f
    });
    
    return true;
}

void ModelRouter::Shutdown() {
    m_models.clear();
}

// ============================================================================
// Model Management
// ============================================================================
bool ModelRouter::RegisterModel(const ModelConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_models[config.name] = config;
    return true;
}

bool ModelRouter::UnregisterModel(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(name);
    if (it == m_models.end()) {
        return false;
    }
    m_models.erase(it);
    return true;
}

std::vector<ModelConfig> ModelRouter::GetAvailableModels() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ModelConfig> result;
    for (const auto& [name, config] : m_models) {
        result.push_back(config);
    }
    return result;
}

ModelConfig ModelRouter::GetModel(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(name);
    if (it != m_models.end()) {
        return it->second;
    }
    return ModelConfig{};
}

// ============================================================================
// Routing
// ============================================================================
RoutingDecision ModelRouter::Route(TaskType taskType, 
                                   const std::string& query,
                                   int preferredContextLength) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    RoutingDecision decision;
    decision.taskType = taskType;
    decision.estimatedTokens = EstimateTokens(query);
    
    // Find best model
    std::string bestModel;
    float bestScore = -1.0f;
    
    for (const auto& [name, config] : m_models) {
        // Skip models that don't fit in VRAM
        if (!CanFitModel(config)) {
            continue;
        }
        
        // Skip models that don't support required features
        if (taskType == TaskType::Completion && !config.supportsFIM) {
            continue;
        }
        
        // Skip models with insufficient context
        if (decision.estimatedTokens > config.contextLength) {
            continue;
        }
        
        float score = CalculateScore(config, taskType, decision.estimatedTokens);
        if (score > bestScore) {
            bestScore = score;
            bestModel = name;
        }
    }
    
    if (bestModel.empty()) {
        // Fallback to first available model
        if (!m_models.empty()) {
            bestModel = m_models.begin()->first;
            decision.confidence = 0.5f;
            decision.reason = "Fallback model";
        } else {
            decision.confidence = 0.0f;
            decision.reason = "No models available";
            return decision;
        }
    } else {
        decision.confidence = bestScore;
        decision.reason = "Optimal for task type and constraints";
    }
    
    decision.modelName = bestModel;
    return decision;
}

RoutingDecision ModelRouter::RouteCompletion(const std::string& prefix,
                                             const std::string& suffix) {
    std::string query = prefix + " [FIM] " + suffix;
    return Route(TaskType::Completion, query, 2048);
}

RoutingDecision ModelRouter::RouteChat(const std::string& message) {
    return Route(TaskType::Chat, message, 8192);
}

RoutingDecision ModelRouter::RouteCodeGeneration(const std::string& description) {
    return Route(TaskType::CodeGeneration, description, 16384);
}

// ============================================================================
// Execution
// ============================================================================
bool ModelRouter::LoadModel(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_models.find(name);
    if (it == m_models.end()) {
        return false;
    }
    
    // In production, this would actually load the GGUF
    m_currentModel = name;
    return true;
}

void ModelRouter::UnloadModel(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_currentModel == name) {
        m_currentModel.clear();
    }
}

// ============================================================================
// VRAM Management
// ============================================================================
int ModelRouter::GetUsedVRAM() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_currentModel.empty()) {
        return 0;
    }
    
    auto it = m_models.find(m_currentModel);
    if (it != m_models.end()) {
        return it->second.vramMB;
    }
    return 0;
}

bool ModelRouter::CanFitModel(const ModelConfig& config) const {
    int used = GetUsedVRAM();
    return (used + config.vramMB) <= m_availableVRAM;
}

// ============================================================================
// Performance Tracking
// ============================================================================
void ModelRouter::RecordLatency(const std::string& modelName, float latencyMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_latencyHistory[modelName] = latencyMs;
}

void ModelRouter::RecordQuality(const std::string& modelName, float qualityScore) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_qualityHistory[modelName] = qualityScore;
}

json ModelRouter::GetPerformanceStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    json stats;
    stats["available_vram_mb"] = m_availableVRAM;
    stats["used_vram_mb"] = GetUsedVRAM();
    stats["current_model"] = m_currentModel;
    
    stats["models"] = json::array();
    for (const auto& [name, config] : m_models) {
        json model;
        model["name"] = name;
        model["vram_mb"] = config.vramMB;
        model["context_length"] = config.contextLength;
        model["supports_tools"] = config.supportsTools;
        model["supports_fim"] = config.supportsFIM;
        
        auto latIt = m_latencyHistory.find(name);
        if (latIt != m_latencyHistory.end()) {
            model["avg_latency_ms"] = latIt->second;
        }
        
        auto qualIt = m_qualityHistory.find(name);
        if (qualIt != m_qualityHistory.end()) {
            model["quality_score"] = qualIt->second;
        }
        
        stats["models"].push_back(model);
    }
    
    return stats;
}

// ============================================================================
// Internal Methods
// ============================================================================
TaskType ModelRouter::ClassifyTask(const std::string& query) {
    std::string lower = query;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Simple keyword-based classification
    if (lower.find("complete") != std::string::npos ||
        lower.find("finish") != std::string::npos) {
        return TaskType::Completion;
    }
    
    if (lower.find("debug") != std::string::npos ||
        lower.find("fix") != std::string::npos ||
        lower.find("error") != std::string::npos) {
        return TaskType::Debug;
    }
    
    if (lower.find("review") != std::string::npos ||
        lower.find("check") != std::string::npos) {
        return TaskType::CodeReview;
    }
    
    if (lower.find("design") != std::string::npos ||
        lower.find("architecture") != std::string::npos) {
        return TaskType::Architecture;
    }
    
    if (lower.find("write") != std::string::npos ||
        lower.find("implement") != std::string::npos ||
        lower.find("create") != std::string::npos) {
        return TaskType::CodeGeneration;
    }
    
    return TaskType::Chat;
}

int ModelRouter::EstimateTokens(const std::string& text) {
    // Rough estimate: ~4 characters per token
    return static_cast<int>(text.length() / 4);
}

float ModelRouter::CalculateScore(const ModelConfig& config,
                                  TaskType taskType,
                                  int requiredTokens) {
    float score = 0.0f;
    
    // Quality score (0-1)
    score += config.qualityScore * 0.4f;
    
    // Latency score (lower is better)
    float latencyScore = 1.0f - std::min(config.latencyMs / 200.0f, 1.0f);
    score += latencyScore * 0.2f;
    
    // Context fit score
    float contextRatio = static_cast<float>(requiredTokens) / config.contextLength;
    float contextScore = 1.0f - std::min(contextRatio, 1.0f);
    score += contextScore * 0.2f;
    
    // Task-specific bonuses
    switch (taskType) {
        case TaskType::Completion:
            if (config.supportsFIM) score += 0.1f;
            if (config.latencyMs < 30) score += 0.1f;
            break;
        case TaskType::CodeGeneration:
            if (config.qualityScore > 0.8f) score += 0.1f;
            break;
        case TaskType::Debug:
            if (config.supportsTools) score += 0.1f;
            break;
        default:
            break;
    }
    
    return score;
}

} // namespace CEO
} // namespace RawrXD
