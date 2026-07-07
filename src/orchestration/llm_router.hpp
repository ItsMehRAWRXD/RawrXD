#pragma once

#include <string>
#include <vector>
#include <memory>

struct ModelCapabilities {
    int reasoning = 0;
    int coding = 0;
    int planning = 0;
    int creativity = 0;
    int speed = 0;
    int costEfficiency = 0;
    
    int getCapabilityScore(const std::string& capability) const {
        if (capability == "reasoning") return reasoning;
        if (capability == "coding") return coding;
        if (capability == "planning") return planning;
        if (capability == "creativity") return creativity;
        if (capability == "speed") return speed;
        if (capability == "cost") return costEfficiency;
        return (reasoning + coding + planning + creativity + speed + costEfficiency) / 6;
    }
};

struct ModelInfo {
    std::string id;
    std::string provider;
    std::string endpoint;
    std::string apiKey;
    int contextWindow = 8192;
    double avgTokenCost = 0.0;
    double avgLatencyMs = 0.0;
    ModelCapabilities capabilities;
    bool available = true;
    int priority = 50;
    int successCount = 0;
    int failureCount = 0;
};

class LLMRouter {

public:
    explicit LLMRouter(void* parent = nullptr);
    ~LLMRouter();
    
    void registerModel(const ModelInfo& model);
    void unregisterModel(const std::string& modelId);
    std::vector<std::string> getAvailableModels() const;
    std::string selectBestModel(const std::string& task, const std::string& language);
    bool routeRequest(const std::string& modelId, const std::string& request);
    void recordSuccess(const std::string& modelId);
    void recordFailure(const std::string& modelId);

private:
    void* m_parent;
    std::vector<ModelInfo> m_models;
};

#endif
