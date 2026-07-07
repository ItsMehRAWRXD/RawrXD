#include "llm_router.hpp"
#include <iostream>
#include <algorithm>

LLMRouter::LLMRouter(void* parent)
    : m_parent(parent)
{
}

LLMRouter::~LLMRouter() = default;

void LLMRouter::registerModel(const ModelInfo& model) {
    m_models.push_back(model);
}

void LLMRouter::unregisterModel(const std::string& modelId) {
    m_models.erase(
        std::remove_if(m_models.begin(), m_models.end(),
            [&modelId](const ModelInfo& m) { return m.id == modelId; }),
        m_models.end()
    );
}

std::vector<std::string> LLMRouter::getAvailableModels() const {
    std::vector<std::string> result;
    for (const auto& model : m_models) {
        if (model.available) {
            result.push_back(model.id);
        }
    }
    return result;
}

std::string LLMRouter::selectBestModel(const std::string& task, const std::string& language) {
    (void)task;
    (void)language;
    for (const auto& model : m_models) {
        if (model.available) {
            return model.id;
        }
    }
    return "";
}

bool LLMRouter::routeRequest(const std::string& modelId, const std::string& request) {
    (void)modelId;
    (void)request;
    return true;
}

void LLMRouter::recordSuccess(const std::string& modelId) {
    for (auto& model : m_models) {
        if (model.id == modelId) {
            model.successCount++;
            break;
        }
    }
}

void LLMRouter::recordFailure(const std::string& modelId) {
    for (auto& model : m_models) {
        if (model.id == modelId) {
            model.failureCount++;
            break;
        }
    }
}
