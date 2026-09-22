#pragma once
#include <string>
#include <cstdint>
#include <atomic>
#include <vector>
#include <functional>

// Minimal ModelInvoker for auto_feature_registry.cpp
class ModelInvoker {
public:
    ModelInvoker();
    void setLLMBackend(const std::string& backend, const std::string& endpoint);
    std::string getLLMBackend() const;
    void setSystemPromptTemplate(const std::string& prompt);
    void setCachingEnabled(bool enabled);
    bool isInvoking() const;
    void cancelPendingRequest();
    void invokeAsync(const std::string& params);
};
