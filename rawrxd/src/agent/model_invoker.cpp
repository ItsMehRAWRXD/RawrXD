#include "model_invoker.hpp"

static std::string s_backend;
static std::string s_endpoint;
static std::string s_systemPrompt;
static bool s_caching = false;
static bool s_invoking = false;

ModelInvoker::ModelInvoker() = default;

void ModelInvoker::setLLMBackend(const std::string& backend, const std::string& endpoint) {
    s_backend = backend;
    s_endpoint = endpoint;
}

std::string ModelInvoker::getLLMBackend() const {
    return s_backend;
}

void ModelInvoker::setSystemPromptTemplate(const std::string& prompt) {
    s_systemPrompt = prompt;
}

void ModelInvoker::setCachingEnabled(bool enabled) {
    s_caching = enabled;
}

bool ModelInvoker::isInvoking() const {
    return s_invoking;
}

void ModelInvoker::cancelPendingRequest() {
    s_invoking = false;
}

void ModelInvoker::invokeAsync(const std::string& params) {
    s_invoking = true;
}
