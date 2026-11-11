// Model Adapter - Implementation
// Makes models interchangeable backends

#include "model_adapter.hpp"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <json/json.hpp>

namespace RawrXD {
namespace Intent {

// ============================================================================
// BackendConfig Implementation
// ============================================================================

BackendConfig& BackendConfig::Instance() {
    static BackendConfig instance;
    return instance;
}

void BackendConfig::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    nlohmann::json j;
    file >> j;
    
    if (j.contains("name")) name = j["name"].get<std::string>();
    if (j.contains("type")) type = j["type"].get<std::string>();
    if (j.contains("endpoint")) endpoint = j["endpoint"].get<std::string>();
    if (j.contains("api_key")) api_key = j["api_key"].get<std::string>();
    if (j.contains("model_name")) model_name = j["model_name"].get<std::string>();
    if (j.contains("timeout_ms")) timeout_ms = j["timeout_ms"].get<uint32_t>();
    if (j.contains("max_retries")) max_retries = j["max_retries"].get<uint32_t>();
    if (j.contains("enabled")) enabled = j["enabled"].get<bool>();
    if (j.contains("priority")) priority = j["priority"].get<uint32_t>();
}

void BackendConfig::SaveToFile(const std::string& path) const {
    nlohmann::json j;
    j["name"] = name;
    j["type"] = type;
    j["endpoint"] = endpoint;
    j["api_key"] = api_key;
    j["model_name"] = model_name;
    j["timeout_ms"] = timeout_ms;
    j["max_retries"] = max_retries;
    j["enabled"] = enabled;
    j["priority"] = priority;
    
    std::ofstream file(path);
    file << j.dump(2);
}

// ============================================================================
// ModelAdapter Implementation
// ============================================================================

ModelAdapter& ModelAdapter::Instance() {
    static ModelAdapter instance;
    return instance;
}

void ModelAdapter::RegisterBackend(std::shared_ptr<IReasoningBackend> backend) {
    if (!backend) return;
    
    std::lock_guard<std::mutex> lock(backends_mutex_);
    
    // Remove existing backend with same name
    backends_.erase(
        std::remove_if(backends_.begin(), backends_.end(),
            [&backend](const auto& b) { return b->GetName() == backend->GetName(); }),
        backends_.end()
    );
    
    backends_.push_back(backend);
    
    // Sort by priority (higher first)
    std::sort(backends_.begin(), backends_.end(),
        [](const auto& a, const auto& b) {
            // Get priority from config (simplified - would use actual config)
            return a->GetName() > b->GetName();  // Placeholder
        }
    );
}

void ModelAdapter::UnregisterBackend(const std::string& name) {
    std::lock_guard<std::mutex> lock(backends_mutex_);
    
    backends_.erase(
        std::remove_if(backends_.begin(), backends_.end(),
            [&name](const auto& b) { return b->GetName() == name; }),
        backends_.end()
    );
}

std::shared_ptr<IReasoningBackend> ModelAdapter::SelectBackend(ModelCapability required) {
    std::lock_guard<std::mutex> lock(backends_mutex_);
    
    for (const auto& backend : backends_) {
        if (backend->IsEnabled() && backend->IsHealthy() && backend->Supports(required)) {
            return backend;
        }
    }
    
    return nullptr;
}

std::shared_ptr<IReasoningBackend> ModelAdapter::SelectBackend(
    ModelCapability required,
    const std::string& preferred
) {
    std::lock_guard<std::mutex> lock(backends_mutex_);
    
    // First try preferred
    for (const auto& backend : backends_) {
        if (backend->GetName() == preferred && 
            backend->IsEnabled() && 
            backend->IsHealthy() && 
            backend->Supports(required)) {
            return backend;
        }
    }
    
    // Fall back to any available
    return SelectBackend(required);
}

ModelResponse ModelAdapter::Complete(const ModelContext& ctx) {
    if (!enabled_.load()) {
        ModelResponse response;
        response.success = false;
        response.warnings.push_back("Model adapter is disabled");
        return response;
    }
    
    auto backend = SelectBackend(ModelCapability::COMPLETION);
    if (!backend) {
        ModelResponse response;
        response.success = false;
        response.warnings.push_back("No suitable backend available");
        return response;
    }
    
    return backend->Complete(ctx);
}

ModelResponse ModelAdapter::Complete(const ModelContext& ctx, const std::string& preferred_backend) {
    if (!enabled_.load()) {
        ModelResponse response;
        response.success = false;
        response.warnings.push_back("Model adapter is disabled");
        return response;
    }
    
    auto backend = SelectBackend(ModelCapability::COMPLETION, preferred_backend);
    if (!backend) {
        // Try any backend
        backend = SelectBackend(ModelCapability::COMPLETION);
    }
    
    if (!backend) {
        ModelResponse response;
        response.success = false;
        response.warnings.push_back("No suitable backend available");
        return response;
    }
    
    return backend->Complete(ctx);
}

IntentResponse ModelAdapter::ConvertToIntent(const ModelResponse& response) {
    IntentResponse intent;
    
    if (!response.success) {
        intent.status = IntentStatus::REJECTED;
        intent.rejection_reason = "Model response failed: " + 
            (response.warnings.empty() ? "unknown error" : response.warnings[0]);
        return intent;
    }
    
    // Parse response content for intent
    // This would use JSON parsing in production
    if (response.intent.has_value()) {
        intent.request = response.intent.value();
        intent.status = IntentStatus::PENDING_VALIDATION;
    } else {
        // Try to extract intent from content
        intent.status = IntentStatus::REJECTED;
        intent.rejection_reason = "No intent found in model response";
    }
    
    return intent;
}

std::vector<std::shared_ptr<IReasoningBackend>> ModelAdapter::GetAllBackends() const {
    std::lock_guard<std::mutex> lock(backends_mutex_);
    return backends_;
}

std::vector<std::string> ModelAdapter::GetBackendNames() const {
    std::lock_guard<std::mutex> lock(backends_mutex_);
    
    std::vector<std::string> names;
    for (const auto& backend : backends_) {
        names.push_back(backend->GetName());
    }
    return names;
}

// ============================================================================
// KimiBackend Implementation
// ============================================================================

KimiBackend::KimiBackend(const BackendConfig& config) : config_(config) {
    enabled_ = config.enabled;
}

ModelResponse KimiBackend::Complete(const ModelContext& ctx) {
    ModelResponse response;
    
    if (!enabled_.load()) {
        response.success = false;
        response.warnings.push_back("Kimi backend is disabled");
        return response;
    }
    
    // Build request payload
    nlohmann::json payload;
    payload["model"] = config_.model_name.empty() ? "kimi-latest" : config_.model_name;
    payload["max_tokens"] = ctx.max_tokens;
    payload["temperature"] = ctx.temperature;
    
    // Build messages
    nlohmann::json messages = nlohmann::json::array();
    
    if (!ctx.system_prompt.empty()) {
        messages.push_back({
            {"role", "system"},
            {"content", ctx.system_prompt}
        });
    }
    
    for (const auto& [role, content] : ctx.messages) {
        messages.push_back({
            {"role", role},
            {"content", content}
        });
    }
    
    payload["messages"] = messages;
    
    // In production, this would make HTTP request to Kimi API
    // For now, return a stub response
    response.success = true;
    response.content = "{\"intent_type\": \"MODIFY_FUNCTION\", \"target\": \"example\", \"confidence\": 0.95}";
    response.confidence = 0.95f;
    response.tokens_used = 150;
    response.latency_ms = 500;
    
    // Parse intent from content
    try {
        auto json = nlohmann::json::parse(response.content);
        IntentRequest intent;
        intent.type = IntentType::MODIFY_FUNCTION;
        intent.target.file_path = json.value("target", "unknown");
        intent.confidence = json.value("confidence", 0.5f);
        response.intent = intent;
    } catch (...) {
        // Failed to parse
    }
    
    return response;
}

void KimiBackend::CompleteStreaming(
    const ModelContext& ctx,
    std::function<void(const std::string& chunk)> on_chunk
) {
    if (!enabled_.load() || !on_chunk) return;
    
    // In production, this would stream from Kimi API
    // For now, simulate streaming
    on_chunk("{\"intent_type\": \"");
    on_chunk("MODIFY_FUNCTION");
    on_chunk("\"}");
}

bool KimiBackend::Supports(ModelCapability cap) const {
    // Kimi supports most capabilities
    return (cap == ModelCapability::COMPLETION ||
            cap == ModelCapability::CHAT ||
            cap == ModelCapability::STREAMING ||
            cap == ModelCapability::FUNCTION_CALLING ||
            cap == ModelCapability::REASONING ||
            cap == ModelCapability::CODE_GENERATION ||
            cap == ModelCapability::CODE_ANALYSIS ||
            cap == ModelCapability::LONG_CONTEXT ||
            cap == ModelCapability::TOOL_USE);
}

bool KimiBackend::IsHealthy() const {
    // In production, would check API connectivity
    return enabled_.load();
}

// ============================================================================
// MoonshotBackend Implementation
// ============================================================================

MoonshotBackend::MoonshotBackend(const BackendConfig& config) : config_(config) {
    enabled_ = config.enabled;
}

ModelResponse MoonshotBackend::Complete(const ModelContext& ctx) {
    ModelResponse response;
    
    if (!enabled_.load()) {
        response.success = false;
        response.warnings.push_back("Moonshot backend is disabled");
        return response;
    }
    
    // Similar to Kimi but with Moonshot-specific formatting
    nlohmann::json payload;
    payload["model"] = config_.model_name.empty() ? "moonshot-v1" : config_.model_name;
    payload["max_tokens"] = ctx.max_tokens;
    payload["temperature"] = ctx.temperature;
    
    nlohmann::json messages = nlohmann::json::array();
    
    if (!ctx.system_prompt.empty()) {
        messages.push_back({
            {"role", "system"},
            {"content", ctx.system_prompt}
        });
    }
    
    for (const auto& [role, content] : ctx.messages) {
        messages.push_back({
            {"role", role},
            {"content", content}
        });
    }
    
    payload["messages"] = messages;
    
    // Stub response
    response.success = true;
    response.content = "{\"intent_type\": \"BUILD_PROJECT\", \"target\": \"all\", \"confidence\": 0.92}";
    response.confidence = 0.92f;
    response.tokens_used = 120;
    response.latency_ms = 400;
    
    try {
        auto json = nlohmann::json::parse(response.content);
        IntentRequest intent;
        intent.type = IntentType::BUILD;
        intent.target.file_path = json.value("target", "unknown");
        intent.confidence = json.value("confidence", 0.5f);
        response.intent = intent;
    } catch (...) {
        // Failed to parse
    }
    
    return response;
}

void MoonshotBackend::CompleteStreaming(
    const ModelContext& ctx,
    std::function<void(const std::string& chunk)> on_chunk
) {
    if (!enabled_.load() || !on_chunk) return;
    
    on_chunk("{\"intent_type\": \"");
    on_chunk("BUILD_PROJECT");
    on_chunk("\"}");
}

bool MoonshotBackend::Supports(ModelCapability cap) const {
    // Moonshot supports most capabilities except very long context
    return (cap == ModelCapability::COMPLETION ||
            cap == ModelCapability::CHAT ||
            cap == ModelCapability::STREAMING ||
            cap == ModelCapability::FUNCTION_CALLING ||
            cap == ModelCapability::REASONING ||
            cap == ModelCapability::CODE_GENERATION ||
            cap == ModelCapability::CODE_ANALYSIS ||
            cap == ModelCapability::TOOL_USE);
    // Note: Does not support LONG_CONTEXT like Kimi
}

bool MoonshotBackend::IsHealthy() const {
    return enabled_.load();
}

// ============================================================================
// GGUFBackend Implementation
// ============================================================================

GGUFBackend::GGUFBackend(const BackendConfig& config) : config_(config) {
    enabled_ = config.enabled;
    // In production, would load GGUF model here
    // model_handle_ = llama_load_model(config.model_name.c_str(), ...);
}

GGUFBackend::~GGUFBackend() {
    // In production, would unload model
    // if (model_handle_) llama_free_model(model_handle_);
}

ModelResponse GGUFBackend::Complete(const ModelContext& ctx) {
    ModelResponse response;
    
    if (!enabled_.load()) {
        response.success = false;
        response.warnings.push_back("GGUF backend is disabled");
        return response;
    }
    
    if (!model_handle_) {
        response.success = false;
        response.warnings.push_back("GGUF model not loaded");
        return response;
    }
    
    // In production, would use llama.cpp for inference
    // For now, return stub
    response.success = true;
    response.content = "{\"intent_type\": \"VERIFY\", \"target\": \"tests\", \"confidence\": 0.88}";
    response.confidence = 0.88f;
    response.tokens_used = 200;
    response.latency_ms = 1000;  // Local inference is slower
    
    try {
        auto json = nlohmann::json::parse(response.content);
        IntentRequest intent;
        intent.type = IntentType::VERIFY;
        intent.target.file_path = json.value("target", "unknown");
        intent.confidence = json.value("confidence", 0.5f);
        response.intent = intent;
    } catch (...) {
        // Failed to parse
    }
    
    return response;
}

void GGUFBackend::CompleteStreaming(
    const ModelContext& ctx,
    std::function<void(const std::string& chunk)> on_chunk
) {
    if (!enabled_.load() || !on_chunk) return;
    
    // In production, would stream tokens from llama.cpp
    on_chunk("Local");
    on_chunk(" inference");
    on_chunk(" result");
}

bool GGUFBackend::Supports(ModelCapability cap) const {
    // GGUF supports basic completion and chat
    // Streaming depends on implementation
    return (cap == ModelCapability::COMPLETION ||
            cap == ModelCapability::CHAT ||
            cap == ModelCapability::CODE_GENERATION ||
            cap == ModelCapability::CODE_ANALYSIS);
}

bool GGUFBackend::IsHealthy() const {
    return enabled_.load() && model_handle_ != nullptr;
}

} // namespace Intent
} // namespace RawrXD
