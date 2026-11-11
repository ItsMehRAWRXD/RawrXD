#pragma once
#ifndef RAWRXD_INFERENCE_MIGRATION_H
#define RAWRXD_INFERENCE_MIGRATION_H

#include "inference_gateway.h"
#include "inference_enforcement.h"
#include <string>
#include <functional>

// ============================================================================
// MIGRATION WRAPPER
// 
// This file provides drop-in replacements for old bypass APIs
// that redirect to the new InferenceGateway with full observability.
// 
// Replace old calls:
//   Old: invokeOllamaGenerate(model, prompt, callback)
//   New: MIGRATED_OllamaGenerate(model, prompt, callback)
//
// Eventually these should all use RAWRXD_INFERENCE() macro directly.
// ============================================================================

namespace RawrXD {
namespace Migration {

// ============================================================================
// Ollama Migration
// ============================================================================
inline void MIGRATED_OllamaGenerate(
    const std::string& model,
    const std::string& prompt,
    std::function<void(const std::string& chunk, bool complete)> callback) {
    
    InferenceRequest req;
    req.model = model;
    req.prompt = prompt;
    req.stream = true;
    
    InferenceGateway::instance().executeStream(req, 
        [callback](const std::string& chunk, bool complete) {
            if (callback) callback(chunk, complete);
        });
}

// ============================================================================
// Cloud API Migration  
// ============================================================================
inline std::string MIGRATED_CloudGenerate(
    const std::string& prompt,
    const std::string& model = "gpt-4",
    float temperature = 0.7f) {
    
    InferenceRequest req;
    req.model = model;
    req.prompt = prompt;
    req.temperature = temperature;
    req.allowRemote = true; // Explicit opt-in required
    
    auto response = InferenceGateway::instance().execute(req);
    return response.success ? response.text : "Error: " + response.error;
}

// ============================================================================
// Completion Engine Migration
// ============================================================================
inline std::vector<std::string> MIGRATED_CodeComplete(
    const std::string& code_context,
    const std::string& model = "codellama",
    int maxLines = 5) {
    
    std::string prompt = "Complete this code with " + std::to_string(maxLines) +
                        " lines. Return ONLY code, no explanation.\n\n" + 
                        code_context;
    
    InferenceRequest req;
    req.model = model;
    req.prompt = prompt;
    req.temperature = 0.2f;
    req.maxTokens = maxLines * 40;
    
    auto response = InferenceGateway::instance().execute(req);
    
    std::vector<std::string> results;
    if (response.success) {
        // Split response into lines
        std::istringstream iss(response.text);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) results.push_back(line);
        }
    }
    return results;
}

// ============================================================================
// Agentic Engine Migration
// ============================================================================
inline std::string MIGRATED_AgenticResponse(
    const std::string& message,
    const std::string& model = "local-default") {
    
    InferenceRequest req;
    req.model = model;
    req.prompt = message;
    req.temperature = 0.8f;
    
    auto response = InferenceGateway::instance().execute(req);
    return response.success ? response.text : "Error: " + response.error;
}

// ============================================================================
// Chat Interface Migration
// ============================================================================
inline std::string MIGRATED_ChatResponse(
    const std::string& message,
    const std::vector<std::pair<std::string, std::string>>& history = {},
    const std::string& model = "local-default") {
    
    // Build context from history
    std::string context;
    for (const auto& [role, content] : history) {
        context += role + ": " + content + "\n";
    }
    context += "User: " + message + "\nAssistant: ";
    
    InferenceRequest req;
    req.model = model;
    req.prompt = context;
    req.temperature = 0.7f;
    
    auto response = InferenceGateway::instance().execute(req);
    return response.success ? response.text : "Error: " + response.error;
}

} // namespace Migration
} // namespace RawrXD

// ============================================================================
// DEPRECATION MARKERS
// These cause compile-time warnings when old APIs are used
// ============================================================================

// Mark common bypass functions as deprecated
namespace RawrXD {
    // Old completion engine
    [[deprecated("Use Migration::MIGRATED_CodeComplete or InferenceGateway")]]
    void IntelligentCompletionEngine_Old();
    
    // Old agentic engine direct calls
    [[deprecated("Use Migration::MIGRATED_AgenticResponse or InferenceGateway")]]
    void AgenticEngine_DirectCall();
    
    // Old chat interface
    [[deprecated("Use Migration::MIGRATED_ChatResponse or InferenceGateway")]]
    void ChatInterface_DirectCall();
}

#endif // RAWRXD_INFERENCE_MIGRATION_H
