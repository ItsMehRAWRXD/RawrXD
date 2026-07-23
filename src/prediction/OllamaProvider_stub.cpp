// OllamaProvider_stub.cpp - Stub implementation for OllamaProvider
// Provides link closure when full OllamaProvider is not available

#include "../agentic/OllamaProvider.h"
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Prediction {

// Constructor
OllamaProvider::OllamaProvider() : m_baseUrl("http://localhost:11434") {}

OllamaProvider::OllamaProvider(const std::string& baseUrl) : m_baseUrl(baseUrl) {}

// Destructor
OllamaProvider::~OllamaProvider() = default;

// Configuration
void OllamaProvider::Configure(const PredictionConfig& config) {
    m_config = config;
}

bool OllamaProvider::IsAvailable() const {
    return false;  // Stub: not available
}

bool OllamaProvider::CheckConnection() const {
    return false;  // Stub: no connection
}

// Synchronous prediction
PredictionResult OllamaProvider::Predict(const PredictionContext& ctx) {
    (void)ctx;
    PredictionResult result;
    result.success = false;
    result.error = "OllamaProvider is stubbed - no Ollama backend available";
    return result;
}

// Streaming prediction
void OllamaProvider::PredictStreaming(const PredictionContext& ctx,
                                      StreamTokenCallback callback) {
    (void)ctx;
    if (callback) {
        callback("", true);  // Signal done with empty token
    }
}

// Cancellation
void OllamaProvider::Cancel() {
    m_cancelled.store(true);
}

// HTTP helpers
std::string OllamaProvider::PostJson(const std::string& endpoint,
                                       const std::string& body,
                                       bool& success) const {
    (void)endpoint; (void)body;
    success = false;
    return "";
}

void OllamaProvider::PostJsonStreaming(const std::string& endpoint,
                                       const std::string& body,
                                       std::function<bool(const std::string& chunk)> onChunk) const {
    (void)endpoint; (void)body; (void)onChunk;
}

} // namespace Prediction
} // namespace RawrXD
