// Fail-closed OllamaProvider — linked only when RAWRXD_OPTIONAL_OLLAMA=OFF.
#include "OllamaProvider.h"

using RawrXD::Prediction::OllamaProvider;
using RawrXD::Prediction::PredictionResult;
using RawrXD::Prediction::PredictionContext;
using RawrXD::Prediction::PredictionConfig;
using RawrXD::Prediction::StreamTokenCallback;

OllamaProvider::OllamaProvider() : m_baseUrl() {}
OllamaProvider::OllamaProvider(const std::string&) : m_baseUrl() {}
OllamaProvider::~OllamaProvider() = default;

void OllamaProvider::Configure(const PredictionConfig& config) { m_config = config; }
bool OllamaProvider::IsAvailable() const { return false; }

PredictionResult OllamaProvider::Predict(const PredictionContext&)
{
    PredictionResult r;
    r.success = false;
    r.error = "OPTIONAL_PROVIDER=OFF: prediction adapter not linked";
    return r;
}

void OllamaProvider::PredictStreaming(const PredictionContext&, StreamTokenCallback)
{
}

void OllamaProvider::Cancel() { m_cancelled.store(true); }
bool OllamaProvider::CheckConnection() const { return false; }
