// ============================================================================
// Deep2InferenceEndpoint.h - Phase 1: Runtime Inference Binding
// REST API for Sovereign Runtime execution
// ============================================================================

#ifndef DEEP2_INFERENCE_ENDPOINT_H
#define DEEP2_INFERENCE_ENDPOINT_H

#include "Deep2Engine.h"
#include <string>
#include <vector>
#include <functional>

namespace Deep2 {

// ============================================================================
// Inference Result
// ============================================================================
struct InferenceResult {
    std::string text;
    size_t tokensGenerated = 0;
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
    std::string finishReason;
    bool success = false;
    std::string error;
};

// ============================================================================
// Model Info
// ============================================================================
struct ModelEndpointInfo {
    std::string id;
    std::string name;
    std::string format;
    std::string quantization;
    size_t parameterCount = 0;
    size_t contextLength = 0;
    bool loaded = false;
};

// ============================================================================
// Hardware Info
// ============================================================================
struct HardwareDeviceInfo {
    std::string name;
    std::string type; // "gpu", "cpu"
    std::string backend; // "Vulkan", "CUDA", "ROCm", "CPU"
    size_t vramBytes = 0;
    size_t memoryBytes = 0;
    bool available = false;
};

// ============================================================================
// Deep2 Inference Endpoint
// Production REST API for inference execution
// ============================================================================
class Deep2InferenceEndpoint {
public:
    Deep2InferenceEndpoint(Deep2Engine* engine);
    ~Deep2InferenceEndpoint();

    // Start/stop server
    bool Start(int port = 11435);
    void Stop();
    bool IsRunning() const;

    // Get server info
    int GetPort() const;
    std::string GetUrl() const;

    // Model management
    std::vector<ModelEndpointInfo> ListModels() const;
    bool LoadModel(const std::string& modelId);
    bool UnloadModel(const std::string& modelId);

    // Hardware info
    std::vector<HardwareDeviceInfo> GetHardwareDevices() const;

    // Inference (blocking)
    InferenceResult Complete(const std::string& prompt, 
                              const std::string& model = "",
                              int maxTokens = 256,
                              float temperature = 0.8f);
    
    InferenceResult Chat(const std::vector<std::pair<std::string, std::string>>& messages,
                          const std::string& model = "",
                          int maxTokens = 256,
                          float temperature = 0.8f);

    // Inference (streaming)
    using TokenCallback = std::function<void(const std::string& token, bool done)>;
    
    void CompleteStream(const std::string& prompt,
                        TokenCallback callback,
                        const std::string& model = "",
                        int maxTokens = 256,
                        float temperature = 0.8f);
    
    void ChatStream(const std::vector<std::pair<std::string, std::string>>& messages,
                    TokenCallback callback,
                    const std::string& model = "",
                    int maxTokens = 256,
                    float temperature = 0.8f);

    // Health and telemetry
    bool HealthCheck() const;
    std::string GetTelemetryJson() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API for external integration
// ============================================================================
extern "C" {

// Start inference endpoint
__declspec(dllexport) bool Deep2InferenceEndpoint_Start(void* engine, int port);

// Stop endpoint
__declspec(dllexport) void Deep2InferenceEndpoint_Stop();

// Check if running
__declspec(dllexport) bool Deep2InferenceEndpoint_IsRunning();

} // extern "C"

} // namespace Deep2

#endif // DEEP2_INFERENCE_ENDPOINT_H
