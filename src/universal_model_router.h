// universal_model_router.h - Unified Interface for Local GGUF + Cloud Models
// Pure Windows native implementation (no Qt dependency)
#ifndef UNIVERSAL_MODEL_ROUTER_H
#define UNIVERSAL_MODEL_ROUTER_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>
#include <cstdint>

// Model backend enumeration
enum class ModelBackend {
    LOCAL_GGUF,        // Local GGUF quantized models
    OLLAMA_LOCAL,      // Ollama API (local HTTP server)
    ANTHROPIC,         // Claude API (Anthropic)
    OPENAI,            // GPT-4, GPT-3.5 (OpenAI)
    GOOGLE,            // Gemini (Google)
    MOONSHOT,          // Kimi (Moonshot)
    AZURE_OPENAI,      // OpenAI through Azure
    AWS_BEDROCK,       // Claude/Mistral through AWS
    KILO_GATEWAY,      // Kilo Gateway (OpenAI-compatible, free catalog)
    OPENROUTER,        // OpenRouter (OpenAI-compatible, free models)
};

// Model configuration structure
struct ModelConfig {
    ModelBackend backend;
    std::string model_id;                               // Model identifier
    std::string api_key;                                // API key
    std::string endpoint;                               // Custom endpoint URL
    std::map<std::string, std::string> parameters;      // Additional parameters
    std::string description;                            // Human-readable description

    // Validation
    bool isValid() const {
        if (model_id.empty()) return false;

        // Cloud models require API key
        if (backend != ModelBackend::LOCAL_GGUF &&
            backend != ModelBackend::OLLAMA_LOCAL &&
            api_key.empty()) {
            return false;
        }

        return true;
    }
};

// Cloud API Client forward declaration
class CloudApiClient;

// Universal Model Router - Routes requests to appropriate backend
class UniversalModelRouter {
public:
    explicit UniversalModelRouter();
    ~UniversalModelRouter();

    // Model registration and management
    void registerModel(const std::string& model_name, const ModelConfig& config);
    void unregisterModel(const std::string& model_name);
    ModelConfig getModelConfig(const std::string& model_name) const;
    std::vector<std::string> getAvailableModels() const;
    std::vector<std::string> getModelsForBackend(ModelBackend backend) const;

    // Model configuration loading
    bool loadConfigFromFile(const std::string& config_file_path);
    bool saveConfigToFile(const std::string& config_file_path);

    // Backend initialization
    void initializeLocalEngine();
    void initializeCloudClient();

    // Direct model access
    ModelConfig getOrLoadModel(const std::string& model_name);
    bool isModelAvailable(const std::string& model_name) const;
    ModelBackend getModelBackend(const std::string& model_name) const;

    // Model info retrieval
    std::string getModelDescription(const std::string& model_name) const;

private:
    std::map<std::string, ModelConfig> model_registry;
    std::unique_ptr<CloudApiClient> cloud_client;
    bool local_engine_ready;
    bool cloud_client_ready;
};

#endif // UNIVERSAL_MODEL_ROUTER_H
