// backend_factory.cpp
// Batch 10: Backend Factory and Registry
//
// Provides unified interface for creating and managing backends
// Supports: Sovereign, Ollama, OpenAI, Anthropic, Local GGUF, vLLM

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <stdexcept>

namespace Benchmark {
namespace Backends {

// Backend types
enum class BackendType {
    SOVEREIGN,
    OLLAMA,
    OPENAI,
    ANTHROPIC,
    LOCAL_GGUF,
    VLLM,
    CUSTOM
};

// Backend configuration base
struct BackendConfig {
    std::string name;
    std::string base_url;
    std::string api_key;
    int timeout_ms = 30000;
    int max_retries = 3;
    std::map<std::string, std::string> extra_params;
};

// Backend interface
class IBackend {
public:
    virtual ~IBackend() = default;
    
    virtual bool IsAvailable() const = 0;
    virtual bool HealthCheck() = 0;
    virtual InferenceResult RunInference(const InferenceRequest& request) = 0;
    virtual std::vector<std::string> ListModels() const = 0;
    virtual std::string GetBackendName() const = 0;
    virtual BackendType GetBackendType() const = 0;
};

// Backend factory
class BackendFactory {
public:
    using BackendCreator = std::function<std::unique_ptr<IBackend>(const BackendConfig&)>;
    
    // Get singleton instance
    static BackendFactory& Instance() {
        static BackendFactory instance;
        return instance;
    }
    
    // Register a backend type
    void Register(BackendType type, BackendCreator creator) {
        creators_[type] = creator;
    }
    
    // Register by name
    void Register(const std::string& name, BackendCreator creator) {
        named_creators_[name] = creator;
    }
    
    // Create backend by type
    std::unique_ptr<IBackend> Create(BackendType type, const BackendConfig& config) {
        auto it = creators_.find(type);
        if (it != creators_.end()) {
            return it->second(config);
        }
        throw std::runtime_error("Unknown backend type");
    }
    
    // Create backend by name
    std::unique_ptr<IBackend> Create(const std::string& name, const BackendConfig& config) {
        // Check named creators first
        auto named_it = named_creators_.find(name);
        if (named_it != named_creators_.end()) {
            return named_it->second(config);
        }
        
        // Try to parse as BackendType
        BackendType type = ParseBackendType(name);
        return Create(type, config);
    }
    
    // Auto-detect and create best backend
    std::unique_ptr<IBackend> AutoCreate(const BackendConfig& config) {
        // Try backends in order of preference
        std::vector<BackendType> preference_order = {
            BackendType::SOVEREIGN,
            BackendType::OLLAMA,
            BackendType::LOCAL_GGUF,
            BackendType::VLLM
        };
        
        for (BackendType type : preference_order) {
            try {
                auto backend = Create(type, config);
                if (backend->IsAvailable()) {
                    return backend;
                }
            } catch (...) {
                // Continue to next
            }
        }
        
        throw std::runtime_error("No backend available");
    }
    
    // List available backend types
    std::vector<std::string> ListBackendTypes() const {
        return {
            "sovereign",
            "ollama",
            "openai",
            "anthropic",
            "local_gguf",
            "vllm"
        };
    }
    
    // Parse backend type from string
    static BackendType ParseBackendType(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        if (lower == "sovereign") return BackendType::SOVEREIGN;
        if (lower == "ollama") return BackendType::OLLAMA;
        if (lower == "openai") return BackendType::OPENAI;
        if (lower == "anthropic") return BackendType::ANTHROPIC;
        if (lower == "local_gguf" || lower == "gguf") return BackendType::LOCAL_GGUF;
        if (lower == "vllm") return BackendType::VLLM;
        
        return BackendType::CUSTOM;
    }
    
    // Convert backend type to string
    static std::string BackendTypeToString(BackendType type) {
        switch (type) {
            case BackendType::SOVEREIGN: return "sovereign";
            case BackendType::OLLAMA: return "ollama";
            case BackendType::OPENAI: return "openai";
            case BackendType::ANTHROPIC: return "anthropic";
            case BackendType::LOCAL_GGUF: return "local_gguf";
            case BackendType::VLLM: return "vllm";
            case BackendType::CUSTOM: return "custom";
        }
        return "unknown";
    }
    
    // Get backend description
    static std::string GetBackendDescription(BackendType type) {
        switch (type) {
            case BackendType::SOVEREIGN:
                return "RawrXD Sovereign inference server";
            case BackendType::OLLAMA:
                return "Ollama local model runner";
            case BackendType::OPENAI:
                return "OpenAI API-compatible service";
            case BackendType::ANTHROPIC:
                return "Anthropic Claude API";
            case BackendType::LOCAL_GGUF:
                return "Local GGUF model (llama.cpp)";
            case BackendType::VLLM:
                return "vLLM inference server";
            case BackendType::CUSTOM:
                return "Custom backend";
        }
        return "Unknown";
    }

private:
    BackendFactory() = default;
    
    std::map<BackendType, BackendCreator> creators_;
    std::map<std::string, BackendCreator> named_creators_;
};

// Backend manager for lifecycle management
class BackendManager {
public:
    static BackendManager& Instance() {
        static BackendManager instance;
        return instance;
    }
    
    // Initialize a backend
    std::shared_ptr<IBackend> Initialize(const std::string& name,
                                          const BackendConfig& config) {
        auto backend = BackendFactory::Instance().Create(name, config);
        
        if (!backend->HealthCheck()) {
            throw std::runtime_error("Backend health check failed: " + name);
        }
        
        backends_[name] = backend;
        return backend;
    }
    
    // Get initialized backend
    std::shared_ptr<IBackend> Get(const std::string& name) {
        auto it = backends_.find(name);
        if (it != backends_.end()) {
            return it->second;
        }
        return nullptr;
    }
    
    // Shutdown a backend
    void Shutdown(const std::string& name) {
        backends_.erase(name);
    }
    
    // Shutdown all backends
    void ShutdownAll() {
        backends_.clear();
    }
    
    // List active backends
    std::vector<std::string> ListActive() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : backends_) {
            names.push_back(name);
        }
        return names;
    }
    
    // Check if backend is active
    bool IsActive(const std::string& name) const {
        return backends_.find(name) != backends_.end();
    }

private:
    BackendManager() = default;
    
    std::map<std::string, std::shared_ptr<IBackend>> backends_;
};

// Backend discovery
class BackendDiscovery {
public:
    struct DiscoveredBackend {
        std::string name;
        BackendType type;
        std::string url;
        bool available;
        std::string version;
    };
    
    // Auto-discover backends on local network
    static std::vector<DiscoveredBackend> DiscoverLocal() {
        std::vector<DiscoveredBackend> discovered;
        
        // Check common ports
        std::vector<std::pair<std::string, int>> endpoints = {
            {"localhost", 8080},   // Sovereign
            {"localhost", 11434},  // Ollama
            {"localhost", 8000},   // vLLM
            {"localhost", 8081},   // Alternative Sovereign
        };
        
        for (const auto& [host, port] : endpoints) {
            std::string url = "http://" + host + ":" + std::to_string(port);
            
            // Try to detect backend type
            BackendType type = DetectBackendType(url);
            if (type != BackendType::CUSTOM) {
                DiscoveredBackend backend;
                backend.name = BackendFactory::BackendTypeToString(type);
                backend.type = type;
                backend.url = url;
                backend.available = true; // Would actually test in production
                discovered.push_back(backend);
            }
        }
        
        return discovered;
    }
    
    // Detect backend type from URL
    static BackendType DetectBackendType(const std::string& url) {
        // Check for Ollama
        if (url.find(":11434") != std::string::npos) {
            return BackendType::OLLAMA;
        }
        
        // Check for vLLM
        if (url.find(":8000") != std::string::npos) {
            return BackendType::VLLM;
        }
        
        // Default to Sovereign for 8080/8081
        if (url.find(":8080") != std::string::npos ||
            url.find(":8081") != std::string::npos) {
            return BackendType::SOVEREIGN;
        }
        
        return BackendType::CUSTOM;
    }
    
    // Check environment variables for backend config
    static BackendConfig ConfigFromEnvironment() {
        BackendConfig config;
        
        const char* backend_url = std::getenv("BENCHMARK_BACKEND_URL");
        if (backend_url) {
            config.base_url = backend_url;
        }
        
        const char* api_key = std::getenv("BENCHMARK_API_KEY");
        if (api_key) {
            config.api_key = api_key;
        }
        
        const char* timeout = std::getenv("BENCHMARK_TIMEOUT");
        if (timeout) {
            config.timeout_ms = std::atoi(timeout);
        }
        
        return config;
    }
};

// Convenience function to create backend
inline std::unique_ptr<IBackend> CreateBackend(const std::string& name,
                                                const BackendConfig& config = BackendConfig()) {
    return BackendFactory::Instance().Create(name, config);
}

// Convenience function to auto-detect and create backend
inline std::unique_ptr<IBackend> AutoCreateBackend(const BackendConfig& config = BackendConfig()) {
    return BackendFactory::Instance().AutoCreate(config);
}

} // namespace Backends
} // namespace Benchmark
