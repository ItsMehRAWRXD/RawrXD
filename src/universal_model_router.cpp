// universal_model_router.cpp - Implementation of Universal Model Router
// Pure Windows native implementation (no Qt dependency)
#include "universal_model_router.h"
#include "cloud_api_client.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

UniversalModelRouter::UniversalModelRouter()
    : local_engine_ready(false),
      cloud_client_ready(false) {
    cloud_client = std::make_unique<CloudApiClient>();
}

UniversalModelRouter::~UniversalModelRouter() = default;

void UniversalModelRouter::registerModel(const std::string& model_name, const ModelConfig& config) {
    if (!config.isValid()) {
        std::cerr << "[router] Invalid configuration for model: " << model_name << std::endl;
        return;
    }

    model_registry[model_name] = config;
}

void UniversalModelRouter::unregisterModel(const std::string& model_name) {
    model_registry.erase(model_name);
}

ModelConfig UniversalModelRouter::getModelConfig(const std::string& model_name) const {
    auto it = model_registry.find(model_name);
    if (it != model_registry.end()) {
        return it->second;
    }

    ModelConfig empty;
    empty.model_id = "";
    return empty;
}

std::vector<std::string> UniversalModelRouter::getAvailableModels() const {
    std::vector<std::string> models;
    for (const auto& pair : model_registry) {
        models.push_back(pair.first);
    }
    return models;
}

std::vector<std::string> UniversalModelRouter::getModelsForBackend(ModelBackend backend) const {
    std::vector<std::string> models;

    for (const auto& pair : model_registry) {
        if (pair.second.backend == backend) {
            models.push_back(pair.first);
        }
    }

    return models;
}

bool UniversalModelRouter::loadConfigFromFile(const std::string& config_file_path) {
    std::ifstream file(config_file_path);
    if (!file.is_open()) {
        std::cerr << "[router] Cannot open config file: " << config_file_path << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    // Simple JSON parsing - in production, use a proper JSON library
    // For now, just register models from environment variables
    model_registry.clear();

    // Check for KILO_GATEWAY model
    const char* kilo_key = std::getenv("KILO_API_KEY");
    const char* kilo_model = std::getenv("KILO_MODEL");
    if (kilo_key && kilo_key[0] != '\0') {
        ModelConfig cfg;
        cfg.backend = ModelBackend::KILO_GATEWAY;
        cfg.model_id = kilo_model ? kilo_model : "kilo-auto/free";
        cfg.api_key = kilo_key;
        registerModel("kilo/free", cfg);
    }

    // Check for OpenRouter
    const char* or_key = std::getenv("OPENROUTER_API_KEY");
    const char* or_model = std::getenv("OPENROUTER_MODEL");
    if (or_key && or_key[0] != '\0') {
        ModelConfig cfg;
        cfg.backend = ModelBackend::OPENROUTER;
        cfg.model_id = or_model ? or_model : "openrouter/free";
        cfg.api_key = or_key;
        registerModel("openrouter/free", cfg);
    }

    std::cout << "[router] Loaded " << model_registry.size() << " cloud models from environment" << std::endl;
    return true;
}

bool UniversalModelRouter::saveConfigToFile(const std::string& config_file_path) {
    using json = nlohmann::json;

    try {
        json config;

        // Serialize all registered models
        json models = json::array();
        for (const auto& [name, cfg] : model_registry) {
            json modelEntry;
            modelEntry["name"] = name;
            modelEntry["backend"] = static_cast<int>(cfg.backend);
            modelEntry["model_id"] = cfg.model_id;
            modelEntry["api_key"] = cfg.api_key;
            modelEntry["endpoint"] = cfg.endpoint;
            modelEntry["description"] = cfg.description;

            // Serialize parameters map
            json params = json::object();
            for (const auto& [k, v] : cfg.parameters) {
                params[k] = v;
            }
            modelEntry["parameters"] = params;

            models.push_back(modelEntry);
        }
        config["models"] = models;

        // Write to file
        std::ofstream file(config_file_path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "[router] Cannot open config file for writing: "
                      << config_file_path << std::endl;
            return false;
        }

        file << config.dump(2);  // Pretty-print with 2-space indentation
        file.close();

        std::cout << "[router] Saved " << model_registry.size()
                  << " model configs to: " << config_file_path << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[router] Failed to save config: " << e.what() << std::endl;
        return false;
    }
}

void UniversalModelRouter::initializeLocalEngine() {
    local_engine_ready = true;
}

void UniversalModelRouter::initializeCloudClient() {
    cloud_client_ready = true;
}

ModelConfig UniversalModelRouter::getOrLoadModel(const std::string& model_name) {
    return getModelConfig(model_name);
}

bool UniversalModelRouter::isModelAvailable(const std::string& model_name) const {
    return model_registry.find(model_name) != model_registry.end();
}

ModelBackend UniversalModelRouter::getModelBackend(const std::string& model_name) const {
    auto it = model_registry.find(model_name);
    if (it != model_registry.end()) {
        return it->second.backend;
    }

    return ModelBackend::LOCAL_GGUF;  // Default
}

std::string UniversalModelRouter::getModelDescription(const std::string& model_name) const {
    auto it = model_registry.find(model_name);
    if (it != model_registry.end()) {
        return it->second.description;
    }

    return "";
}
