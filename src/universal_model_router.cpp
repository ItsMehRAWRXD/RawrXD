<<<<<<< HEAD
// universal_model_router.cpp - Implementation of Universal Model Router
// Win32: include winsock2 + windows + winhttp first to avoid header order / macro conflicts (e.g. with nlohmann/json).
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

#include "universal_model_router.h"
#include "cloud_api_client.h"
#include "cpu_inference_engine.h"
#include "RawrXD_PipeClient.h"
#include <nlohmann/json.hpp>

// ASM Model Loader externs
extern "C" {
    int LoadModel(const wchar_t* path);
    void* GetTensor(const char* name);
    void UnloadModel();
    int ModelLoaderInit();
    int HotSwapModel(const wchar_t* newPath, char preserveKV);
    const wchar_t* GetCurrentModelPath();
    unsigned long long GetModelLoadTimestamp();
}

// Beacon externs
extern "C" {
    int BeaconRouterInit();
    int BeaconSend(int beaconID, void* pData, int dataLen);
    int BeaconRecv(int beaconID, void** ppData, int* pLen);
    int TryBeaconRecv(int beaconID, void** ppData, int* pLen);
    int RegisterAgent(int agentID, int beaconSlot);
}

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include "agent/local_reasoning_integration.hpp"

using namespace RawrXD;

namespace {
static ModelBackend backendFromString(const std::string& s) {
    if (s == "LOCAL_GGUF") return ModelBackend::LOCAL_GGUF;
    if (s == "OLLAMA_LOCAL") return ModelBackend::OLLAMA_LOCAL;
    if (s == "ANTHROPIC") return ModelBackend::ANTHROPIC;
    if (s == "OPENAI") return ModelBackend::OPENAI;
    if (s == "GOOGLE") return ModelBackend::GOOGLE;
    if (s == "MOONSHOT") return ModelBackend::MOONSHOT;
    if (s == "AZURE_OPENAI") return ModelBackend::AZURE_OPENAI;
    if (s == "AWS_BEDROCK") return ModelBackend::AWS_BEDROCK;
    if (s == "REASONING_ENGINE") return ModelBackend::REASONING_ENGINE;
    return ModelBackend::LOCAL_GGUF;
}
static const char* backendToString(ModelBackend b) {
    switch (b) {
        case ModelBackend::LOCAL_GGUF: return "LOCAL_GGUF";
        case ModelBackend::OLLAMA_LOCAL: return "OLLAMA_LOCAL";
        case ModelBackend::ANTHROPIC: return "ANTHROPIC";
        case ModelBackend::OPENAI: return "OPENAI";
        case ModelBackend::GOOGLE: return "GOOGLE";
        case ModelBackend::MOONSHOT: return "MOONSHOT";
        case ModelBackend::AZURE_OPENAI: return "AZURE_OPENAI";
        case ModelBackend::AWS_BEDROCK: return "AWS_BEDROCK";
        case ModelBackend::REASONING_ENGINE: return "REASONING_ENGINE";
    }
    return "LOCAL_GGUF";
}
}

namespace RawrXD {

UniversalModelRouter::UniversalModelRouter()
    : m_localEngineReady(false),
      m_cloudClientReady(false)
{
    // Cloud client will be initialized lazily
}

UniversalModelRouter::~UniversalModelRouter() = default;

void UniversalModelRouter::registerModel(const std::string& model_name, const ModelConfig& config)
{
    if (!config.isValid()) {
        if (m_onError) {
            m_onError("Invalid configuration for model: " + model_name);
        }
        return;
    }
    
    m_modelRegistry[model_name] = config;
    if (m_onModelRegistered) {
        m_onModelRegistered(model_name, config.backend);
    }
}

void UniversalModelRouter::unregisterModel(const std::string& model_name)
{
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        m_modelRegistry.erase(it);
        if (m_onModelUnregistered) {
            m_onModelUnregistered(model_name);
        }
    }
}

ModelConfig UniversalModelRouter::getModelConfig(const std::string& model_name) const
{
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        return it->second;
    }
    
    ModelConfig empty;
    return empty;
}

std::vector<std::string> UniversalModelRouter::getAvailableModels() const
{
    std::vector<std::string> models;
    for (const auto& [name, _] : m_modelRegistry) {
        models.push_back(name);
    }
    return models;
}

std::vector<std::string> UniversalModelRouter::getModelsForBackend(ModelBackend backend) const
{
    std::vector<std::string> models;
    
    for (const auto& [name, config] : m_modelRegistry) {
        if (config.backend == backend) {
            models.push_back(name);
        }
    }
    
    return models;
}

bool UniversalModelRouter::loadConfigFromFile(const std::string& config_file_path)
{
    std::ifstream file(config_file_path);
    if (!file.is_open()) {
        if (m_onError) {
            m_onError("Cannot open config file: " + config_file_path);
        }
        return false;
    }
    try {
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        nlohmann::json j = nlohmann::json::parse(content);
        return loadConfigFromJson(j);
    } catch (const std::exception& e) {
        if (m_onError) m_onError(std::string("Config parse error: ") + e.what());
        return false;
    }
}

bool UniversalModelRouter::loadConfigFromJson(const json& config_json)
{
    if (!config_json.is_object() || !config_json.contains("models") || !config_json["models"].is_object()) {
        if (m_onError) m_onError("Invalid config format: expected { \"models\": { ... } }");
        return false;
    }

    m_modelRegistry.clear();
    for (auto it = config_json["models"].begin(); it != config_json["models"].end(); ++it) {
        const std::string& name = it.key();
        const auto& mc = it.value();
        if (!mc.is_object()) continue;

        ModelConfig config;
        config.backend = backendFromString(mc.value("backend", "LOCAL_GGUF"));
        config.model_id = mc.value("model_id", "");
        config.api_key = mc.value("api_key", "");
        config.endpoint = mc.value("endpoint", "");
        config.description = mc.value("description", "");
        if (mc.contains("full_config")) {
            config.full_config = mc["full_config"];
        } else {
            config.full_config = json{};
        }
        if (mc.contains("parameters") && mc["parameters"].is_object()) {
            for (auto p = mc["parameters"].begin(); p != mc["parameters"].end(); ++p) {
                if (p->is_string()) config.parameters[p.key()] = p->get<std::string>();
                else config.parameters[p.key()] = p->dump();
            }
        }

        if (!config.model_id.empty()) {
            m_modelRegistry[name] = config;
            if (m_onModelRegistered) m_onModelRegistered(name, config.backend);
        }
    }

    if (m_onConfigLoaded) m_onConfigLoaded(static_cast<int>(m_modelRegistry.size()));
    return true;
}

bool UniversalModelRouter::saveConfigToFile(const std::string& config_file_path)
{
    std::ofstream file(config_file_path);
    if (!file.is_open()) {
        if (m_onError) m_onError("Cannot write config file: " + config_file_path);
        return false;
    }
    try {
        nlohmann::json models = nlohmann::json::object();
        for (const auto& [name, config] : m_modelRegistry) {
            nlohmann::json mc;
            mc["backend"] = backendToString(config.backend);
            mc["model_id"] = config.model_id;
            mc["api_key"] = config.api_key;
            mc["endpoint"] = config.endpoint;
            mc["description"] = config.description;
            mc["full_config"] = config.full_config;
            nlohmann::json params = nlohmann::json::object();
            for (const auto& [k, v] : config.parameters)
                params[k] = v;
            mc["parameters"] = std::move(params);
            models[name] = std::move(mc);
        }
        nlohmann::json root;
        root["models"] = std::move(models);
        file << root.dump(2);
        file.close();
        return true;
    } catch (const std::exception& e) {
        if (m_onError) m_onError(std::string("Config save error: ") + e.what());
        return false;
    }
}

void UniversalModelRouter::initializeLocalEngine(const std::string& model_path)
{
    // Initialize the ASM Model Loader
    if (ModelLoaderInit() != 0) {
        if (m_onError) m_onError("Failed to initialize ASM Model Loader");
        return;
    }

    // Initialize Beacon Router for inter-agent communication
    if (BeaconRouterInit() != 0) {
        if (m_onError) m_onError("Failed to initialize Beacon Router");
        return;
    }

    // Load the model using ASM
    std::wstring wide_path(model_path.begin(), model_path.end());
    if (LoadModel(wide_path.c_str()) != 0) {
        if (m_onError) m_onError("Failed to load model via ASM: " + model_path);
        return;
    }

    m_localEngineReady = true;
    
    if (m_onModelRegistered) {
        m_onModelRegistered(model_path, ModelBackend::LOCAL_GGUF);
    }
}

void UniversalModelRouter::initializeCloudClient()
{
    // Cloud client is already initialized
    m_cloudClientReady = true;
}

bool UniversalModelRouter::hotSwapModel(const std::string& new_model_path, bool preserve_kv_cache)
{
    std::wstring wide_path(new_model_path.begin(), new_model_path.end());
    int result = HotSwapModel(wide_path.c_str(), preserve_kv_cache ? 1 : 0);
    return result == 1;
}

ModelConfig UniversalModelRouter::getOrLoadModel(const std::string& model_name)
{
    return getModelConfig(model_name);
}

bool UniversalModelRouter::isModelAvailable(const std::string& model_name) const
{
    return m_modelRegistry.find(model_name) != m_modelRegistry.end();
}

ModelBackend UniversalModelRouter::getModelBackend(const std::string& model_name) const
{
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        return it->second.backend;
    }
    
    return ModelBackend::LOCAL_GGUF;  // Default
}

std::string UniversalModelRouter::getModelDescription(const std::string& model_name) const
{
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        return it->second.description;
    }
    
    return "";
}

json UniversalModelRouter::getModelInfo(const std::string& model_name) const
{
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        const ModelConfig& cfg = it->second;
        json info = json::object();
        info["backend"] = backendToString(cfg.backend);
        info["model_id"] = cfg.model_id;
        info["endpoint"] = cfg.endpoint;
        info["description"] = cfg.description;
        json params = json::object();
        for (const auto& kv : cfg.parameters) {
            params[kv.first] = kv.second;
        }
        info["parameters"] = std::move(params);
        info["full_config"] = cfg.full_config;
        return info;
    }

    return json{};
}

void UniversalModelRouter::onLocalEngineInitialized()
{
    m_localEngineReady = true;
}

void UniversalModelRouter::onCloudClientInitialized()
{
    m_cloudClientReady = true;
}

void UniversalModelRouter::onEngineError(const std::string& error)
{
    if (m_onError) {
        m_onError(error);
    }
}

#if defined(_WIN32)
// Call Ollama /api/generate with the given model name (agentic autonomous local — any model from /api/tags is valid)
static void invokeOllamaGenerate(const std::string& model_name, const std::string& prompt,
    std::function<void(const std::string& chunk, bool complete)> callback)
{
    if (!callback) return;
    const wchar_t* host = L"localhost";
    INTERNET_PORT port = 11434;
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Router/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!hSession) { callback("Error: WinHttpOpen failed.", true); return; }
    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        callback("Error: Cannot connect to Ollama. Start Ollama (ollama serve) or use File > Load GGUF for local inference.", true);
        return;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); callback("Error: WinHttpOpenRequest failed.", true); return; }
    std::string escPrompt;
    escPrompt.reserve(prompt.size() + 16);
    for (char c : prompt) {
        if (c == '"') escPrompt += "\\\"";
        else if (c == '\\') escPrompt += "\\\\";
        else if (c == '\n') escPrompt += "\\n";
        else if (c == '\r') escPrompt += "\\r";
        else if (static_cast<unsigned char>(c) >= 32 || c == '\t') escPrompt += c;
    }
    std::string escModel;
    escModel.reserve(model_name.size() + 4);
    for (char c : model_name) {
        if (c == '"') escModel += "\\\"";
        else if (c == '\\') escModel += "\\\\";
        else if (static_cast<unsigned char>(c) >= 32 || c == '\t') escModel += c;
    }
    std::string body = "{\"model\":\"" + escModel + "\",\"prompt\":\"" + escPrompt + "\",\"stream\":true}";
    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!sent) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); callback("Error: Ollama request send failed.", true); return; }
    if (!WinHttpReceiveResponse(hRequest, NULL)) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); callback("Error: Ollama not responding.", true); return; }
    std::string lineBuf;
    char buf[4096];
    DWORD dwRead;
    for (;;) {
        dwRead = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwRead) || dwRead == 0) break;
        if (dwRead > sizeof(buf)) dwRead = sizeof(buf);
        if (!WinHttpReadData(hRequest, buf, dwRead, &dwRead) || dwRead == 0) break;
        for (DWORD i = 0; i < dwRead; i++) {
            if (buf[i] == '\n') {
                if (!lineBuf.empty()) {
                    try {
                        auto j = nlohmann::json::parse(lineBuf);
                        if (j.contains("error") && j["error"].is_string()) {
                            std::string err = "Error: " + j["error"].get<std::string>();
                            err += "\n\nTip: Ensure Ollama is running (ollama serve), the model exists (ollama pull "
                                + model_name + "), or use File > Load GGUF for local inference.";
                            callback(err, true);
                            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
                            return;
                        }
                        if (j.contains("response") && j["response"].is_string()) {
                            std::string tok = j["response"].get<std::string>();
                            if (!tok.empty()) callback(tok, false);
                        }
                        if (j.contains("done") && j["done"].get<bool>()) { callback("", true); WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }
                    } catch (...) {}
                }
                lineBuf.clear();
            } else {
                lineBuf += buf[i];
            }
        }
    }
    if (!lineBuf.empty()) {
        try {
            auto j = nlohmann::json::parse(lineBuf);
            if (j.contains("response") && j["response"].is_string()) {
                std::string tok = j["response"].get<std::string>();
                if (!tok.empty()) callback(tok, false);
            }
        } catch (...) {}
    }
    callback("", true);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}
#endif

std::string UniversalModelRouter::routeQuery(const std::string& model_name, const std::string& prompt, float /*temperature*/)
{
    // If the user registered this model, prefer its configured model_id/backend.
    std::string backendModelId = model_name;
    ModelBackend backend = ModelBackend::OLLAMA_LOCAL;
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        backend = it->second.backend;
        if (!it->second.model_id.empty()) backendModelId = it->second.model_id;
    }

    if (backend == ModelBackend::REASONING_ENGINE) {
        auto rr = LocalReasoningIntegration::analyzeCode(prompt, "text", true, true);
        std::string out = rr.summary;
        for (const auto& s : rr.suggestions) { out += "\n"; out += s; }
        return out;
    }

    if (backend == ModelBackend::ANTHROPIC) {
        return "Error: ANTHROPIC backend not wired in this build. Configure a local backend (Ollama/LOCAL_GGUF) or add cloud client integration.";
    }
    if (backend == ModelBackend::OPENAI || backend == ModelBackend::AZURE_OPENAI) {
        return "Error: OPENAI backend not wired in this build. Configure a local backend (Ollama/LOCAL_GGUF) or add cloud client integration.";
    }

#if defined(_WIN32)
    std::string out;
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;

    invokeOllamaGenerate(backendModelId, prompt, [&](const std::string& chunk, bool complete) {
        if (!chunk.empty()) out += chunk;
        if (complete) {
            std::lock_guard<std::mutex> lock(mu);
            done = true;
            cv.notify_one();
        }
    });

    {
        std::unique_lock<std::mutex> lock(mu);
        cv.wait_for(lock, std::chrono::seconds(120), [&]() { return done; });
    }
    if (!done && out.empty()) return "Error: Ollama request timed out.";
    return out;
#else
    return "Error: Ollama streaming only implemented on Windows in this build.";
#endif
}

void UniversalModelRouter::routeStreamQuery(const std::string& model_name, const std::string& prompt, StreamCallback callback, float /*temperature*/)
{
    if (!callback) return;

    std::string backendModelId = model_name;
    ModelBackend backend = ModelBackend::OLLAMA_LOCAL;
    auto it = m_modelRegistry.find(model_name);
    if (it != m_modelRegistry.end()) {
        backend = it->second.backend;
        if (!it->second.model_id.empty()) backendModelId = it->second.model_id;
    }

    if (backend == ModelBackend::REASONING_ENGINE) {
        callback(routeQuery(model_name, prompt));
        return;
    }

#if defined(_WIN32)
    invokeOllamaGenerate(backendModelId, prompt, [&](const std::string& chunk, bool complete) {
        (void)complete;
        if (!chunk.empty()) callback(chunk);
    });
#else
    callback(routeQuery(model_name, prompt));
#endif
}

std::vector<std::string> UniversalModelRouter::getAvailableBackends() const
{
    return {
        "RawrXD-Native (Local GGUF)",
        "RawrXD Reasoning (Alpha)",
        "Claude-3.5-Sonnet (Anthropic)",
        "GPT-4o (OpenAI)",
        "Gemini-1.5-Pro (Google)",
        "Llama-3-70B (Local Ollama)"
    };
}

void UniversalModelRouter::routeRequest(const std::string& model_name,
                                        const std::string& prompt,
                                        std::function<void(const std::string&)> callback)
{
    if (!callback) return;
    callback(routeQuery(model_name, prompt));
}

} // namespace RawrXD
=======
#include "universal_model_router.h"
#include "cloud_api_client.h"
#include "cpu_inference_engine.h"
#include "RawrXD_PipeClient.h"
#include <fstream>
#include <iostream>
#include <future>
#include <filesystem>

namespace RawrXD {

UniversalModelRouter::UniversalModelRouter() : local_engine_ready(false), local_engine(nullptr), cloud_client(nullptr) {}


UniversalModelRouter::~UniversalModelRouter() {
    // Unique ptrs handle cleanup
}

void UniversalModelRouter::registerModel(const std::string& name, const ModelConfig& config) {
    if (name.empty()) return;
    model_registry[name] = config;
}

void UniversalModelRouter::unregisterModel(const std::string& name) {
    model_registry.erase(name);
}

ModelConfig UniversalModelRouter::getModelConfig(const std::string& name) const {
    auto it = model_registry.find(name);
    if (it != model_registry.end()) return it->second;
    return ModelConfig();
}

std::vector<std::string> UniversalModelRouter::getAvailableModels() const {
    std::vector<std::string> keys;
    for(const auto& [k, v] : model_registry) keys.push_back(k);
    return keys;
}

std::vector<std::string> UniversalModelRouter::getModelsForBackend(ModelBackend backend) const {
     std::vector<std::string> keys;
     for(const auto& [k, v] : model_registry) {
         if (v.backend == backend) keys.push_back(k);
     }
     return keys;
}

bool UniversalModelRouter::loadConfigFromFile(const std::string& path) {
    try {
        std::ifstream f(path);
        if (!f.is_open()) return false;
        json j;
        f >> j;
        return loadConfigFromJson(j);
    } catch (...) {
        return false;
    }
}

bool UniversalModelRouter::loadConfigFromJson(const json& j) {
    try {
        if (!j.is_object()) return false;
        
        if (j.contains("models") && j["models"].is_object()) {
            for (auto& [name, model_json] : j["models"].items()) {
                ModelConfig config;
                // Default to LOCAL_GGUF if not specified
                int backendVal = model_json.value("backend", 0);
                config.backend = static_cast<ModelBackend>(backendVal);
                config.model_id = model_json.value("model_id", "");
                config.api_key = model_json.value("api_key", "");
                config.endpoint = model_json.value("endpoint", "");
                config.description = model_json.value("description", "");
                
                if (model_json.contains("parameters") && model_json["parameters"].is_object()) {
                    for (auto& [pk, pv] : model_json["parameters"].items()) {
                        config.parameters[pk] = pv.get<std::string>();
                    }
                }
                
                config.full_config = model_json;
                registerModel(name, config);
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool UniversalModelRouter::saveConfigToFile(const std::string& path) {
    try {
        json root = json::object();
        json models = json::object();
        
        for (const auto& [name, config] : model_registry) {
            json m;
            m["backend"] = static_cast<int>(config.backend);
            m["model_id"] = config.model_id;
            m["api_key"] = config.api_key;
            m["endpoint"] = config.endpoint;
            m["description"] = config.description;
            
            json params = json::object();
            for (const auto& [pk, pv] : config.parameters) {
                params[pk] = pv;
            }
            m["parameters"] = params;
            
            models[name] = m;
        }
        
        root["models"] = models;
        
        std::ofstream f(path);
        if (!f.is_open()) return false;
        f << root.dump(4);
        return true;
    } catch (...) {
        return false;
    }
}

void UniversalModelRouter::initializeLocalEngine(const std::string& path) {
    if (!local_engine) {
        local_engine = std::make_unique<CPUInferenceEngine>();
    }
    
    std::string modelPath = path;
    
    // Auto-discovery logic if path is empty
    if (modelPath.empty()) {
        // Check if we have a default "local" model in the registry
        for (const auto& [name, config] : model_registry) {
            if (config.backend == ModelBackend::LOCAL_GGUF && !config.model_id.empty()) {
                // If model_id looks like a path, use it
                if (std::filesystem::exists(config.model_id)) {
                    modelPath = config.model_id;
                    break;
                }
            }
        }
        
        // Fallback to common locations
        if (modelPath.empty()) {
            std::vector<std::string> searchPaths = {
                "models/phi-2.gguf",
                "models/mistral-7b-quantized.gguf",
                "D:/rawrxd/models/default.gguf"
            };
            for (const auto& p : searchPaths) {
                if (std::filesystem::exists(p)) {
                    modelPath = p;
                    break;
                }
            }
        }
    }

    if (!modelPath.empty() && std::filesystem::exists(modelPath)) {
        if (local_engine->loadModel(modelPath)) {
            local_engine_ready = true;
        } else {
             std::cerr << "Failed to load local model: " << modelPath << std::endl;
        }
    } else {
        std::cerr << "No local model found or specified." << std::endl;
    }
}

void UniversalModelRouter::initializeCloudClient() {
    // CloudApiClient is standard unique_ptr
    if (!cloud_client) {
        cloud_client = std::make_unique<CloudApiClient>(this);
    }
}

ModelConfig UniversalModelRouter::getOrLoadModel(const std::string& name) {
    return getModelConfig(name);
}

bool UniversalModelRouter::isModelAvailable(const std::string& name) const {
    return model_registry.find(name) != model_registry.end();
}

ModelBackend UniversalModelRouter::getModelBackend(const std::string& name) const {
    auto it = model_registry.find(name);
    if (it != model_registry.end()) return it->second.backend;
    return ModelBackend::LOCAL_GGUF;
}

std::string UniversalModelRouter::getModelDescription(const std::string& name) const {
    auto it = model_registry.find(name);
    if (it != model_registry.end()) return it->second.description;
    return "";
}

json UniversalModelRouter::getModelInfo(const std::string& name) const {
    auto it = model_registry.find(name);
    if (it != model_registry.end()) return it->second.full_config;
    return json::object();
}

// Helper to bridge configs
RawrXD::CloudModelConfig bridgeToCloudConfig(const RawrXD::ModelConfig& mc, float temp) {
    RawrXD::CloudModelConfig cc;
    
    switch(mc.backend) {
        case ModelBackend::ANTHROPIC: cc.provider = "anthropic"; break;
        case ModelBackend::OLLAMA_LOCAL: cc.provider = "ollama"; break;
        case ModelBackend::AZURE_OPENAI: cc.provider = "azure"; break;
        case ModelBackend::GOOGLE: cc.provider = "google"; break;
        case ModelBackend::MOONSHOT: cc.provider = "moonshot"; break;
        case ModelBackend::OPENAI: 
        default:
            cc.provider = "openai"; break;
    }
    
    cc.model = mc.model_id;
    cc.apiKey = mc.api_key;
    cc.endpoint = mc.endpoint;
    cc.temperature = temp;
    
    // Check parameters for overrides
    if (mc.parameters.count("max_tokens")) {
        try { cc.maxTokens = std::stoi(mc.parameters.at("max_tokens")); } catch(...) {}
    }
    
    return cc;
}

std::string UniversalModelRouter::routeQuery(const std::string& model_name, const std::string& prompt, float temperature) {
    if (!isModelAvailable(model_name)) {
        return "Error: Model not found.";
    }

    ModelConfig config = getModelConfig(model_name);
    
    if (config.backend == ModelBackend::LOCAL_GGUF || config.backend == ModelBackend::LOCAL_TITAN) {
        if (!local_engine_ready || !local_engine) {
             initializeLocalEngine(""); // Lazy init
        }
        
        // Blocking generation using streaming interface
        std::string full_response;
        std::promise<void> done_promise;
        std::future<void> done_future = done_promise.get_future();
        
        if (local_engine) {
            // For TITAN, we might want to ensure the specific model is loaded if not already
            // CPUInferenceEngine handles internal routing to Titan if available.
            
            local_engine->GenerateStreaming(
                local_engine->Tokenize(prompt), 
                512, // max tokens
                [&full_response](const std::string& chunk) { full_response += chunk; },
                [&done_promise]() { done_promise.set_value(); }
            );
            done_future.wait();
        } else {
             return "Error: Local Engine Failed Init";
        }
        
        return full_response;
    } else {
        if (!cloud_client) {
            initializeCloudClient();
        }
        return cloud_client->generate(prompt, bridgeToCloudConfig(config, temperature));
    }
}

void UniversalModelRouter::routeStreamQuery(const std::string& model_name, const std::string& prompt, StreamCallback callback, float temperature) {
    if (!isModelAvailable(model_name)) {
        if(callback) callback("Error: Model not found.");
        return;
    }

    ModelConfig config = getModelConfig(model_name);
    
    if (config.backend == ModelBackend::LOCAL_GGUF || config.backend == ModelBackend::LOCAL_TITAN) {
        if (!local_engine_ready || !local_engine) {
             initializeLocalEngine("");
        }
        if (local_engine) {
            local_engine->GenerateStreaming(
                local_engine->Tokenize(prompt),
                512,
                callback,
                nullptr // No completion callback usage here
            ); 
        }
    } else {
        if (!cloud_client) {
            initializeCloudClient();
        }
        cloud_client->generateStream(prompt, bridgeToCloudConfig(config, temperature), callback);
    }
}



} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
