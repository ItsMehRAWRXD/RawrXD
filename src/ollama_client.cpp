#include "ollama_client.h"
#include "json_parse_guard.hpp"
#include "json_sanitizer.hpp"
#include "json_schema_validator.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Backend {

using json = nlohmann::json;
using JSONGuard = JSON::JSONParseGuard;
using JSONSanitizer = JSON::JSONSanitizer;
using JSONValidator = JSON::JSONSchemaValidator;
using JSONRecovery = JSON::JSONParseRecovery;

// CURL callback for writing response data
size_t curlWriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((const char*)contents, size * nmemb);
    return size * nmemb;
}

// CURL callback for streaming response data
size_t curlStreamCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* callback_data = static_cast<std::tuple<StreamCallback, ErrorCallback, CompletionCallback>*>(userp);
    auto& [on_chunk, on_error, on_complete] = *callback_data;
    
    std::string chunk((const char*)contents, size * nmemb);
    
    // Use hardened parse guard with sanitization
    json j = JSONGuard::SafeParseStreamChunk(chunk, [on_error](const std::string& err) {
        if (on_error) {
            on_error(err);
        }
    });
    
    if (j.is_null() || j.empty()) {
        // Parsing failed, skip this chunk
        return size * nmemb;
    }
    
    try {
        if (j.contains("response")) {
            std::string response_chunk = j["response"];
            if (on_chunk) {
                on_chunk(response_chunk);
            }
        }
        
        if (j.contains("done") && j["done"].get<bool>()) {
            OllamaResponse final_response;
            final_response.done = true;
            final_response.model = j.value("model", "");
            final_response.total_duration = j.value("total_duration", 0ULL);
            final_response.prompt_eval_count = j.value("prompt_eval_count", 0ULL);
            final_response.eval_count = j.value("eval_count", 0ULL);
            final_response.load_duration = j.value("load_duration", 0ULL);
            final_response.prompt_eval_duration = j.value("prompt_eval_duration", 0ULL);
            final_response.eval_duration = j.value("eval_duration", 0ULL);
            
            if (on_complete) {
                on_complete(final_response);
            }
        }
    } catch (const std::exception& e) {
        if (on_error) {
            on_error(std::string("Response field extraction error: ") + e.what());
        }
    }
    
    return size * nmemb;
}

OllamaClient::OllamaClient(const std::string& base_url)
    : m_base_url(base_url) {
}

OllamaClient::~OllamaClient() {
}

void OllamaClient::setBaseUrl(const std::string& url) {
    m_base_url = url;
}

bool OllamaClient::testConnection() {
    std::string response = makeGetRequest("/api/tags");
    return !response.empty();
}

std::string OllamaClient::getVersion() {
    std::string response = makeGetRequest("/api/version");
    if (response.empty()) return "";
    
    json j = JSONGuard::SafeParse(response);
    if (j.empty() || !j.is_object()) return "";
    
    return JSONValidator::GetStringField(j, "version", "");
}

bool OllamaClient::isRunning() {
    return testConnection();
}

std::vector<OllamaModel> OllamaClient::listModels() {
    std::string response = makeGetRequest("/api/tags");
    if (response.empty()) return {};
    
    return parseModels(response);
}

std::vector<OllamaModel> OllamaClient::filterModels(
    const std::vector<OllamaModel>& models,
    std::function<bool(const OllamaModel&)> predicate) const {
    
    std::vector<OllamaModel> filtered;
    for (const auto& model : models) {
        if (predicate(model)) {
            filtered.push_back(model);
        }
    }
    return filtered;
}

const OllamaModel* OllamaClient::findModelById(
    const std::vector<OllamaModel>& models,
    const std::string& targetId) const {
    
    for (const auto& model : models) {
        if (model.id == targetId) {
            return &model;
        }
    }
    return nullptr;
}

OllamaResponse OllamaClient::generateSync(const OllamaGenerateRequest& request) {
    std::string json_body = createGenerateRequestJson(request);
    std::string response = makePostRequest("/api/generate", json_body);
    
    if (response.empty()) {
        OllamaResponse res;
        res.error = true;
        res.error_message = "Empty response from server";
        return res;
    }
    
    return parseResponse(response);
}

OllamaResponse OllamaClient::chatSync(const OllamaChatRequest& request) {
    std::string json_body = createChatRequestJson(request);
    std::string response = makePostRequest("/api/chat", json_body);
    
    if (response.empty()) {
        OllamaResponse res;
        res.error = true;
        res.error_message = "Empty response from server";
        return res;
    }
    
    return parseResponse(response);
}

bool OllamaClient::generate(const OllamaGenerateRequest& request,
                            StreamCallback on_chunk,
                            ErrorCallback on_error,
                            CompletionCallback on_complete) {
    std::string json_body = createGenerateRequestJson(request);
    return makeStreamingPostRequest("/api/generate", json_body, on_chunk, on_error, on_complete);
}

bool OllamaClient::chat(const OllamaChatRequest& request,
                        StreamCallback on_chunk,
                        ErrorCallback on_error,
                        CompletionCallback on_complete) {
    std::string json_body = createChatRequestJson(request);
    return makeStreamingPostRequest("/api/chat", json_body, on_chunk, on_error, on_complete);
}

std::vector<float> OllamaClient::embeddings(const std::string& model, const std::string& prompt) {
    json request_json = {
        {"model", model},
        {"prompt", prompt}
    };
    
    std::string json_body = request_json.dump();
    std::string response = makePostRequest("/api/embeddings", json_body);
    
    if (response.empty()) return {};
    
    // Use hardened parser
    json j = JSONGuard::SafeParse(response);
    if (j.empty() || !j.is_object()) {
        return {};
    }
    
    try {
        json embedding_field = JSONValidator::GetArrayField(j, "embedding");
        if (!embedding_field.empty() && embedding_field.is_array()) {
            return embedding_field.get<std::vector<float>>();
        }
    } catch (const std::exception& e) {
        // Silently return empty vector if conversion fails
        (void)e;
    }
    
    return {};
}

std::string OllamaClient::createGenerateRequestJson(const OllamaGenerateRequest& req) {
    json j = {
        {"model", req.model},
        {"prompt", req.prompt},
        {"stream", req.stream}
    };
    
    if (!req.options.empty()) {
        json options = json::object();
        for (const auto& [key, value] : req.options) {
            options[key] = value;
        }
        j["options"] = options;
    }
    
    return j.dump();
}

std::string OllamaClient::createChatRequestJson(const OllamaChatRequest& req) {
    json j = {
        {"model", req.model},
        {"stream", req.stream},
        {"messages", json::array()}
    };
    
    for (const auto& msg : req.messages) {
        j["messages"].push_back({
            {"role", msg.role},
            {"content", msg.content}
        });
    }
    
    if (!req.options.empty()) {
        json options = json::object();
        for (const auto& [key, value] : req.options) {
            options[key] = value;
        }
        j["options"] = options;
    }
    
    return j.dump();
}

OllamaResponse OllamaClient::parseResponse(const std::string& json_str) {
    OllamaResponse response;
    
    // ===== LAYER 1: Sanitization =====
    std::string sanitized = JSONSanitizer::Sanitize(json_str);
    
    if (sanitized.empty()) {
        response.error = true;
        response.error_message = "Response sanitized to empty (likely malformed input)";
        return response;
    }
    
    // ===== LAYER 2: Safe Parse =====
    std::string parse_error;
    json j = JSONGuard::SafeParse(sanitized,
        [&parse_error](const std::string& err) {
            parse_error = err;
        });
    
    if (j.empty() || !j.is_object()) {
        response.error = true;
        response.error_message = "Failed to parse response JSON. Original error: " + parse_error;
        // Log the problematic output for debugging
        if (json_str.length() < 500) {
            response.error_message += ". Raw input: " + json_str;
        }
        return response;
    }
    
    // ===== LAYER 3: Safe Field Extraction =====
    try {
        response.model = JSONValidator::GetStringField(j, "model", "");
        response.response = JSONValidator::GetStringField(j, "response", "");
        response.done = j.value("done", false);
        
        if (j.contains("message") && j["message"].is_object()) {
            response.message.role = JSONValidator::GetStringField(j["message"], "role", "");
            response.message.content = JSONValidator::GetStringField(j["message"], "content", "");
        }
        
        response.total_duration = j.value("total_duration", 0ULL);
        response.prompt_eval_count = j.value("prompt_eval_count", 0ULL);
        response.eval_count = j.value("eval_count", 0ULL);
        response.load_duration = j.value("load_duration", 0ULL);
        response.prompt_eval_duration = j.value("prompt_eval_duration", 0ULL);
        response.eval_duration = j.value("eval_duration", 0ULL);
        
        response.error = false;
    } catch (const std::exception& e) {
        response.error = true;
        response.error_message = std::string("Field extraction error: ") + e.what();
    }
    
    return response;
}

std::vector<OllamaModel> OllamaClient::parseModels(const std::string& json_str) {
    std::vector<OllamaModel> models;
    
    // Sanitize and parse safely
    std::string sanitized = JSONSanitizer::Sanitize(json_str);
    if (sanitized.empty()) {
        return models;  // Return empty vector on failure
    }
    
    json j = JSONGuard::SafeParse(sanitized, [](const std::string& err) {
        // Could log here; for now, silent failure to callers
        (void)err;
    });
    
    if (j.empty() || !j.is_object()) {
        return models;  // Invalid or empty response
    }
    
    try {
        json models_array = JSONValidator::GetArrayField(j, "models");
        
        for (const auto& model_json : models_array) {
            if (!model_json.is_object()) {
                continue;  // Skip malformed entries
            }
            
            OllamaModel model;
            model.name = JSONValidator::GetStringField(model_json, "name", "");
            
            // Skip entries with empty names
            if (model.name.empty()) {
                continue;
            }
            
            model.id = model.name;  // Use name as ID
            model.size = model_json.value("size", 0ULL);
            model.digest = JSONValidator::GetStringField(model_json, "digest", "");
            model.modified_at = JSONValidator::GetStringField(model_json, "modified_at", "");
            
            // Parse details if available
            json details = JSONValidator::GetObjectField(model_json, "details");
            if (!details.empty()) {
                model.format = JSONValidator::GetStringField(details, "format", "");
                model.family = JSONValidator::GetStringField(details, "family", "");
                model.parameter_size = JSONValidator::GetStringField(details, "parameter_size", "");
                model.quantization_level = JSONValidator::GetStringField(details, "quantization_level", "");
            }
            
            models.push_back(model);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing models (recovered): " << e.what() << std::endl;
        // Return partial results on error
    }
    
    return models;
}

std::string OllamaClient::makeGetRequest(const std::string& endpoint) {
    (void)endpoint;
    return {};
}

std::string OllamaClient::makePostRequest(const std::string& endpoint, const std::string& json_body) {
    (void)endpoint;
    (void)json_body;
    return {};
}

bool OllamaClient::makeStreamingPostRequest(const std::string& endpoint,
                                           const std::string& json_body,
                                           StreamCallback on_chunk,
                                           ErrorCallback on_error,
                                           CompletionCallback on_complete) {
    (void)endpoint;
    (void)json_body;
    (void)on_chunk;
    (void)on_complete;
    if (on_error) {
        on_error("HTTP backend unavailable: built without libcurl support.");
    }
    return false;
}

} // namespace Backend
} // namespace RawrXD
