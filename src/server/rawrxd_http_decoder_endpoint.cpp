// ============================================================================
// rawrxd_http_decoder_endpoint.cpp - Phase 7: HTTP Decoder Wiring
// REST API endpoint for llama_decode_internal with Epoch-RCU integration
// ============================================================================

#include "rawrxd_http_decoder_endpoint.h"
#include "llama_decode_internal.h"
#include "sovereign_transformer_forward.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

using namespace Sovereign;

// External from http server main
extern bool g_debug;

// ============================================================================
// Decode Request/Response Structures
// ============================================================================
struct DecodeRequest {
    std::vector<int32_t> tokens;
    std::vector<int32_t> positions;  // Optional, auto-generated if empty
    float temperature = 0.8f;
    float top_p = 0.95f;
    int top_k = 40;
    int max_tokens = 1;
    bool return_logits = false;
    std::string model;  // Epoch ID or model name
};

struct DecodeResponse {
    bool success = false;
    int error_code = 0;
    std::string error_message;
    std::vector<int32_t> output_tokens;
    std::vector<float> logits;  // If return_logits=true
    int tokens_used = 0;
    int tokens_generated = 0;
};

// ============================================================================
// Simple JSON Parsing (no external deps)
// ============================================================================
// Parse simple JSON: {"tokens":[1,2,3],"temperature":0.8,...}
bool ParseDecodeRequest(const char* json_str, DecodeRequest& req) {
    if (!json_str || !*json_str) return false;
    
    const char* p = json_str;
    
    // Find tokens array
    const char* tokens_key = strstr(p, "\"tokens\"");
    if (!tokens_key) return false;
    
    const char* bracket = strchr(tokens_key, '[');
    if (!bracket) return false;
    
    // Parse tokens
    bracket++;
    while (*bracket && *bracket != ']') {
        while (*bracket && (*bracket == ' ' || *bracket == '\t' || *bracket == '\n' || *bracket == '\r' || *bracket == ',')) bracket++;
        if (*bracket == ']') break;
        if (*bracket >= '0' && *bracket <= '9') {
            int32_t val = 0;
            while (*bracket >= '0' && *bracket <= '9') {
                val = val * 10 + (*bracket - '0');
                bracket++;
            }
            req.tokens.push_back(val);
        }
        bracket++;
    }
    
    if (req.tokens.empty()) return false;
    
    // Optional: positions array
    const char* pos_key = strstr(p, "\"positions\"");
    if (pos_key) {
        const char* pos_bracket = strchr(pos_key, '[');
        if (pos_bracket) {
            pos_bracket++;
            while (*pos_bracket && *pos_bracket != ']') {
                while (*pos_bracket && (*pos_bracket == ' ' || *pos_bracket == '\t' || *pos_bracket == '\n' || *pos_bracket == '\r' || *pos_bracket == ',')) pos_bracket++;
                if (*pos_bracket == ']') break;
                if (*pos_bracket >= '0' && *pos_bracket <= '9') {
                    int32_t val = 0;
                    while (*pos_bracket >= '0' && *pos_bracket <= '9') {
                        val = val * 10 + (*pos_bracket - '0');
                        pos_bracket++;
                    }
                    req.positions.push_back(val);
                }
                pos_bracket++;
            }
        }
    }
    
    // Optional: temperature
    const char* temp_key = strstr(p, "\"temperature\"");
    if (temp_key) {
        const char* colon = strchr(temp_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            req.temperature = (float)atof(colon);
        }
    }
    
    // Optional: top_p
    const char* topp_key = strstr(p, "\"top_p\"");
    if (topp_key) {
        const char* colon = strchr(topp_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            req.top_p = (float)atof(colon);
        }
    }
    
    // Optional: top_k
    const char* topk_key = strstr(p, "\"top_k\"");
    if (topk_key) {
        const char* colon = strchr(topk_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            req.top_k = atoi(colon);
        }
    }
    
    // Optional: max_tokens
    const char* maxtok_key = strstr(p, "\"max_tokens\"");
    if (maxtok_key) {
        const char* colon = strchr(maxtok_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            req.max_tokens = atoi(colon);
        }
    }
    
    // Optional: return_logits
    const char* logits_key = strstr(p, "\"return_logits\"");
    if (logits_key) {
        const char* colon = strchr(logits_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            if (strncmp(colon, "true", 4) == 0) req.return_logits = true;
        }
    }
    
    // Optional: model
    const char* model_key = strstr(p, "\"model\"");
    if (model_key) {
        const char* colon = strchr(model_key, ':');
        if (colon) {
            colon++;
            while (*colon && (*colon == ' ' || *colon == '\t')) colon++;
            if (*colon == '\"') {
                colon++;
                const char* end = strchr(colon, '\"');
                if (end) {
                    req.model.assign(colon, end - colon);
                }
            }
        }
    }
    
    return true;
}

// ============================================================================
// Epoch-RCU Model Resolution
// ============================================================================
// Get model weights for the requested epoch/model
// Returns nullptr if no model available
ModelWeights* GetModelForEpoch(const std::string& epoch_id) {
    // TODO: Integrate with Epoch-RCU router
    // For now, return the global model if available
    extern ModelWeights* g_current_model;
    return g_current_model;
}

// Global model pointer (set by hotpatch system)
ModelWeights* g_current_model = nullptr;

// ============================================================================
// Decode Execution
// ============================================================================
DecodeResponse ExecuteDecode(const DecodeRequest& req) {
    DecodeResponse resp;
    
    // Get model for requested epoch
    ModelWeights* model = GetModelForEpoch(req.model);
    if (!model) {
        resp.error_code = -1;
        resp.error_message = "No model loaded";
        return resp;
    }
    
    // Initialize KV cache if needed
    static KVCache* kv_cache = nullptr;
    if (!kv_cache) {
        kv_cache = new KVCache();
        if (!kv_cache->Initialize(model->n_layers, model->seq_len, 
                                   model->n_kv_heads, model->head_dim)) {
            resp.error_code = -2;
            resp.error_message = "Failed to initialize KV cache";
            return resp;
        }
    }
    
    // Initialize context
    static llama_context* ctx = nullptr;
    if (!ctx) {
        ctx = new llama_context();
        if (!ctx->init(model, kv_cache)) {
            resp.error_code = -3;
            resp.error_message = "Failed to initialize context";
            return resp;
        }
    }
    
    // Prepare positions (auto-generate if not provided)
    std::vector<int32_t> positions;
    if (req.positions.empty()) {
        int start_pos = ctx->seq_pos;
        for (size_t i = 0; i < req.tokens.size(); i++) {
            positions.push_back(start_pos + i);
        }
    } else {
        positions = req.positions;
    }
    
    // Validate token count matches position count
    if (req.tokens.size() != positions.size()) {
        resp.error_code = -4;
        resp.error_message = "Token count mismatch with position count";
        return resp;
    }
    
    // Create batch (cast away const - llama_batch modifies token pointer internally)
    llama_batch batch = llama_batch::init(
        static_cast<int32_t>(req.tokens.size()),
        const_cast<int32_t*>(req.tokens.data()),
        positions.data()
    );
    
    // Run decode
    int result = llama_decode_internal(ctx, batch);
    if (result != 0) {
        resp.error_code = result;
        resp.error_message = "Decode failed";
        return resp;
    }
    
    resp.tokens_used = static_cast<int>(req.tokens.size());
    
    // Get logits if requested
    if (req.return_logits) {
        float* logits = llama_get_logits(ctx);
        if (logits && model->vocab_size > 0) {
            resp.logits.resize(model->vocab_size);
            memcpy(resp.logits.data(), logits, model->vocab_size * sizeof(float));
        }
    }
    
    // Sample tokens if max_tokens > 0
    for (int i = 0; i < req.max_tokens; i++) {
        int32_t token = llama_sample_token(ctx, req.temperature, req.top_p, req.top_k);
        resp.output_tokens.push_back(token);
        resp.tokens_generated++;
        
        // Continue generation with sampled token
        if (i < req.max_tokens - 1) {
            llama_batch next_batch = llama_batch::single(token, ctx->seq_pos);
            int next_result = llama_decode_internal(ctx, next_batch);
            if (next_result != 0) break;
        }
    }
    
    resp.success = true;
    return resp;
}

// ============================================================================
// JSON Response Serialization (manual, no deps)
// ============================================================================
std::string SerializeDecodeResponse(const DecodeResponse& resp) {
    char buffer[4096];
    int pos = 0;
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "{");
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\"success\":%s,", resp.success ? "true" : "false");
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\"tokens_used\":%d,", resp.tokens_used);
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\"tokens_generated\":%d", resp.tokens_generated);
    
    if (resp.success) {
        // Output tokens array
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\"output_tokens\":[");
        for (size_t i = 0; i < resp.output_tokens.size(); i++) {
            if (i > 0) pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",");
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%d", resp.output_tokens[i]);
        }
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "]");
        
        // Optional logits
        if (!resp.logits.empty()) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\"logits\":[");
            for (size_t i = 0; i < resp.logits.size() && i < 100; i++) {  // Limit to 100
                if (i > 0) pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",");
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%.6f", resp.logits[i]);
            }
            if (resp.logits.size() > 100) {
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",...");
            }
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "]");
        }
    } else {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\"error_code\":%d", resp.error_code);
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",\"error_message\":\"");
        // Escape quotes in error message
        for (char c : resp.error_message) {
            if (c == '"' || c == '\\') {
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\\");
            }
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%c", c);
        }
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\"");
    }
    
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "}");
    return std::string(buffer);
}

// ============================================================================
// HTTP Handler
// ============================================================================
void HandleDecodeEndpoint(SOCKET client, const char* body) {
    DecodeRequest req;
    
    if (!ParseDecodeRequest(body, req)) {
        const char* error_json = "{\"success\":false,\"error_code\":-10,\"error_message\":\"Invalid JSON or missing tokens\"}";
        SendJsonResponse(client, 400, error_json);
        return;
    }
    
    if (g_debug) {
        printf("[Decode] Processing %zu tokens, model=%s\n", 
               req.tokens.size(), req.model.c_str());
    }
    
    DecodeResponse resp = ExecuteDecode(req);
    std::string json_response = SerializeDecodeResponse(resp);
    
    int status = resp.success ? 200 : 500;
    SendJsonResponse(client, status, json_response.c_str());
}

// Helper to send JSON response
void SendJsonResponse(SOCKET client, int status, const char* json) {
    char response[8192];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, (status == 200) ? "OK" : "Error",
        strlen(json), json);
    send(client, response, len, 0);
}

// ============================================================================
// Epoch-RCU Integration
// ============================================================================
void SetCurrentModel(ModelWeights* model) {
    g_current_model = model;
    if (g_debug) printf("[Decode] Model updated: %p\n", (void*)model);
}

ModelWeights* GetCurrentModel() {
    return g_current_model;
}
