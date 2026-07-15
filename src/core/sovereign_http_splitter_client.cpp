// ============================================================================
// sovereign_http_splitter_client.cpp - Phase 8: HTTP Splitter Client
// Batch splitter integration with HTTP decoder endpoint
// ============================================================================

#include "sovereign_http_splitter_client.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

namespace Sovereign {

// ============================================================================
// Global Client Instance
// ============================================================================
static HTTPSplitterClient* g_splitter_client = nullptr;

HTTPSplitterClient* GetGlobalSplitterClient() {
    return g_splitter_client;
}

void SetGlobalSplitterClient(HTTPSplitterClient* client) {
    g_splitter_client = client;
}

// Convenience function for single decode
SplitterDecodeResponse HttpDecode(const std::vector<int32_t>& tokens, 
                                   const std::vector<int32_t>& positions,
                                   int max_tokens) {
    HTTPSplitterClient* client = GetGlobalSplitterClient();
    if (!client || !client->IsInitialized()) {
        SplitterDecodeResponse resp;
        resp.error_code = -1;
        resp.error_message = "Splitter client not initialized";
        return resp;
    }
    
    SplitterDecodeRequest req;
    req.tokens = tokens;
    req.positions = positions;
    req.max_tokens = max_tokens;
    return client->Decode(req);
}

// ============================================================================
// Constructor/Destructor
// ============================================================================
HTTPSplitterClient::HTTPSplitterClient() 
    : initialized_(false), socket_(INVALID_SOCKET) {
    InitializeCriticalSection(&cs_);
}

HTTPSplitterClient::~HTTPSplitterClient() {
    Shutdown();
    DeleteCriticalSection(&cs_);
}

// ============================================================================
// Initialization
// ============================================================================
bool HTTPSplitterClient::Initialize(const SplitterClientConfig& config) {
    if (initialized_) {
        return true;  // Already initialized
    }
    
    config_ = config;
    
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        if (config_.debug) {
            printf("[SplitterClient] WSAStartup failed: %d\n", result);
        }
        return false;
    }
    
    initialized_ = true;
    
    if (config_.debug) {
        printf("[SplitterClient] Initialized for %s:%d%s\n", 
               config_.host.c_str(), config_.port, config_.endpoint.c_str());
    }
    
    // Set as global client
    SetGlobalSplitterClient(this);
    
    return true;
}

void HTTPSplitterClient::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    Disconnect();
    WSACleanup();
    initialized_ = false;
    
    if (g_splitter_client == this) {
        g_splitter_client = nullptr;
    }
    
    if (config_.debug) {
        printf("[SplitterClient] Shutdown complete\n");
    }
}

// ============================================================================
// Connection Management
// ============================================================================
bool HTTPSplitterClient::Connect() {
    EnterCriticalSection(&cs_);
    
    if (socket_ != INVALID_SOCKET) {
        LeaveCriticalSection(&cs_);
        return true;  // Already connected
    }
    
    // Create socket
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        if (config_.debug) {
            printf("[SplitterClient] Socket creation failed: %d\n", WSAGetLastError());
        }
        LeaveCriticalSection(&cs_);
        return false;
    }
    
    // Set timeout
    DWORD timeout = config_.timeout_ms;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    
    // Resolve host
    struct hostent* host = gethostbyname(config_.host.c_str());
    if (!host) {
        if (config_.debug) {
            printf("[SplitterClient] Failed to resolve host: %s\n", config_.host.c_str());
        }
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        LeaveCriticalSection(&cs_);
        return false;
    }
    
    // Connect
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(config_.port);
    memcpy(&serverAddr.sin_addr, host->h_addr, host->h_length);
    
    int result = connect(socket_, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        if (config_.debug) {
            printf("[SplitterClient] Connect failed: %d\n", WSAGetLastError());
        }
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        LeaveCriticalSection(&cs_);
        return false;
    }
    
    LeaveCriticalSection(&cs_);
    
    if (config_.debug) {
        printf("[SplitterClient] Connected to %s:%d\n", config_.host.c_str(), config_.port);
    }
    
    return true;
}

void HTTPSplitterClient::Disconnect() {
    EnterCriticalSection(&cs_);
    
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    
    LeaveCriticalSection(&cs_);
}

// ============================================================================
// HTTP Request Building
// ============================================================================
std::string HTTPSplitterClient::BuildHttpRequest(const SplitterDecodeRequest& request) {
    // Build JSON body manually
    char body[4096];
    int pos = 0;
    
    pos += snprintf(body + pos, sizeof(body) - pos, "{");
    
    // Tokens array (required)
    pos += snprintf(body + pos, sizeof(body) - pos, "\"tokens\":[");
    for (size_t i = 0; i < request.tokens.size(); i++) {
        if (i > 0) pos += snprintf(body + pos, sizeof(body) - pos, ",");
        pos += snprintf(body + pos, sizeof(body) - pos, "%d", request.tokens[i]);
    }
    pos += snprintf(body + pos, sizeof(body) - pos, "]");
    
    // Positions array (optional)
    if (!request.positions.empty()) {
        pos += snprintf(body + pos, sizeof(body) - pos, ",\"positions\":[");
        for (size_t i = 0; i < request.positions.size(); i++) {
            if (i > 0) pos += snprintf(body + pos, sizeof(body) - pos, ",");
            pos += snprintf(body + pos, sizeof(body) - pos, "%d", request.positions[i]);
        }
        pos += snprintf(body + pos, sizeof(body) - pos, "]");
    }
    
    // Optional parameters
    pos += snprintf(body + pos, sizeof(body) - pos, ",\"temperature\":%.3f", request.temperature);
    pos += snprintf(body + pos, sizeof(body) - pos, ",\"top_p\":%.3f", request.top_p);
    pos += snprintf(body + pos, sizeof(body) - pos, ",\"top_k\":%d", request.top_k);
    pos += snprintf(body + pos, sizeof(body) - pos, ",\"max_tokens\":%d", request.max_tokens);
    
    if (request.return_logits) {
        pos += snprintf(body + pos, sizeof(body) - pos, ",\"return_logits\":true");
    }
    
    if (!request.model.empty()) {
        pos += snprintf(body + pos, sizeof(body) - pos, ",\"model\":\"%s\"", request.model.c_str());
    }
    
    pos += snprintf(body + pos, sizeof(body) - pos, "}");
    
    // Build HTTP request
    char http_request[8192];
    snprintf(http_request, sizeof(http_request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        config_.endpoint.c_str(),
        config_.host.c_str(),
        config_.port,
        strlen(body),
        body);
    
    return std::string(http_request);
}

// ============================================================================
// HTTP Response Parsing
// ============================================================================
SplitterDecodeResponse HTTPSplitterClient::ParseHttpResponse(const std::string& response) {
    SplitterDecodeResponse resp;
    
    // Find HTTP status line
    size_t status_pos = response.find("HTTP/1.1 ");
    if (status_pos == std::string::npos) {
        status_pos = response.find("HTTP/1.0 ");
    }
    
    if (status_pos != std::string::npos) {
        // Parse status code
        int status_code = atoi(response.c_str() + status_pos + 9);
        resp.http_status = status_code;
        
        if (status_code != 200) {
            resp.error_code = -status_code;
            resp.error_message = "HTTP error";
            return resp;
        }
    }
    
    // Find body (after \r\n\r\n)
    size_t body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        resp.error_code = -2;
        resp.error_message = "Invalid HTTP response (no body)";
        return resp;
    }
    body_start += 4;
    
    std::string body = response.substr(body_start);
    
    // Parse JSON response manually
    // Look for "success":true/false
    if (body.find("\"success\":true") != std::string::npos) {
        resp.success = true;
    } else if (body.find("\"success\":false") != std::string::npos) {
        resp.success = false;
    }
    
    // Parse tokens_used
    size_t used_pos = body.find("\"tokens_used\":");
    if (used_pos != std::string::npos) {
        resp.tokens_used = atoi(body.c_str() + used_pos + 14);
    }
    
    // Parse tokens_generated
    size_t gen_pos = body.find("\"tokens_generated\":");
    if (gen_pos != std::string::npos) {
        resp.tokens_generated = atoi(body.c_str() + gen_pos + 18);
    }
    
    // Parse output_tokens array
    size_t tokens_pos = body.find("\"output_tokens\":[");
    if (tokens_pos != std::string::npos) {
        tokens_pos += 17;  // Skip past the key
        const char* p = body.c_str() + tokens_pos;
        while (*p && *p != ']') {
            while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '[' || *p == ',')) p++;
            if (*p == ']') break;
            if (*p >= '0' && *p <= '9') {
                int32_t val = 0;
                while (*p >= '0' && *p <= '9') {
                    val = val * 10 + (*p - '0');
                    p++;
                }
                resp.output_tokens.push_back(val);
            }
            p++;
        }
    }
    
    // Parse error_code if present
    size_t err_pos = body.find("\"error_code\":");
    if (err_pos != std::string::npos) {
        resp.error_code = atoi(body.c_str() + err_pos + 13);
    }
    
    // Parse error_message if present
    size_t msg_pos = body.find("\"error_message\":\"");
    if (msg_pos != std::string::npos) {
        msg_pos += 17;
        size_t msg_end = body.find("\"", msg_pos);
        if (msg_end != std::string::npos) {
            resp.error_message = body.substr(msg_pos, msg_end - msg_pos);
        }
    }
    
    return resp;
}

// ============================================================================
// HTTP Request Sending
// ============================================================================
std::string HTTPSplitterClient::SendHttpRequest(const std::string& request) {
    if (!Connect()) {
        return "";
    }
    
    EnterCriticalSection(&cs_);
    
    // Send request
    int sent = send(socket_, request.c_str(), (int)request.length(), 0);
    if (sent == SOCKET_ERROR) {
        if (config_.debug) {
            printf("[SplitterClient] Send failed: %d\n", WSAGetLastError());
        }
        LeaveCriticalSection(&cs_);
        Disconnect();
        return "";
    }
    
    // Receive response
    char buffer[8192];
    std::string response;
    int received;
    
    do {
        received = recv(socket_, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            response += buffer;
        }
    } while (received > 0);
    
    LeaveCriticalSection(&cs_);
    
    if (received == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && config_.debug) {
            printf("[SplitterClient] Receive failed: %d\n", error);
        }
        // Don't disconnect on timeout - connection may still be valid
    }
    
    return response;
}

// ============================================================================
// Decode Operations
// ============================================================================
SplitterDecodeResponse HTTPSplitterClient::Decode(const SplitterDecodeRequest& request) {
    SplitterDecodeResponse resp;
    
    if (!initialized_) {
        resp.error_code = -1;
        resp.error_message = "Client not initialized";
        return resp;
    }
    
    // Build and send request
    std::string http_request = BuildHttpRequest(request);
    
    // Retry logic
    for (int retry = 0; retry < config_.max_retries; retry++) {
        if (retry > 0 && config_.debug) {
            printf("[SplitterClient] Retry %d/%d\n", retry, config_.max_retries);
        }
        
        std::string http_response = SendHttpRequest(http_request);
        
        if (!http_response.empty()) {
            resp = ParseHttpResponse(http_response);
            if (resp.success || resp.http_status == 200) {
                return resp;
            }
        }
        
        // Disconnect and retry
        Disconnect();
    }
    
    resp.error_code = -3;
    resp.error_message = "Max retries exceeded";
    return resp;
}

std::vector<SplitterDecodeResponse> HTTPSplitterClient::DecodeBatch(
    const std::vector<SplitterDecodeRequest>& requests) {
    std::vector<SplitterDecodeResponse> responses;
    responses.reserve(requests.size());
    
    for (const auto& req : requests) {
        responses.push_back(Decode(req));
    }
    
    return responses;
}

// ============================================================================
// Health Check
// ============================================================================
bool HTTPSplitterClient::HealthCheck() {
    if (!initialized_) {
        return false;
    }
    
    // Build health check request
    char request[512];
    snprintf(request, sizeof(request),
        "GET /health HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n"
        "\r\n",
        config_.host.c_str(), config_.port);
    
    std::string response = SendHttpRequest(request);
    
    // Check for 200 OK and status:ok
    return (response.find("200 OK") != std::string::npos && 
            response.find("\"status\":\"ok\"") != std::string::npos);
}

} // namespace Sovereign
