//==============================================================================
// SRIPBackend.cpp - Phase LMM-5: SRIP Client Backend Implementation
//==============================================================================

#include "SRIPBackend.h"
#include "../core/ExecutionJournal.h"
#include "../core/LowMemProfile.h"
#include <ws2tcpip.h>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

//==============================================================================
// Lifecycle
//==============================================================================

SRIPBackend::SRIPBackend(const SRIPConfig* config) 
    : m_state(SRIP_STATE_DISCONNECTED)
    , m_socket(INVALID_SOCKET)
    , m_tokensPerSecond(0)
    , m_latencyMs(0)
    , m_sessionStartTime(0)
    , m_tokenCount(0) {
    
    if (config) {
        m_config = *config;
    } else {
        // Default config
        strcpy(m_config.host, "localhost");
        m_config.port = SRIP_DEFAULT_PORT;
        m_config.connect_timeout_ms = 5000;
        m_config.read_timeout_ms = 30000;
        m_config.enable_keepalive = 1;
        m_config.max_retries = 3;
    }
}

SRIPBackend::~SRIPBackend() {
    Shutdown();
}

int SRIPBackend::Initialize(const ModelInfo* info) {
    (void)info;
    
    // Connect to SRIP server
    int result = Connect();
    if (result != 0) {
        Journal_LogUserRequest("SRIP backend init failed", m_config.host);
        return -1;
    }
    
    Journal_LogUserRequest("SRIP backend initialized", m_config.host);
    return 0;
}

void SRIPBackend::Shutdown() {
    if (m_socket != INVALID_SOCKET) {
        // Send goodbye
        SendFrame(SRIP_MSG_GOODBYE, NULL, 0);
        Disconnect();
    }
    
    m_state = SRIP_STATE_DISCONNECTED;
}

bool SRIPBackend::IsAvailable() const {
    return m_state == SRIP_STATE_AUTHENTICATED || m_state == SRIP_STATE_CONNECTED;
}

const char* SRIPBackend::GetStateString() const {
    switch (m_state) {
        case SRIP_STATE_DISCONNECTED: return "disconnected";
        case SRIP_STATE_CONNECTING: return "connecting";
        case SRIP_STATE_CONNECTED: return "connected";
        case SRIP_STATE_AUTHENTICATED: return "authenticated";
        case SRIP_STATE_GENERATING: return "generating";
        case SRIP_STATE_ERROR: return "error";
        default: return "unknown";
    }
}

//==============================================================================
// Connection
//==============================================================================

int SRIPBackend::Connect() {
    if (m_state != SRIP_STATE_DISCONNECTED) {
        return 0; // Already connected
    }
    
    m_state = SRIP_STATE_CONNECTING;
    
    int result = TryConnect();
    if (result != 0) {
        m_state = SRIP_STATE_ERROR;
        return -1;
    }
    
    m_state = SRIP_STATE_CONNECTED;
    
    // Send HELLO
    result = SendHello();
    if (result != 0) {
        Disconnect();
        m_state = SRIP_STATE_ERROR;
        return -1;
    }
    
    // Wait for WELCOME
    SRIP_Header hdr;
    SRIP_PayloadWelcome welcome;
    result = ReceiveFrame(&hdr, &welcome, sizeof(welcome), m_config.connect_timeout_ms);
    
    if (result != 0 || hdr.msg_type != SRIP_MSG_WELCOME) {
        Disconnect();
        m_state = SRIP_STATE_ERROR;
        return -1;
    }
    
    m_state = SRIP_STATE_AUTHENTICATED;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "SRIP connected to %s:%d", m_config.host, m_config.port);
    Journal_LogUserRequest(msg, "");
    
    return 0;
}

int SRIPBackend::TryConnect() {
    // Create socket
    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
        return -1;
    }
    
    // Set timeouts
    DWORD timeout = m_config.read_timeout_ms;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    
    // Enable keepalive
    if (m_config.enable_keepalive) {
        int keepalive = 1;
        setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
    }
    
    // Connect
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_config.port);
    inet_pton(AF_INET, m_config.host, &addr.sin_addr);
    
    uint64_t start = GetTickCount64();
    
    if (::connect(m_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return -1;
    }
    
    m_latencyMs = GetTickCount64() - start;
    
    return 0;
}

void SRIPBackend::Disconnect() {
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    m_state = SRIP_STATE_DISCONNECTED;
}

//==============================================================================
// Protocol
//==============================================================================

int SRIPBackend::SendFrame(SRIPMessageType type, const void* payload, uint32_t payload_len) {
    if (m_socket == INVALID_SOCKET) {
        return -1;
    }
    
    SRIP_Header hdr;
    SRIP_InitHeader(&hdr, type, payload_len);
    
    // Serialize header
    uint8_t frame[SRIP_HEADER_SIZE + SRIP_MAX_PAYLOAD];
    if (SRIP_SerializeHeader(&hdr, frame, sizeof(frame)) != 0) {
        return -1;
    }
    
    // Copy payload
    if (payload && payload_len > 0) {
        memcpy(frame + SRIP_HEADER_SIZE, payload, payload_len);
    }
    
    // Send
    size_t total_len = SRIP_HEADER_SIZE + payload_len;
    size_t sent = 0;
    
    while (sent < total_len) {
        int result = send(m_socket, (const char*)frame + sent, (int)(total_len - sent), 0);
        if (result == SOCKET_ERROR) {
            m_state = SRIP_STATE_ERROR;
            return -1;
        }
        sent += result;
    }
    
    return 0;
}

int SRIPBackend::ReceiveFrame(SRIP_Header* hdr, void* payload, size_t payload_size, int timeout_ms) {
    if (m_socket == INVALID_SOCKET) {
        return -1;
    }
    
    // Set timeout
    DWORD timeout = timeout_ms;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    
    // Receive header
    uint8_t header_buf[SRIP_HEADER_SIZE];
    size_t received = 0;
    
    while (received < SRIP_HEADER_SIZE) {
        int result = recv(m_socket, (char*)header_buf + received, 
                         (int)(SRIP_HEADER_SIZE - received), 0);
        if (result <= 0) {
            return -1;
        }
        received += result;
    }
    
    // Deserialize header
    if (SRIP_DeserializeHeader(header_buf, SRIP_HEADER_SIZE, hdr) != 0) {
        return -1;
    }
    
    if (SRIP_ValidateHeader(hdr) != 0) {
        return -1;
    }
    
    // Receive payload
    if (hdr->payload_length > 0) {
        if (hdr->payload_length > payload_size) {
            return -1; // Payload too large
        }
        
        received = 0;
        while (received < hdr->payload_length) {
            int result = recv(m_socket, (char*)payload + received,
                           (int)(hdr->payload_length - received), 0);
            if (result <= 0) {
                return -1;
            }
            received += result;
        }
    }
    
    return 0;
}

int SRIPBackend::SendHello() {
    SRIP_PayloadHello hello = {};
    hello.client_version = (SRIP_VERSION_MAJOR << 16) | SRIP_VERSION_MINOR;
    strcpy(hello.client_name, "RawrXD-SRIP-Client");
    
    return SendFrame(SRIP_MSG_HELLO, &hello, sizeof(hello));
}

int SRIPBackend::SendSelectModel(const char* model_id) {
    SRIP_PayloadSelectModel select = {};
    strncpy(select.model_id, model_id, sizeof(select.model_id) - 1);
    select.context_length = 4096;
    select.temperature = 0.7f;
    select.top_p = 0.9f;
    select.max_tokens = 2048;
    
    return SendFrame(SRIP_MSG_SELECT_MODEL, &select, sizeof(select));
}

int SRIPBackend::SendPrompt(const char* prompt) {
    // Calculate payload size
    size_t prompt_len = strlen(prompt);
    if (prompt_len > SRIP_MAX_TOKENS) {
        prompt_len = SRIP_MAX_TOKENS;
    }
    
    size_t payload_size = sizeof(uint32_t) + prompt_len;
    uint8_t* payload = new uint8_t[payload_size];
    
    // Write length
    *(uint32_t*)payload = (uint32_t)prompt_len;
    
    // Write prompt
    memcpy(payload + sizeof(uint32_t), prompt, prompt_len);
    
    int result = SendFrame(SRIP_MSG_PROMPT, payload, (uint32_t)payload_size);
    
    delete[] payload;
    
    return result;
}

int SRIPBackend::ReceiveToken(SRIP_PayloadToken* token, int timeout_ms) {
    SRIP_Header hdr;
    return ReceiveFrame(&hdr, token, sizeof(SRIP_PayloadToken), timeout_ms);
}

int SRIPBackend::SendAbort() {
    return SendFrame(SRIP_MSG_ABORT, NULL, 0);
}

//==============================================================================
// Inference
//==============================================================================

int SRIPBackend::Generate(const InferenceRequest* req, InferenceResponse* res) {
    if (!req || !res) {
        return -1;
    }
    
    // Ensure connected
    if (m_state != SRIP_STATE_AUTHENTICATED) {
        if (Connect() != 0) {
            return -1;
        }
    }
    
    // Select model
    if (SendSelectModel(req->model_id) != 0) {
        return -1;
    }
    
    // Send prompt
    if (SendPrompt(req->prompt) != 0) {
        return -1;
    }
    
    m_state = SRIP_STATE_GENERATING;
    m_sessionStartTime = GetTickCount64();
    m_tokenCount = 0;
    
    // Collect all tokens
    std::string full_response;
    SRIP_PayloadToken token;
    
    while (true) {
        if (ReceiveToken(&token, m_config.read_timeout_ms) != 0) {
            break;
        }
        
        if (token.is_special) {
            // Check for end token
            break;
        }
        
        full_response += token.token_text;
        m_tokenCount++;
    }
    
    // Calculate metrics
    uint64_t elapsed = GetTickCount64() - m_sessionStartTime;
    if (elapsed > 0) {
        m_tokensPerSecond = (float)m_tokenCount / (elapsed / 1000.0f);
    }
    
    // Fill response
    strncpy(res->text, full_response.c_str(), sizeof(res->text) - 1);
    res->token_count = m_tokenCount;
    res->generation_time_ms = elapsed;
    res->tokens_per_second = m_tokensPerSecond;
    
    m_state = SRIP_STATE_AUTHENTICATED;
    
    Journal_LogUserRequest("SRIP generation complete", req->model_id);
    
    return 0;
}

int SRIPBackend::GenerateStreaming(const InferenceRequest* req, 
                                    TokenCallback callback, void* user_data) {
    if (!req || !callback) {
        return -1;
    }
    
    // Ensure connected
    if (m_state != SRIP_STATE_AUTHENTICATED) {
        if (Connect() != 0) {
            return -1;
        }
    }
    
    // Select model
    if (SendSelectModel(req->model_id) != 0) {
        return -1;
    }
    
    // Send prompt
    if (SendPrompt(req->prompt) != 0) {
        return -1;
    }
    
    m_state = SRIP_STATE_GENERATING;
    m_sessionStartTime = GetTickCount64();
    m_tokenCount = 0;
    
    // Stream tokens
    SRIP_PayloadToken token;
    
    while (true) {
        if (ReceiveToken(&token, m_config.read_timeout_ms) != 0) {
            break;
        }
        
        // Call callback
        int cont = callback(token.token_text, token.logprob, user_data);
        if (!cont) {
            // Client requested abort
            SendAbort();
            break;
        }
        
        if (token.is_special) {
            break;
        }
        
        m_tokenCount++;
    }
    
    // Calculate metrics
    uint64_t elapsed = GetTickCount64() - m_sessionStartTime;
    if (elapsed > 0) {
        m_tokensPerSecond = (float)m_tokenCount / (elapsed / 1000.0f);
    }
    
    m_state = SRIP_STATE_AUTHENTICATED;
    
    Journal_LogUserRequest("SRIP streaming complete", req->model_id);
    
    return 0;
}
