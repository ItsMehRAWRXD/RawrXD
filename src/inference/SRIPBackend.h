//==============================================================================
// SRIPBackend.h - Phase LMM-5: SRIP Client Backend
//
// InferenceBackend implementation that connects to SRIP servers
// - Binary protocol (no HTTP overhead)
// - Streaming token support
// - Capability negotiation
// - Connection pooling
//==============================================================================

#ifndef SRIP_BACKEND_H
#define SRIP_BACKEND_H

#include "InferenceBackend.h"
#include "../net/SRIPProtocol.h"
#include <winsock2.h>

//==============================================================================
// SRIP Backend Configuration
//==============================================================================

typedef struct SRIPConfig {
    char host[128];
    int port;
    int connect_timeout_ms;
    int read_timeout_ms;
    int enable_keepalive;
    int max_retries;
} SRIPConfig;

//==============================================================================
// SRIP Backend State
//==============================================================================

typedef enum {
    SRIP_STATE_DISCONNECTED = 0,
    SRIP_STATE_CONNECTING = 1,
    SRIP_STATE_CONNECTED = 2,
    SRIP_STATE_AUTHENTICATED = 3,
    SRIP_STATE_GENERATING = 4,
    SRIP_STATE_ERROR = -1
} SRIPState;

//==============================================================================
// SRIP Backend Class
//==============================================================================

class SRIPBackend : public InferenceBackend {
public:
    SRIPBackend(const SRIPConfig* config);
    virtual ~SRIPBackend();

    // InferenceBackend interface
    virtual int Initialize(const ModelInfo* info) override;
    virtual int Generate(const InferenceRequest* req, InferenceResponse* res) override;
    virtual int GenerateStreaming(const InferenceRequest* req, 
                                   TokenCallback callback, void* user_data) override;
    virtual void Shutdown() override;
    virtual bool IsAvailable() const override;
    virtual const char* GetBackendName() const override { return "srip"; }

    // SRIP-specific
    int Connect();
    void Disconnect();
    int SendHello();
    int SendSelectModel(const char* model_id);
    int SendPrompt(const char* prompt);
    int ReceiveToken(SRIP_PayloadToken* token, int timeout_ms);
    int SendAbort();
    
    // State
    SRIPState GetState() const { return m_state; }
    const char* GetStateString() const;
    
    // Metrics
    float GetTokensPerSecond() const { return m_tokensPerSecond; }
    uint64_t GetLatencyMs() const { return m_latencyMs; }

private:
    SRIPConfig m_config;
    SRIPState m_state;
    SOCKET m_socket;
    
    // Connection
    int TryConnect();
    int SendFrame(SRIPMessageType type, const void* payload, uint32_t payload_len);
    int ReceiveFrame(SRIP_Header* hdr, void* payload, size_t payload_size, int timeout_ms);
    
    // Streaming
    int StreamTokens(TokenCallback callback, void* user_data);
    
    // Metrics
    float m_tokensPerSecond;
    uint64_t m_latencyMs;
    uint64_t m_sessionStartTime;
    uint32_t m_tokenCount;
    
    // Buffer for receiving
    uint8_t m_recvBuffer[SRIP_MAX_PAYLOAD + SRIP_HEADER_SIZE];
};

#endif // SRIP_BACKEND_H
