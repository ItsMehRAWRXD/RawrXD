//==============================================================================
// SRIPProtocol.h - Phase LMM-5: Sovereign Remote Inference Protocol
//
// Binary protocol for remote inference:
// - Fixed-size headers for fast parsing
// - Minimal overhead (no JSON, no HTTP)
// - Streaming token support
// - Capability negotiation
// - Request multiplexing
//==============================================================================

#ifndef SRIP_PROTOCOL_H
#define SRIP_PROTOCOL_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Protocol Constants
//==============================================================================

#define SRIP_MAGIC          0x53524950  // "SRIP" in ASCII
#define SRIP_VERSION_MAJOR  1
#define SRIP_VERSION_MINOR  0
#define SRIP_DEFAULT_PORT   8080
#define SRIP_MAX_MODELS     64
#define SRIP_MAX_TOKENS     32768
#define SRIP_MAX_PAYLOAD    (1024 * 1024)  // 1MB max payload

//==============================================================================
// Message Types
//==============================================================================

typedef enum {
    // Connection
    SRIP_MSG_HELLO = 0x01,      // Client -> Server: initiate session
    SRIP_MSG_WELCOME = 0x02,    // Server -> Client: session accepted
    SRIP_MSG_GOODBYE = 0x03,    // Either: close session
    
    // Capability negotiation
    SRIP_MSG_CAPABILITIES = 0x10,  // Server -> Client: available models/features
    SRIP_MSG_SELECT_MODEL = 0x11,  // Client -> Server: choose model
    
    // Inference
    SRIP_MSG_PROMPT = 0x20,     // Client -> Server: send prompt
    SRIP_MSG_TOKEN = 0x21,      // Server -> Client: generated token
    SRIP_MSG_COMPLETE = 0x22,   // Server -> Client: generation done
    SRIP_MSG_ABORT = 0x23,      // Client -> Server: stop generation
    
    // Metrics
    SRIP_MSG_METRICS = 0x30,    // Server -> Client: performance stats
    
    // Errors
    SRIP_MSG_ERROR = 0x40       // Either: error occurred
} SRIPMessageType;

//==============================================================================
// Error Codes
//==============================================================================

typedef enum {
    SRIP_ERR_NONE = 0,
    SRIP_ERR_UNKNOWN_MSG = 1,
    SRIP_ERR_INVALID_VERSION = 2,
    SRIP_ERR_MODEL_NOT_FOUND = 3,
    SRIP_ERR_MODEL_BUSY = 4,
    SRIP_ERR_OUT_OF_MEMORY = 5,
    SRIP_ERR_TIMEOUT = 6,
    SRIP_ERR_INVALID_PROMPT = 7,
    SRIP_ERR_SERVER_ERROR = 8
} SRIPErrorCode;

//==============================================================================
// Protocol Header
//==============================================================================

#pragma pack(push, 1)

typedef struct SRIP_Header {
    uint32_t magic;             // SRIP_MAGIC
    uint16_t version_major;     // SRIP_VERSION_MAJOR
    uint16_t version_minor;     // SRIP_VERSION_MINOR
    uint16_t msg_type;          // SRIPMessageType
    uint32_t payload_length;    // Length of payload following header
    uint32_t request_id;        // Unique request identifier
    uint32_t flags;             // Protocol flags
} SRIP_Header;

#pragma pack(pop)

#define SRIP_HEADER_SIZE sizeof(SRIP_Header)

//==============================================================================
// Payload Structures
//==============================================================================

// HELLO payload
#pragma pack(push, 1)
typedef struct SRIP_PayloadHello {
    uint32_t client_version;
    char client_name[64];
} SRIP_PayloadHello;

// WELCOME payload
typedef struct SRIP_PayloadWelcome {
    uint32_t server_version;
    uint32_t session_id;
    uint32_t max_context;
    uint32_t max_tokens;
} SRIP_PayloadWelcome;

// CAPABILITIES payload
typedef struct SRIP_ModelInfo {
    char id[64];
    char name[128];
    char quantization[16];
    uint64_t parameter_count;
    uint32_t context_length;
    uint32_t capabilities;
} SRIP_ModelInfo;

typedef struct SRIP_PayloadCapabilities {
    uint32_t model_count;
    SRIP_ModelInfo models[SRIP_MAX_MODELS];
} SRIP_PayloadCapabilities;

// SELECT_MODEL payload
typedef struct SRIP_PayloadSelectModel {
    char model_id[64];
    uint32_t context_length;
    float temperature;
    float top_p;
    uint32_t max_tokens;
} SRIP_PayloadSelectModel;

// PROMPT payload
typedef struct SRIP_PayloadPrompt {
    uint32_t prompt_length;
    char prompt_text[SRIP_MAX_TOKENS];  // Variable length
} SRIP_PayloadPrompt;

// TOKEN payload
typedef struct SRIP_PayloadToken {
    uint32_t token_id;
    char token_text[256];       // UTF-8 token text
    float logprob;
    uint32_t is_special;        // 1 if special token (EOS, etc.)
} SRIP_PayloadToken;

// COMPLETE payload
typedef struct SRIP_PayloadComplete {
    uint32_t token_count;
    uint64_t generation_time_ms;
    float tokens_per_second;
} SRIP_PayloadComplete;

// METRICS payload
typedef struct SRIP_PayloadMetrics {
    float tokens_per_second;
    uint64_t memory_used_mb;
    uint64_t memory_total_mb;
    uint32_t queue_depth;
} SRIP_PayloadMetrics;

// ERROR payload
typedef struct SRIP_PayloadError {
    uint32_t error_code;
    char error_message[256];
} SRIP_PayloadError;

#pragma pack(pop)

//==============================================================================
// Protocol Functions
//==============================================================================

// Initialize header with defaults
void SRIP_InitHeader(SRIP_Header* hdr, SRIPMessageType type, uint32_t payload_len);

// Validate header
int SRIP_ValidateHeader(const SRIP_Header* hdr);

// Serialize header to buffer
int SRIP_SerializeHeader(const SRIP_Header* hdr, uint8_t* buf, size_t buf_size);

// Deserialize header from buffer
int SRIP_DeserializeHeader(const uint8_t* buf, size_t buf_size, SRIP_Header* hdr);

// Calculate total message size
static inline size_t SRIP_MessageSize(const SRIP_Header* hdr) {
    return SRIP_HEADER_SIZE + hdr->payload_length;
}

// Get message type name
const char* SRIP_MessageTypeName(SRIPMessageType type);

// Get error code name
const char* SRIP_ErrorCodeName(SRIPErrorCode code);

//==============================================================================
// Utility
//==============================================================================

// Generate unique request ID
uint32_t SRIP_GenerateRequestId(void);

// Format header for debugging
void SRIP_FormatHeader(const SRIP_Header* hdr, char* out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif // SRIP_PROTOCOL_H
