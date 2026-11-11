/*=============================================================================
 * AwsBedrockClient.h — Native Win32 AWS Bedrock Client
 *
 * Connects to AWS Bedrock Runtime using WinSock + Schannel (native TLS).
 * No external dependencies — no libcurl, no OpenSSL, no Python.
 *
 * Architecture:
 *   - Non-blocking WinSock TCP socket
 *   - Schannel SSPI for TLS 1.2/1.3
 *   - Manual HTTP/1.1 request construction with SigV4 signing
 *   - Streaming response chunk parsing
 *
 * Threading: Designed for use from a dedicated worker thread.
 *            All state is per-instance (not global).
 *===========================================================================*/

#pragma once
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <schannel.h>
#include <security.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * CONSTANTS
 *===========================================================================*/

#define AWS_BEDROCK_MAX_RESPONSE     (512 * 1024)  // 512KB max response
#define AWS_BEDROCK_DEFAULT_PORT     443
#define AWS_BEDROCK_TIMEOUT_MS       30000
#define AWS_BEDROCK_BUFFER_SIZE      16384

/*=============================================================================
 * CALLBACK TYPES
 *===========================================================================*/

/**
 * @brief Callback invoked when a chunk of streaming response is received
 * @param context   User-provided context pointer
 * @param data      Pointer to response chunk data
 * @param dataLen   Length of the chunk
 * @param isFinal   TRUE if this is the last chunk
 */
typedef void (CALLBACK* AwsBedrockStreamCallback)(void* context, const char* data, size_t dataLen, BOOL isFinal);

/**
 * @brief Callback invoked when a tool_use block is detected
 * @param context   User-provided context pointer
 * @param toolName  Name of the tool to execute
 * @param toolInput JSON string of tool arguments
 */
typedef void (CALLBACK* AwsBedrockToolCallback)(void* context, const char* toolName, const char* toolInput);

/*=============================================================================
 * CLIENT STATE
 *============================================================================*/

typedef struct {
    // Connection state
    SOCKET              socket;
    BOOL                connected;
    BOOL                tlsEstablished;
    
    // Credential context (Schannel)
    CredHandle          schannelCred;
    CtxtHandle          schannelCtx;
    SecBufferDesc       schannelOutBuffer;
    SecBuffer           schannelOutSecBuf[1];
    
    // Host info
    char                host[256];
    int                 port;
    
    // Response buffer
    char*               responseBuffer;
    size_t              responseCapacity;
    size_t              responseLength;
    
    // Callbacks
    AwsBedrockStreamCallback streamCallback;
    AwsBedrockToolCallback   toolCallback;
    void*               callbackContext;
    
    // Error state
    char                lastError[512];
    int                 lastWinSockError;
    
    // Internal
    BOOL                initialized;
} AwsBedrockClient;

/*=============================================================================
 * API FUNCTIONS
 *============================================================================*/

/**
 * @brief Initialize the Bedrock client
 * @param client    Client structure to initialize
 * @return TRUE on success
 */
BOOL AwsBedrockClient_Init(AwsBedrockClient* client);

/**
 * @brief Set callbacks for streaming and tool use
 */
void AwsBedrockClient_SetCallbacks(
    AwsBedrockClient* client,
    AwsBedrockStreamCallback streamCb,
    AwsBedrockToolCallback toolCb,
    void* context
);

/**
 * @brief Connect to the Bedrock endpoint
 * @param client    Initialized client
 * @param host      Hostname (e.g., "bedrock-runtime.us-east-1.amazonaws.com")
 * @param port      Port (usually 443)
 * @return TRUE on success
 */
BOOL AwsBedrockClient_Connect(AwsBedrockClient* client, const char* host, int port);

/**
 * @brief Send a signed HTTP POST request to Bedrock
 *
 * Constructs the full HTTP/1.1 request with the provided Authorization header
 * and body, sends it over the TLS connection, and reads the response.
 *
 * @param client            Connected client
 * @param authorization     The full Authorization header (from SigV4)
 * @param xAmzDate          The X-Amz-Date header value
 * @param xAmzTarget        The X-Amz-Target header value
 * @param contentType       The Content-Type header value
 * @param body              The JSON request body
 * @param bodyLen           Length of the body
 * @return TRUE on success (response is in client->responseBuffer)
 */
BOOL AwsBedrockClient_SendRequest(
    AwsBedrockClient* client,
    const char* authorization,
    const char* xAmzDate,
    const char* xAmzTarget,
    const char* contentType,
    const char* body,
    size_t bodyLen
);

/**
 * @brief Get the response buffer (valid after successful SendRequest)
 * @return Pointer to null-terminated response string
 */
const char* AwsBedrockClient_GetResponse(AwsBedrockClient* client);

/**
 * @brief Disconnect and clean up
 */
void AwsBedrockClient_Disconnect(AwsBedrockClient* client);

/**
 * @brief Get the last error message
 */
const char* AwsBedrockClient_GetLastError(AwsBedrockClient* client);

#ifdef __cplusplus
}
#endif
