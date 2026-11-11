//=============================================================================
// MCP_Transport_Native.h
// RawrXD IDE - Model Context Protocol Native Transport C Interface
//
// C/C++ header for MASM x64 MCP transport implementation
// Provides JSON-RPC 2.0, SSE streaming, and OAuth 2.0 with PKCE
//=============================================================================

#pragma once

#include <windows.h>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Constants
//=============================================================================

#define MCP_VERSION_MAJOR           2025
#define MCP_VERSION_MINOR           11
#define MCP_VERSION_PATCH           25

// Transport states
#define MCP_STATE_DISCONNECTED      0
#define MCP_STATE_CONNECTING        1
#define MCP_STATE_CONNECTED         2
#define MCP_STATE_AUTHORIZING       3
#define MCP_STATE_AUTHORIZED        4
#define MCP_STATE_ERROR             5
#define MCP_STATE_RECONNECTING      6

// HTTP methods
#define MCP_HTTP_GET                0
#define MCP_HTTP_POST               1
#define MCP_HTTP_DELETE             2

// Buffer sizes
#define MCP_MAX_URL_LENGTH          2048
#define MCP_MAX_HEADER_SIZE         8192
#define MCP_MAX_BODY_SIZE           1048576     // 1MB
#define MCP_SSE_BUFFER_SIZE         65536       // 64KB
#define MCP_JSONRPC_ID_MAX          4294967295

// Timeouts (milliseconds)
#define MCP_DEFAULT_TIMEOUT         30000       // 30 seconds
#define MCP_SSE_KEEPALIVE_MS        15000       // 15 seconds
#define MCP_RECONNECT_DELAY_MS      5000        // 5 seconds
#define MCP_MAX_RECONNECT_ATTEMPTS  5

// OAuth 2.0 constants
#define MCP_PKCE_VERIFIER_LENGTH    128
#define MCP_STATE_PARAM_LENGTH      64

// Callback types
#define MCP_CALLBACK_MESSAGE        0
#define MCP_CALLBACK_ERROR          1
#define MCP_CALLBACK_CONNECT        2
#define MCP_CALLBACK_DISCONNECT     3
#define MCP_CALLBACK_SSE            4

// Error codes
#define MCP_ERROR_NONE              0
#define MCP_ERROR_OUT_OF_MEMORY     1
#define MCP_ERROR_INVALID_STATE     2
#define MCP_ERROR_CONNECTION_FAILED 3
#define MCP_ERROR_AUTH_FAILED       4
#define MCP_ERROR_REQUEST_TIMEOUT   5
#define MCP_ERROR_INVALID_RESPONSE  6
#define MCP_ERROR_SSE_DISCONNECT    7

//=============================================================================
// Opaque Handle
//=============================================================================

typedef struct MCP_TRANSPORT_CTX* HMCPTransport;

//=============================================================================
// Callback Types
//=============================================================================

// Message received callback
// Called when a JSON-RPC response is received
// Parameters:
//   pUserData - User data pointer from transport creation
//   pMessage - JSON response body (UTF-8, null-terminated)
//   dwMessageLength - Length of message in bytes
//   dwRequestId - JSON-RPC request ID
// Returns: TRUE to continue, FALSE to abort
typedef BOOL (CALLBACK *MCP_OnMessageCallback)(
    void* pUserData,
    const char* pMessage,
    DWORD dwMessageLength,
    DWORD dwRequestId
);

// Error callback
// Called when a transport error occurs
// Parameters:
//   pUserData - User data pointer
//   dwErrorCode - MCP_ERROR_* code
//   pErrorMessage - Human-readable error description
//   dwErrorMessageLength - Length of error message
// Returns: TRUE to attempt reconnect, FALSE to propagate error
typedef BOOL (CALLBACK *MCP_OnErrorCallback)(
    void* pUserData,
    DWORD dwErrorCode,
    const char* pErrorMessage,
    DWORD dwErrorMessageLength
);

// Connection state callbacks
// Parameters:
//   pUserData - User data pointer
//   pServerUrl - Server URL connected to
// Returns: void
typedef void (CALLBACK *MCP_OnConnectCallback)(
    void* pUserData,
    const wchar_t* pServerUrl
);

typedef void (CALLBACK *MCP_OnDisconnectCallback)(
    void* pUserData,
    DWORD dwReason
);

// SSE event callback
// Called for each Server-Sent Event received
// Parameters:
//   pUserData - User data pointer
//   pwszEventType - Event type (message, error, etc.)
//   pwszEventId - Event ID for replay
//   pData - Event data
//   dwDataLength - Data length
//   dwRetryMs - Retry timing hint
// Returns: TRUE to continue, FALSE to unsubscribe
typedef BOOL (CALLBACK *MCP_OnSSEEventCallback)(
    void* pUserData,
    const wchar_t* pwszEventType,
    const wchar_t* pwszEventId,
    const char* pData,
    DWORD dwDataLength,
    DWORD dwRetryMs
);

//=============================================================================
// Transport Lifecycle
//=============================================================================

/// Creates a new MCP transport context
/// 
/// @param pwszServerUrl - Base server URL (e.g., L"https://api.example.com")
/// @param pUserData - User data pointer passed to all callbacks
/// @return Transport handle or NULL on failure
HMCPTransport MCP_Transport_Create(
    const wchar_t* pwszServerUrl,
    void* pUserData
);

/// Destroys an MCP transport context and frees all resources
/// 
/// @param hTransport - Transport handle
void MCP_Transport_Destroy(
    HMCPTransport hTransport
);

//=============================================================================
// Connection Management
//=============================================================================

/// Establishes connection to MCP server
/// 
/// @param hTransport - Transport handle
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_Connect(
    HMCPTransport hTransport
);

/// Closes connection to MCP server
/// 
/// @param hTransport - Transport handle
void MCP_Transport_Disconnect(
    HMCPTransport hTransport
);

/// Gets current transport state
/// 
/// @param hTransport - Transport handle
/// @return One of MCP_STATE_* constants
DWORD MCP_Transport_GetSessionState(
    HMCPTransport hTransport
);

/// Gets last error code
/// 
/// @param hTransport - Transport handle
/// @return Last MCP_ERROR_* code
DWORD MCP_Transport_GetLastError(
    HMCPTransport hTransport
);

//=============================================================================
// JSON-RPC Request/Response
//=============================================================================

/// Sends a JSON-RPC request and waits for response
/// 
/// @param hTransport - Transport handle
/// @param pRequestBody - JSON request body (UTF-8)
/// @param dwRequestLength - Length of request body
/// @param ppResponseBuffer - Receives pointer to response buffer (caller must free with HeapFree)
/// @param pdwResponseLength - Receives response length
/// @param dwTimeoutMs - Timeout in milliseconds (0 for default)
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_SendRequest(
    HMCPTransport hTransport,
    const char* pRequestBody,
    DWORD dwRequestLength,
    char** ppResponseBuffer,
    DWORD* pdwResponseLength,
    DWORD dwTimeoutMs
);

/// Sends a JSON-RPC notification (fire-and-forget)
/// 
/// @param hTransport - Transport handle
/// @param pNotificationBody - JSON notification body (UTF-8)
/// @param dwNotificationLength - Length of notification body
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_SendNotification(
    HMCPTransport hTransport,
    const char* pNotificationBody,
    DWORD dwNotificationLength
);

//=============================================================================
// Server-Sent Events (SSE)
//=============================================================================

/// Starts Server-Sent Events subscription
/// 
/// @param hTransport - Transport handle
/// @param pwszEndpoint - SSE endpoint path (e.g., L"/v1/sse")
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_SubscribeSSE(
    HMCPTransport hTransport,
    const wchar_t* pwszEndpoint
);

/// Stops SSE subscription
/// 
/// @param hTransport - Transport handle
void MCP_Transport_UnsubscribeSSE(
    HMCPTransport hTransport
);

/// Checks if SSE is currently subscribed
/// 
/// @param hTransport - Transport handle
/// @return TRUE if subscribed, FALSE otherwise
BOOL MCP_Transport_IsSSESubscribed(
    HMCPTransport hTransport
);

//=============================================================================
// OAuth 2.0 Authorization with PKCE
//=============================================================================

/// Performs OAuth 2.0 authorization with PKCE
/// 
/// @param hTransport - Transport handle
/// @param pwszAuthEndpoint - Authorization endpoint URL
/// @param pwszTokenEndpoint - Token endpoint URL
/// @param pwszClientId - OAuth client ID
/// @param pwszScopes - Space-separated scopes
/// @param pwszRedirectUri - Redirect URI
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_Authorize(
    HMCPTransport hTransport,
    const wchar_t* pwszAuthEndpoint,
    const wchar_t* pwszTokenEndpoint,
    const wchar_t* pwszClientId,
    const wchar_t* pwszScopes,
    const wchar_t* pwszRedirectUri
);

/// Refreshes OAuth access token using refresh token
/// 
/// @param hTransport - Transport handle
/// @return TRUE on success, FALSE on failure
BOOL MCP_Transport_RefreshToken(
    HMCPTransport hTransport
);

/// Gets current access token
/// 
/// @param hTransport - Transport handle
/// @param pwszTokenBuffer - Buffer to receive token
/// @param pdwBufferSize - On input: buffer size in WCHARs, on output: required size
/// @return TRUE on success, FALSE if buffer too small
BOOL MCP_Transport_GetAccessToken(
    HMCPTransport hTransport,
    wchar_t* pwszTokenBuffer,
    DWORD* pdwBufferSize
);

/// Checks if token is expired
/// 
/// @param hTransport - Transport handle
/// @return TRUE if expired or no token, FALSE if valid
BOOL MCP_Transport_IsTokenExpired(
    HMCPTransport hTransport
);

//=============================================================================
// Callback Registration
//=============================================================================

/// Sets a callback function
/// 
/// @param hTransport - Transport handle
/// @param dwCallbackType - One of MCP_CALLBACK_* constants
/// @param pfnCallback - Callback function pointer
/// @return TRUE on success, FALSE on invalid callback type
BOOL MCP_Transport_SetCallback(
    HMCPTransport hTransport,
    DWORD dwCallbackType,
    void* pfnCallback
);

//=============================================================================
// Configuration
//=============================================================================

/// Sets request timeout
/// 
/// @param hTransport - Transport handle
/// @param dwTimeoutMs - Timeout in milliseconds
void MCP_Transport_SetTimeout(
    HMCPTransport hTransport,
    DWORD dwTimeoutMs
);

/// Enables/disables SSE streaming
/// 
/// @param hTransport - Transport handle
/// @param bEnable - TRUE to enable SSE, FALSE to disable
void MCP_Transport_EnableSSE(
    HMCPTransport hTransport,
    BOOL bEnable
);

/// Sets maximum reconnection attempts
/// 
/// @param hTransport - Transport handle
/// @param dwMaxAttempts - Maximum attempts (0 for unlimited)
void MCP_Transport_SetMaxReconnectAttempts(
    HMCPTransport hTransport,
    DWORD dwMaxAttempts
);

//=============================================================================
// Utility Functions
//=============================================================================

/// Generates a JSON-RPC request with auto-incrementing ID
/// 
/// @param pwszMethod - Method name
/// @param pParamsJson - Parameters as JSON object or array
/// @param ppRequestBuffer - Receives allocated request buffer
/// @param pdwRequestLength - Receives request length
/// @return TRUE on success, FALSE on failure
BOOL MCP_Util_BuildJsonRpcRequest(
    const wchar_t* pwszMethod,
    const char* pParamsJson,
    char** ppRequestBuffer,
    DWORD* pdwRequestLength
);

/// Parses a JSON-RPC response
/// 
/// @param pResponse - Response buffer
/// @param dwResponseLength - Response length
/// @param pdwRequestId - Receives request ID
/// @param ppResultJson - Receives pointer to result (NULL if error)
/// @param ppErrorJson - Receives pointer to error (NULL if success)
/// @return TRUE on success, FALSE on parse error
BOOL MCP_Util_ParseJsonRpcResponse(
    const char* pResponse,
    DWORD dwResponseLength,
    DWORD* pdwRequestId,
    const char** ppResultJson,
    const char** ppErrorJson
);

/// URL-encodes a string
/// 
/// @param pwszInput - Input string
/// @param pwszOutput - Output buffer
/// @param dwOutputSize - Output buffer size in WCHARs
/// @return TRUE on success, FALSE if buffer too small
BOOL MCP_Util_UrlEncode(
    const wchar_t* pwszInput,
    wchar_t* pwszOutput,
    DWORD dwOutputSize
);

/// Base64URL encodes data (RFC 4648)
/// 
/// @param pInput - Input data
/// @param dwInputLength - Input length
/// @param pszOutput - Output buffer
/// @param pdwOutputSize - On input: buffer size, on output: required size
/// @return TRUE on success, FALSE if buffer too small
BOOL MCP_Util_Base64UrlEncode(
    const BYTE* pInput,
    DWORD dwInputLength,
    char* pszOutput,
    DWORD* pdwOutputSize
);

/// Generates PKCE code verifier
/// 
/// @param pszVerifier - Output buffer (must be at least MCP_PKCE_VERIFIER_LENGTH * 4/3 + 1)
/// @param dwVerifierSize - Buffer size
/// @return TRUE on success, FALSE on failure
BOOL MCP_Util_GeneratePKCEVerifier(
    char* pszVerifier,
    DWORD dwVerifierSize
);

/// Generates PKCE code challenge from verifier
/// 
/// @param pszVerifier - Verifier string
/// @param pszChallenge - Output buffer
/// @param dwChallengeSize - Buffer size
/// @return TRUE on success, FALSE on failure
BOOL MCP_Util_GeneratePKCEChallenge(
    const char* pszVerifier,
    char* pszChallenge,
    DWORD dwChallengeSize
);

#ifdef __cplusplus
}
#endif

//=============================================================================
// C++ Wrapper Class (Optional)
//=============================================================================

#ifdef __cplusplus

namespace RawrXD {
namespace MCP {

/// C++ wrapper for MCP transport
class Transport {
public:
    Transport(const std::wstring& serverUrl);
    ~Transport();

    // Non-copyable
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    // Movable
    Transport(Transport&& other) noexcept;
    Transport& operator=(Transport&& other) noexcept;

    // Connection
    bool Connect();
    void Disconnect();
    bool IsConnected() const;
    DWORD GetState() const;

    // JSON-RPC
    std::optional<std::string> SendRequest(
        const std::string& method,
        const nlohmann::json& params,
        DWORD timeoutMs = MCP_DEFAULT_TIMEOUT
    );
    bool SendNotification(const std::string& method, const nlohmann::json& params);

    // SSE
    bool SubscribeSSE(const std::wstring& endpoint);
    void UnsubscribeSSE();
    bool IsSSESubscribed() const;

    // OAuth 2.0
    bool Authorize(
        const std::wstring& authEndpoint,
        const std::wstring& tokenEndpoint,
        const std::wstring& clientId,
        const std::wstring& scopes,
        const std::wstring& redirectUri
    );
    bool RefreshToken();
    bool IsTokenExpired() const;

    // Callbacks
    void SetOnMessage(std::function<void(const nlohmann::json&, DWORD)> callback);
    void SetOnError(std::function<bool(DWORD, const std::string&)> callback);
    void SetOnConnect(std::function<void(const std::wstring&)> callback);
    void SetOnDisconnect(std::function<void(DWORD)> callback);
    void SetOnSSEEvent(std::function<bool(const std::wstring&, const std::wstring&, const std::string&)> callback);

private:
    HMCPTransport m_hTransport;
    void* m_pUserData;

    // Callback storage
    std::function<void(const nlohmann::json&, DWORD)> m_onMessage;
    std::function<bool(DWORD, const std::string&)> m_onError;
    std::function<void(const std::wstring&)> m_onConnect;
    std::function<void(DWORD)> m_onDisconnect;
    std::function<bool(const std::wstring&, const std::wstring&, const std::string&)> m_onSSEEvent;

    // Static trampolines
    static BOOL CALLBACK OnMessageTrampoline(void* pUserData, const char* pMessage, DWORD dwLength, DWORD dwId);
    static BOOL CALLBACK OnErrorTrampoline(void* pUserData, DWORD dwError, const char* pMsg, DWORD dwLen);
    static void CALLBACK OnConnectTrampoline(void* pUserData, const wchar_t* pUrl);
    static void CALLBACK OnDisconnectTrampoline(void* pUserData, DWORD dwReason);
    static BOOL CALLBACK OnSSEEventTrampoline(void* pUserData, const wchar_t* pType, const wchar_t* pId, const char* pData, DWORD dwLen, DWORD dwRetry);
};

} // namespace MCP
} // namespace RawrXD

#endif // __cplusplus
