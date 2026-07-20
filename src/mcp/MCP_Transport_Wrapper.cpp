//=============================================================================
// MCP_Transport_Wrapper.cpp
// RawrXD IDE - Model Context Protocol C++ Wrapper Implementation
//=============================================================================

#include "MCP_Transport_Native.h"
#include <nlohmann/json.hpp>
#include <string>

#ifdef __cplusplus

namespace RawrXD {
namespace MCP {

//=============================================================================
// Transport Implementation
//=============================================================================

Transport::Transport(const std::wstring& serverUrl)
    : m_hTransport(nullptr)
    , m_pUserData(this)
{
    m_hTransport = MCP_Transport_Create(serverUrl.c_str(), m_pUserData);
}

Transport::~Transport()
{
    if (m_hTransport) {
        MCP_Transport_Destroy(m_hTransport);
        m_hTransport = nullptr;
    }
}

Transport::Transport(Transport&& other) noexcept
    : m_hTransport(other.m_hTransport)
    , m_pUserData(other.m_pUserData)
    , m_onMessage(std::move(other.m_onMessage))
    , m_onError(std::move(other.m_onError))
    , m_onConnect(std::move(other.m_onConnect))
    , m_onDisconnect(std::move(other.m_onDisconnect))
    , m_onSSEEvent(std::move(other.m_onSSEEvent))
{
    other.m_hTransport = nullptr;
    other.m_pUserData = nullptr;
}

Transport& Transport::operator=(Transport&& other) noexcept
{
    if (this != &other) {
        if (m_hTransport) {
            MCP_Transport_Destroy(m_hTransport);
        }
        
        m_hTransport = other.m_hTransport;
        m_pUserData = other.m_pUserData;
        m_onMessage = std::move(other.m_onMessage);
        m_onError = std::move(other.m_onError);
        m_onConnect = std::move(other.m_onConnect);
        m_onDisconnect = std::move(other.m_onDisconnect);
        m_onSSEEvent = std::move(other.m_onSSEEvent);
        
        other.m_hTransport = nullptr;
        other.m_pUserData = nullptr;
    }
    return *this;
}

bool Transport::Connect()
{
    if (!m_hTransport) return false;
    return MCP_Transport_Connect(m_hTransport) != FALSE;
}

void Transport::Disconnect()
{
    if (m_hTransport) {
        MCP_Transport_Disconnect(m_hTransport);
    }
}

bool Transport::IsConnected() const
{
    if (!m_hTransport) return false;
    DWORD state = MCP_Transport_GetSessionState(m_hTransport);
    return state == MCP_STATE_CONNECTED || state == MCP_STATE_AUTHORIZED;
}

DWORD Transport::GetState() const
{
    if (!m_hTransport) return MCP_STATE_DISCONNECTED;
    return MCP_Transport_GetSessionState(m_hTransport);
}

std::optional<std::string> Transport::SendRequest(
    const std::string& method,
    const nlohmann::json& params,
    DWORD timeoutMs)
{
    if (!m_hTransport) return std::nullopt;
    
    // Build JSON-RPC request
    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", method},
        {"params", params},
        {"id", 0}  // ID will be assigned by native layer
    };
    
    std::string requestBody = request.dump();
    
    char* pResponse = nullptr;
    DWORD responseLength = 0;
    
    BOOL result = MCP_Transport_SendRequest(
        m_hTransport,
        requestBody.c_str(),
        static_cast<DWORD>(requestBody.length()),
        &pResponse,
        &responseLength,
        timeoutMs
    );
    
    if (!result || !pResponse) {
        return std::nullopt;
    }
    
    std::string response(pResponse, responseLength);
    
    // Free response buffer
    HANDLE hHeap = GetProcessHeap();
    HeapFree(hHeap, 0, pResponse);
    
    // Parse response
    try {
        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.contains("error")) {
            return std::nullopt;  // JSON-RPC error
        }
        if (jsonResponse.contains("result")) {
            return jsonResponse["result"].dump();
        }
        return response;
    } catch (...) {
        return response;  // Return raw if parse fails
    }
}

bool Transport::SendNotification(const std::string& method, const nlohmann::json& params)
{
    if (!m_hTransport) return false;
    
    nlohmann::json notification = {
        {"jsonrpc", "2.0"},
        {"method", method},
        {"params", params}
    };
    
    std::string body = notification.dump();
    
    return MCP_Transport_SendNotification(
        m_hTransport,
        body.c_str(),
        static_cast<DWORD>(body.length())
    ) != FALSE;
}

bool Transport::SubscribeSSE(const std::wstring& endpoint)
{
    if (!m_hTransport) return false;
    return MCP_Transport_SubscribeSSE(m_hTransport, endpoint.c_str()) != FALSE;
}

void Transport::UnsubscribeSSE()
{
    if (m_hTransport) {
        MCP_Transport_UnsubscribeSSE(m_hTransport);
    }
}

bool Transport::IsSSESubscribed() const
{
    if (!m_hTransport) return false;
    return MCP_Transport_IsSSESubscribed(m_hTransport) != FALSE;
}

bool Transport::Authorize(
    const std::wstring& authEndpoint,
    const std::wstring& tokenEndpoint,
    const std::wstring& clientId,
    const std::wstring& scopes,
    const std::wstring& redirectUri)
{
    if (!m_hTransport) return false;
    return MCP_Transport_Authorize(
        m_hTransport,
        authEndpoint.c_str(),
        tokenEndpoint.c_str(),
        clientId.c_str(),
        scopes.c_str(),
        redirectUri.c_str()
    ) != FALSE;
}

bool Transport::RefreshToken()
{
    if (!m_hTransport) return false;
    return MCP_Transport_RefreshToken(m_hTransport) != FALSE;
}

bool Transport::IsTokenExpired() const
{
    if (!m_hTransport) return true;
    return MCP_Transport_IsTokenExpired(m_hTransport) != FALSE;
}

//=============================================================================
// Callback Setters
//=============================================================================

void Transport::SetOnMessage(std::function<void(const nlohmann::json&, DWORD)> callback)
{
    m_onMessage = std::move(callback);
    if (m_hTransport) {
        MCP_Transport_SetCallback(
            m_hTransport,
            MCP_CALLBACK_MESSAGE,
            m_onMessage ? OnMessageTrampoline : nullptr
        );
    }
}

void Transport::SetOnError(std::function<bool(DWORD, const std::string&)> callback)
{
    m_onError = std::move(callback);
    if (m_hTransport) {
        MCP_Transport_SetCallback(
            m_hTransport,
            MCP_CALLBACK_ERROR,
            m_onError ? OnErrorTrampoline : nullptr
        );
    }
}

void Transport::SetOnConnect(std::function<void(const std::wstring&)> callback)
{
    m_onConnect = std::move(callback);
    if (m_hTransport) {
        MCP_Transport_SetCallback(
            m_hTransport,
            MCP_CALLBACK_CONNECT,
            m_onConnect ? OnConnectTrampoline : nullptr
        );
    }
}

void Transport::SetOnDisconnect(std::function<void(DWORD)> callback)
{
    m_onDisconnect = std::move(callback);
    if (m_hTransport) {
        MCP_Transport_SetCallback(
            m_hTransport,
            MCP_CALLBACK_DISCONNECT,
            m_onDisconnect ? OnDisconnectTrampoline : nullptr
        );
    }
}

void Transport::SetOnSSEEvent(std::function<bool(const std::wstring&, const std::wstring&, const std::string&)> callback)
{
    m_onSSEEvent = std::move(callback);
    if (m_hTransport) {
        MCP_Transport_SetCallback(
            m_hTransport,
            MCP_CALLBACK_SSE,
            m_onSSEEvent ? OnSSEEventTrampoline : nullptr
        );
    }
}

//=============================================================================
// Static Callback Trampolines
//=============================================================================

BOOL CALLBACK Transport::OnMessageTrampoline(
    void* pUserData,
    const char* pMessage,
    DWORD dwLength,
    DWORD dwId)
{
    auto* pTransport = static_cast<Transport*>(pUserData);
    if (pTransport && pTransport->m_onMessage) {
        try {
            auto json = nlohmann::json::parse(pMessage, pMessage + dwLength);
            pTransport->m_onMessage(json, dwId);
        } catch (...) {
            // Parse error - call with null
            pTransport->m_onMessage(nlohmann::json(), dwId);
        }
    }
    return TRUE;
}

BOOL CALLBACK Transport::OnErrorTrampoline(
    void* pUserData,
    DWORD dwError,
    const char* pMsg,
    DWORD dwLen)
{
    auto* pTransport = static_cast<Transport*>(pUserData);
    if (pTransport && pTransport->m_onError) {
        std::string msg(pMsg, dwLen);
        return pTransport->m_onError(dwError, msg) ? TRUE : FALSE;
    }
    return FALSE;  // Don't reconnect by default
}

void CALLBACK Transport::OnConnectTrampoline(
    void* pUserData,
    const wchar_t* pUrl)
{
    auto* pTransport = static_cast<Transport*>(pUserData);
    if (pTransport && pTransport->m_onConnect) {
        pTransport->m_onConnect(pUrl);
    }
}

void CALLBACK Transport::OnDisconnectTrampoline(
    void* pUserData,
    DWORD dwReason)
{
    auto* pTransport = static_cast<Transport*>(pUserData);
    if (pTransport && pTransport->m_onDisconnect) {
        pTransport->m_onDisconnect(dwReason);
    }
}

BOOL CALLBACK Transport::OnSSEEventTrampoline(
    void* pUserData,
    const wchar_t* pType,
    const wchar_t* pId,
    const char* pData,
    DWORD dwLen,
    DWORD /*dwRetry*/)
{
    auto* pTransport = static_cast<Transport*>(pUserData);
    if (pTransport && pTransport->m_onSSEEvent) {
        std::string data(pData, dwLen);
        return pTransport->m_onSSEEvent(pType, pId, data) ? TRUE : FALSE;
    }
    return TRUE;
}

} // namespace MCP
} // namespace RawrXD

#endif // __cplusplus
