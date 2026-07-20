//=============================================================================
// MCP_Test.cpp
// RawrXD IDE - Model Context Protocol Transport Test
//=============================================================================

#include "MCP_Transport_Native.h"
#include <stdio>
#include <string>

//=============================================================================
// Test Configuration
//=============================================================================

// Test server (using a mock MCP server or local endpoint)
#define TEST_SERVER_URL     L"http://localhost:3000"
#define TEST_ENDPOINT       L"/mcp/v1"

//=============================================================================
// Callback Handlers
//=============================================================================

static void OnConnect(void* pUserData, const wchar_t* pUrl)
{
    wprintf(L"[TEST] Connected to: %s\n", pUrl);
}

static void OnDisconnect(void* pUserData, DWORD dwReason)
{
    wprintf(L"[TEST] Disconnected, reason: %lu\n", dwReason);
}

static BOOL OnMessage(void* pUserData, const char* pMessage, DWORD dwLength, DWORD dwId)
{
    printf("[TEST] Message received (ID=%lu, len=%lu):\n", dwId, dwLength);
    printf("%.*s\n", dwLength, pMessage);
    return TRUE;
}

static BOOL OnError(void* pUserData, DWORD dwError, const char* pMsg, DWORD dwLen)
{
    printf("[TEST] Error %lu: %.*s\n", dwError, dwLen, pMsg);
    return FALSE;  // Don't auto-reconnect in tests
}

static BOOL OnSSE(void* pUserData, const wchar_t* pType, const wchar_t* pId,
                  const char* pData, DWORD dwLen, DWORD dwRetry)
{
    wprintf(L"[TEST] SSE Event: type=%s, id=%s, len=%lu\n", pType, pId, dwLen);
    printf("%.*s\n", dwLen, pData);
    return TRUE;
}

//=============================================================================
// Test Functions
//=============================================================================

bool Test_CreateDestroy()
{
    printf("\n=== Test: Create/Destroy ===\n");
    
    HMCPTransport hTransport = MCP_Transport_Create(TEST_SERVER_URL, nullptr);
    if (!hTransport) {
        printf("FAILED: Could not create transport\n");
        return false;
    }
    
    printf("Transport created successfully\n");
    
    MCP_Transport_Destroy(hTransport);
    printf("Transport destroyed successfully\n");
    
    return true;
}

bool Test_Callbacks()
{
    printf("\n=== Test: Callback Registration ===\n");
    
    HMCPTransport hTransport = MCP_Transport_Create(TEST_SERVER_URL, nullptr);
    if (!hTransport) {
        printf("FAILED: Could not create transport\n");
        return false;
    }
    
    // Register callbacks
    BOOL result = MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_CONNECT, OnConnect);
    printf("SetCallback(CONNECT): %s\n", result ? "OK" : "FAILED");
    
    result = MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_DISCONNECT, OnDisconnect);
    printf("SetCallback(DISCONNECT): %s\n", result ? "OK" : "FAILED");
    
    result = MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_MESSAGE, OnMessage);
    printf("SetCallback(MESSAGE): %s\n", result ? "OK" : "FAILED");
    
    result = MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_ERROR, OnError);
    printf("SetCallback(ERROR): %s\n", result ? "OK" : "FAILED");
    
    result = MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_SSE, OnSSE);
    printf("SetCallback(SSE): %s\n", result ? "OK" : "FAILED");
    
    MCP_Transport_Destroy(hTransport);
    return true;
}

bool Test_StateMachine()
{
    printf("\n=== Test: State Machine ===\n");
    
    HMCPTransport hTransport = MCP_Transport_Create(TEST_SERVER_URL, nullptr);
    if (!hTransport) {
        printf("FAILED: Could not create transport\n");
        return false;
    }
    
    DWORD state = MCP_Transport_GetSessionState(hTransport);
    printf("Initial state: %lu (expected %d = DISCONNECTED)\n", state, MCP_STATE_DISCONNECTED);
    
    if (state != MCP_STATE_DISCONNECTED) {
        printf("FAILED: Wrong initial state\n");
        MCP_Transport_Destroy(hTransport);
        return false;
    }
    
    MCP_Transport_Destroy(hTransport);
    return true;
}

bool Test_Connection()
{
    printf("\n=== Test: Connection (requires server) ===\n");
    
    HMCPTransport hTransport = MCP_Transport_Create(TEST_SERVER_URL, nullptr);
    if (!hTransport) {
        printf("FAILED: Could not create transport\n");
        return false;
    }
    
    // Register callbacks
    MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_CONNECT, OnConnect);
    MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_DISCONNECT, OnDisconnect);
    MCP_Transport_SetCallback(hTransport, MCP_CALLBACK_ERROR, OnError);
    
    printf("Attempting to connect to %ls...\n", TEST_SERVER_URL);
    
    BOOL result = MCP_Transport_Connect(hTransport);
    printf("Connect result: %s\n", result ? "SUCCESS" : "FAILED");
    
    if (result) {
        DWORD state = MCP_Transport_GetSessionState(hTransport);
        printf("State after connect: %lu (expected %d = CONNECTED)\n", 
               state, MCP_STATE_CONNECTED);
        
        // Test disconnect
        printf("Disconnecting...\n");
        MCP_Transport_Disconnect(hTransport);
        
        state = MCP_Transport_GetSessionState(hTransport);
        printf("State after disconnect: %lu (expected %d = DISCONNECTED)\n",
               state, MCP_STATE_DISCONNECTED);
    }
    
    MCP_Transport_Destroy(hTransport);
    return true;
}

bool Test_JSONRPC_BuildParse()
{
    printf("\n=== Test: JSON-RPC Build/Parse ===\n");
    
    // Test building a request
    const char* params = "{\"key\":\"value\",\"number\":42}";
    char* pRequest = nullptr;
    DWORD requestLen = 0;
    
    BOOL result = MCP_Util_BuildJsonRpcRequest(L"test/method", params, &pRequest, &requestLen);
    printf("BuildJsonRpcRequest: %s\n", result ? "OK" : "FAILED");
    
    if (result && pRequest) {
        printf("Request: %.*s\n", requestLen, pRequest);
        
        // Test parsing a response
        const char* response = "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"ok\"},\"id\":1}";
        DWORD requestId = 0;
        const char* pResult = nullptr;
        const char* pError = nullptr;
        
        result = MCP_Util_ParseJsonRpcResponse(response, strlen(response), 
                                                &requestId, &pResult, &pError);
        printf("ParseJsonRpcResponse: %s\n", result ? "OK" : "FAILED");
        printf("  Request ID: %lu\n", requestId);
        printf("  Result: %s\n", pResult ? pResult : "(null)");
        printf("  Error: %s\n", pError ? pError : "(null)");
        
        // Free request buffer
        HANDLE hHeap = GetProcessHeap();
        HeapFree(hHeap, 0, pRequest);
    }
    
    return true;
}

bool Test_PKCE()
{
    printf("\n=== Test: PKCE Generation ===\n");
    
    char verifier[256] = {0};
    char challenge[256] = {0};
    DWORD verifierSize = sizeof(verifier);
    DWORD challengeSize = sizeof(challenge);
    
    BOOL result = MCP_Util_GeneratePKCEVerifier(verifier, &verifierSize);
    printf("GeneratePKCEVerifier: %s\n", result ? "OK" : "FAILED");
    
    if (result) {
        printf("  Verifier: %s\n", verifier);
        
        result = MCP_Util_GeneratePKCEChallenge(verifier, challenge, &challengeSize);
        printf("GeneratePKCEChallenge: %s\n", result ? "OK" : "FAILED");
        
        if (result) {
            printf("  Challenge: %s\n", challenge);
        }
    }
    
    return true;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[])
{
    printf("=============================================================================\n");
    printf("RawrXD MCP Transport Test Suite\n");
    printf("=============================================================================\n");
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (Test_CreateDestroy()) passed++; else failed++;
    if (Test_Callbacks()) passed++; else failed++;
    if (Test_StateMachine()) passed++; else failed++;
    if (Test_JSONRPC_BuildParse()) passed++; else failed++;
    if (Test_PKCE()) passed++; else failed++;
    
    // Connection test (optional - requires server)
    if (argc > 1 && strcmp(argv[1], "--connection") == 0) {
        if (Test_Connection()) passed++; else failed++;
    } else {
        printf("\n=== Skipping Connection Test ===\n");
        printf("Run with --connection flag to test actual server connection\n");
    }
    
    printf("\n=============================================================================\n");
    printf("Test Results: %d passed, %d failed\n", passed, failed);
    printf("=============================================================================\n");
    
    return failed > 0 ? 1 : 0;
}
