// RawrXD_LSP_Engine.cpp - Language Server Protocol Implementation
// Zero dependencies, pure Win32 sockets

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define LSP_BUFFER_SIZE 65536
#define LSP_MAX_SERVERS 8

// LSP Message types
enum LSPMessageType {
    LSP_REQUEST = 1,
    LSP_RESPONSE,
    LSP_NOTIFICATION
};

// LSP Server capabilities
struct LSPServerCaps {
    BOOL bHover;
    BOOL bCompletion;
    BOOL bDefinition;
    BOOL bReferences;
    BOOL bDocumentSymbol;
    BOOL bCodeAction;
    BOOL bRename;
    BOOL bSignatureHelp;
    BOOL bFormatting;
    BOOL bRangeFormatting;
    BOOL bTypeDefinition;
    BOOL bImplementation;
    BOOL bColorProvider;
    BOOL bFoldingRange;
    BOOL bExecuteCommand;
};

// LSP Server state
struct LSPServer {
    BOOL bActive;
    BOOL bInitialized;
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hStdinWrite;
    HANDLE hStdoutRead;
    SOCKET socket;
    int nRequestId;
    char szLanguage[32];
    char szRootPath[MAX_PATH];
    LSPServerCaps caps;
    CRITICAL_SECTION cs;
};

// Global LSP state
static LSPServer g_LSP_Servers[LSP_MAX_SERVERS] = {0};
static BOOL g_LSP_Initialized = FALSE;
static HANDLE g_LSP_Thread = NULL;
static volatile BOOL g_LSP_Running = FALSE;

// LSP Message handlers
typedef void (*LSPMessageHandler)(const char* json, size_t len);

// Function prototypes
BOOL LSP_Initialize(void);
void LSP_Shutdown(void);
BOOL LSP_StartServer(const char* szLanguage, const char* szRootPath, const char* szCommand);
void LSP_StopServer(int nServerId);
BOOL LSP_SendMessage(int nServerId, const char* szJson);
BOOL LSP_SendRequest(int nServerId, const char* szMethod, const char* szParams);
void LSP_HandleResponse(const char* json, size_t len);
void LSP_HandleNotification(const char* json, size_t len);
unsigned __stdcall LSP_ReaderThread(void* pArg);
unsigned __stdcall LSP_MainThread(void* pArg);

// JSON helpers
void LSP_EscapeJson(char* dst, size_t dstSize, const char* src);
void LSP_BuildRequest(char* buffer, size_t bufferSize, int id, const char* method, const char* params);
void LSP_BuildNotification(char* buffer, size_t bufferSize, const char* method, const char* params);

// Initialize LSP subsystem
BOOL LSP_Initialize(void) {
    if (g_LSP_Initialized) return TRUE;
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return FALSE;
    }
    
    // Initialize server slots
    for (int i = 0; i < LSP_MAX_SERVERS; i++) {
        g_LSP_Servers[i].bActive = FALSE;
        g_LSP_Servers[i].bInitialized = FALSE;
        g_LSP_Servers[i].hProcess = NULL;
        g_LSP_Servers[i].hStdinWrite = NULL;
        g_LSP_Servers[i].hStdoutRead = NULL;
        g_LSP_Servers[i].socket = INVALID_SOCKET;
        g_LSP_Servers[i].nRequestId = 1;
        InitializeCriticalSection(&g_LSP_Servers[i].cs);
    }
    
    // Start main LSP thread
    g_LSP_Running = TRUE;
    g_LSP_Thread = (HANDLE)_beginthreadex(NULL, 0, LSP_MainThread, NULL, 0, NULL);
    if (!g_LSP_Thread) {
        WSACleanup();
        return FALSE;
    }
    
    g_LSP_Initialized = TRUE;
    return TRUE;
}

// Shutdown LSP subsystem
void LSP_Shutdown(void) {
    if (!g_LSP_Initialized) return;
    
    g_LSP_Running = FALSE;
    
    // Stop all servers
    for (int i = 0; i < LSP_MAX_SERVERS; i++) {
        if (g_LSP_Servers[i].bActive) {
            LSP_StopServer(i);
        }
        DeleteCriticalSection(&g_LSP_Servers[i].cs);
    }
    
    // Wait for main thread
    if (g_LSP_Thread) {
        WaitForSingleObject(g_LSP_Thread, 5000);
        CloseHandle(g_LSP_Thread);
    }
    
    WSACleanup();
    g_LSP_Initialized = FALSE;
}

// Start LSP server for a language
BOOL LSP_StartServer(const char* szLanguage, const char* szRootPath, const char* szCommand) {
    // Find free slot
    int nSlot = -1;
    for (int i = 0; i < LSP_MAX_SERVERS; i++) {
        if (!g_LSP_Servers[i].bActive) {
            nSlot = i;
            break;
        }
    }
    
    if (nSlot == -1) return FALSE;
    
    LSPServer* pServer = &g_LSP_Servers[nSlot];
    
    // Create pipes for stdin/stdout
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hStdinRead, hStdoutWrite;
    
    if (!CreatePipe(&hStdinRead, &pServer->hStdinWrite, &sa, 0)) return FALSE;
    if (!CreatePipe(&pServer->hStdoutRead, &hStdoutWrite, &sa, 0)) {
        CloseHandle(hStdinRead);
        CloseHandle(pServer->hStdinWrite);
        return FALSE;
    }
    
    // Set pipe handles to be inherited
    SetHandleInformation(pServer->hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(pServer->hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    
    // Create process
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;
    
    PROCESS_INFORMATION pi = {0};
    
    char szCmdLine[1024];
    _snprintf_s(szCmdLine, sizeof(szCmdLine), _TRUNCATE, "\"%s\"", szCommand);
    
    if (!CreateProcessA(NULL, szCmdLine, NULL, NULL, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, szRootPath, &si, &pi)) {
        CloseHandle(hStdinRead);
        CloseHandle(pServer->hStdinWrite);
        CloseHandle(pServer->hStdoutRead);
        CloseHandle(hStdoutWrite);
        return FALSE;
    }
    
    // Close unused pipe ends
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);
    
    // Store process info
    pServer->hProcess = pi.hProcess;
    pServer->hThread = pi.hThread;
    pServer->bActive = TRUE;
    strncpy_s(pServer->szLanguage, sizeof(pServer->szLanguage), szLanguage, _TRUNCATE);
    strncpy_s(pServer->szRootPath, sizeof(pServer->szRootPath), szRootPath, _TRUNCATE);
    
    // Resume process
    ResumeThread(pi.hThread);
    
    // Start reader thread
    _beginthreadex(NULL, 0, LSP_ReaderThread, (void*)(size_t)nSlot, 0, NULL);
    
    // Send initialize request
    char szInitRequest[4096];
    _snprintf_s(szInitRequest, sizeof(szInitRequest), _TRUNCATE,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"processId\":%lu,\"rootPath\":\"%s\",\"capabilities\":{}}}}",
        GetCurrentProcessId(), szRootPath);
    
    LSP_SendMessage(nSlot, szInitRequest);
    
    return TRUE;
}

// Stop LSP server
void LSP_StopServer(int nServerId) {
    if (nServerId < 0 || nServerId >= LSP_MAX_SERVERS) return;
    
    LSPServer* pServer = &g_LSP_Servers[nServerId];
    if (!pServer->bActive) return;
    
    EnterCriticalSection(&pServer->cs);
    
    // Send shutdown request
    LSP_SendRequest(nServerId, "shutdown", "{}");
    
    // Terminate process
    if (pServer->hProcess) {
        TerminateProcess(pServer->hProcess, 0);
        WaitForSingleObject(pServer->hProcess, 1000);
        CloseHandle(pServer->hProcess);
    }
    if (pServer->hThread) {
        CloseHandle(pServer->hThread);
    }
    
    // Close pipes
    if (pServer->hStdinWrite) CloseHandle(pServer->hStdinWrite);
    if (pServer->hStdoutRead) CloseHandle(pServer->hStdoutRead);
    if (pServer->socket != INVALID_SOCKET) closesocket(pServer->socket);
    
    pServer->bActive = FALSE;
    pServer->bInitialized = FALSE;
    
    LeaveCriticalSection(&pServer->cs);
}

// Send raw message to LSP server
BOOL LSP_SendMessage(int nServerId, const char* szJson) {
    if (nServerId < 0 || nServerId >= LSP_MAX_SERVERS) return FALSE;
    
    LSPServer* pServer = &g_LSP_Servers[nServerId];
    if (!pServer->bActive) return FALSE;
    
    EnterCriticalSection(&pServer->cs);
    
    // Build LSP message with Content-Length header
    size_t nJsonLen = strlen(szJson);
    char szHeader[256];
    int nHeaderLen = _snprintf_s(szHeader, sizeof(szHeader), _TRUNCATE,
        "Content-Length: %zu\r\n\r\n", nJsonLen);
    
    // Send header
    DWORD dwWritten = 0;
    BOOL bSuccess = WriteFile(pServer->hStdinWrite, szHeader, nHeaderLen, &dwWritten, NULL);
    
    // Send JSON
    if (bSuccess) {
        bSuccess = WriteFile(pServer->hStdinWrite, szJson, (DWORD)nJsonLen, &dwWritten, NULL);
    }
    
    LeaveCriticalSection(&pServer->cs);
    
    return bSuccess;
}

// Send LSP request
BOOL LSP_SendRequest(int nServerId, const char* szMethod, const char* szParams) {
    if (nServerId < 0 || nServerId >= LSP_MAX_SERVERS) return FALSE;
    
    LSPServer* pServer = &g_LSP_Servers[nServerId];
    if (!pServer->bActive) return FALSE;
    
    EnterCriticalSection(&pServer->cs);
    int nId = pServer->nRequestId++;
    LeaveCriticalSection(&pServer->cs);
    
    char szRequest[4096];
    _snprintf_s(szRequest, sizeof(szRequest), _TRUNCATE,
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"%s\",\"params\":%s}",
        nId, szMethod, szParams);
    
    return LSP_SendMessage(nServerId, szRequest);
}

// Send completion request
BOOL LSP_RequestCompletion(int nServerId, const char* szFilePath, int nLine, int nCol) {
    char szParams[1024];
    _snprintf_s(szParams, sizeof(szParams), _TRUNCATE,
        "{\"textDocument\":{\"uri\":\"file://%s\"},\"position\":{\"line\":%d,\"character\":%d}}",
        szFilePath, nLine, nCol);
    
    return LSP_SendRequest(nServerId, "textDocument/completion", szParams);
}

// Send hover request
BOOL LSP_RequestHover(int nServerId, const char* szFilePath, int nLine, int nCol) {
    char szParams[1024];
    _snprintf_s(szParams, sizeof(szParams), _TRUNCATE,
        "{\"textDocument\":{\"uri\":\"file://%s\"},\"position\":{\"line\":%d,\"character\":%d}}",
        szFilePath, nLine, nCol);
    
    return LSP_SendRequest(nServerId, "textDocument/hover", szParams);
}

// Send definition request
BOOL LSP_RequestDefinition(int nServerId, const char* szFilePath, int nLine, int nCol) {
    char szParams[1024];
    _snprintf_s(szParams, sizeof(szParams), _TRUNCATE,
        "{\"textDocument\":{\"uri\":\"file://%s\"},\"position\":{\"line\":%d,\"character\":%d}}",
        szFilePath, nLine, nCol);
    
    return LSP_SendRequest(nServerId, "textDocument/definition", szParams);
}

// Send document open notification
BOOL LSP_NotifyDocumentOpen(int nServerId, const char* szFilePath, const char* szLanguage, const char* szContent) {
    // Escape content for JSON
    size_t nContentLen = strlen(szContent);
    char* szEscaped = (char*)malloc(nContentLen * 2 + 1);
    if (!szEscaped) return FALSE;
    
    char* dst = szEscaped;
    for (const char* src = szContent; *src; src++) {
        if (*src == '\\' || *src == '"') {
            *dst++ = '\\';
        }
        if (*src == '\n') {
            *dst++ = '\\';
            *dst++ = 'n';
        } else if (*src == '\r') {
            *dst++ = '\\';
            *dst++ = 'r';
        } else if (*src == '\t') {
            *dst++ = '\\';
            *dst++ = 't';
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    
    char szParams[65536];
    _snprintf_s(szParams, sizeof(szParams), _TRUNCATE,
        "{\"textDocument\":{\"uri\":\"file://%s\",\"languageId\":\"%s\",\"version\":1,\"text\":\"%s\"}}",
        szFilePath, szLanguage, szEscaped);
    
    free(szEscaped);
    
    char szNotification[65536 + 256];
    _snprintf_s(szNotification, sizeof(szNotification), _TRUNCATE,
        "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/didOpen\",\"params\":%s}", szParams);
    
    return LSP_SendMessage(nServerId, szNotification);
}

// Reader thread for LSP server output
unsigned __stdcall LSP_ReaderThread(void* pArg) {
    int nServerId = (int)(size_t)pArg;
    LSPServer* pServer = &g_LSP_Servers[nServerId];
    
    char szBuffer[LSP_BUFFER_SIZE];
    char szMessage[65536];
    int nMessageLen = 0;
    int nContentLength = -1;
    
    while (pServer->bActive && g_LSP_Running) {
        DWORD dwRead = 0;
        BOOL bSuccess = ReadFile(pServer->hStdoutRead, szBuffer, sizeof(szBuffer) - 1, &dwRead, NULL);
        
        if (!bSuccess || dwRead == 0) {
            Sleep(10);
            continue;
        }
        
        szBuffer[dwRead] = '\0';
        
        // Parse LSP messages
        char* p = szBuffer;
        while (*p) {
            // Look for Content-Length header
            if (strncmp(p, "Content-Length: ", 16) == 0) {
                nContentLength = atoi(p + 16);
                p = strstr(p, "\r\n\r\n");
                if (p) {
                    p += 4;
                    nMessageLen = 0;
                }
            } else if (nContentLength > 0 && nMessageLen < nContentLength) {
                // Accumulate message body
                int nToCopy = min((int)strlen(p), nContentLength - nMessageLen);
                memcpy(szMessage + nMessageLen, p, nToCopy);
                nMessageLen += nToCopy;
                p += nToCopy;
                
                if (nMessageLen >= nContentLength) {
                    // Complete message received
                    szMessage[nContentLength] = '\0';
                    
                    // Handle message
                    if (strstr(szMessage, "\"id\":")) {
                        LSP_HandleResponse(szMessage, nContentLength);
                    } else {
                        LSP_HandleNotification(szMessage, nContentLength);
                    }
                    
                    nContentLength = -1;
                    nMessageLen = 0;
                }
            } else {
                p++;
            }
        }
    }
    
    return 0;
}

// Handle LSP response
void LSP_HandleResponse(const char* json, size_t len) {
    (void)len;
    
    // Parse response ID
    const char* pId = strstr(json, "\"id\":");
    if (pId) {
        int nId = atoi(pId + 5);
        
        // Check for result
        const char* pResult = strstr(json, "\"result\":");
        if (pResult) {
            // Handle completion results
            if (strstr(json, "\"items\"")) {
                // TODO: Parse completion items and display
                OutputDebugStringA("LSP: Completion received\n");
            }
            // Handle hover results
            else if (strstr(json, "\"contents\"")) {
                // TODO: Parse hover info and display tooltip
                OutputDebugStringA("LSP: Hover received\n");
            }
            // Handle definition results
            else if (strstr(json, "\"uri\":")) {
                // TODO: Parse location and navigate
                OutputDebugStringA("LSP: Definition received\n");
            }
        }
        
        // Check for error
        const char* pError = strstr(json, "\"error\":");
        if (pError) {
            OutputDebugStringA("LSP: Error response\n");
        }
    }
}

// Handle LSP notification
void LSP_HandleNotification(const char* json, size_t len) {
    (void)len;
    
    // Handle publish diagnostics
    if (strstr(json, "\"method\":\"textDocument/publishDiagnostics\"")) {
        // TODO: Parse diagnostics and update UI
        OutputDebugStringA("LSP: Diagnostics received\n");
    }
    // Handle log messages
    else if (strstr(json, "\"method\":\"window/logMessage\"")) {
        OutputDebugStringA("LSP: Log message\n");
    }
    // Handle show messages
    else if (strstr(json, "\"method\":\"window/showMessage\"")) {
        OutputDebugStringA("LSP: Show message\n");
    }
}

// Main LSP thread
unsigned __stdcall LSP_MainThread(void* pArg) {
    (void)pArg;
    
    while (g_LSP_Running) {
        // Keepalive and health checks
        for (int i = 0; i < LSP_MAX_SERVERS; i++) {
            if (g_LSP_Servers[i].bActive) {
                // Check if process is still alive
                DWORD dwExitCode = 0;
                if (GetExitCodeProcess(g_LSP_Servers[i].hProcess, &dwExitCode)) {
                    if (dwExitCode != STILL_ACTIVE) {
                        // Server crashed, restart
                        OutputDebugStringA("LSP: Server crashed, restarting...\n");
                        LSP_StopServer(i);
                        // TODO: Restart with same config
                    }
                }
            }
        }
        
        Sleep(1000);
    }
    
    return 0;
}

// Public API: Initialize LSP
extern "C" __declspec(dllexport) BOOL RawrXD_LSP_Init(void) {
    return LSP_Initialize();
}

// Public API: Shutdown LSP
extern "C" __declspec(dllexport) void RawrXD_LSP_Shutdown(void) {
    LSP_Shutdown();
}

// Public API: Start language server
extern "C" __declspec(dllexport) int RawrXD_LSP_Start(const char* szLanguage, 
    const char* szRootPath, const char* szCommand) {
    
    if (LSP_StartServer(szLanguage, szRootPath, szCommand)) {
        // Find and return server ID
        for (int i = 0; i < LSP_MAX_SERVERS; i++) {
            if (g_LSP_Servers[i].bActive && 
                strcmp(g_LSP_Servers[i].szLanguage, szLanguage) == 0) {
                return i;
            }
        }
    }
    return -1;
}

// Public API: Request completion
extern "C" __declspec(dllexport) BOOL RawrXD_LSP_Complete(int nServerId, 
    const char* szFilePath, int nLine, int nCol) {
    return LSP_RequestCompletion(nServerId, szFilePath, nLine, nCol);
}

// Public API: Request hover
extern "C" __declspec(dllexport) BOOL RawrXD_LSP_Hover(int nServerId,
    const char* szFilePath, int nLine, int nCol) {
    return LSP_RequestHover(nServerId, szFilePath, nLine, nCol);
}

// Public API: Request definition
extern "C" __declspec(dllexport) BOOL RawrXD_LSP_GotoDef(int nServerId,
    const char* szFilePath, int nLine, int nCol) {
    return LSP_RequestDefinition(nServerId, szFilePath, nLine, nCol);
}

// End of RawrXD_LSP_Engine.cpp
