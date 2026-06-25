// agentic_router_bridge_lsp_adapter.cpp - Production Implementation
// Bridges agentic router messages to LSP protocol format
// ============================================================================

#include <windows.h>
#include <cstring>

// ============================================================================
// Constants
// ============================================================================
#define MAX_ROUTED_MESSAGES 256
#define MAX_MESSAGE_LEN     4096

// ============================================================================
// Message Types
// ============================================================================
enum LspMessageType {
    LSP_UNKNOWN = 0,
    LSP_INITIALIZE = 1,
    LSP_SHUTDOWN = 2,
    LSP_COMPLETION = 3,
    LSP_DIAGNOSTIC = 4,
    LSP_HOVER = 5,
    LSP_DEFINITION = 6,
    LSP_REFERENCES = 7,
    LSP_DOCUMENT_SYMBOL = 8,
    LSP_WORKSPACE_SYMBOL = 9,
    LSP_CODE_ACTION = 10,
    LSP_FORMATTING = 11,
    LSP_RENAME = 12
};

// ============================================================================
// Message Queue Entry
// ============================================================================
struct RoutedMessage {
    volatile LONG active;
    LspMessageType type;
    char payload[MAX_MESSAGE_LEN];
    DWORD timestamp;
};

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static RoutedMessage g_messageQueue[MAX_ROUTED_MESSAGES];
static volatile LONG g_msgHead = 0;
static volatile LONG g_msgTail = 0;
static volatile LONG g_msgCount = 0;

// ============================================================================
// Helper: Get message type from JSON method field
// ============================================================================
static LspMessageType ParseMessageType(const char* payload) {
    if (!payload) return LSP_UNKNOWN;
    if (strstr(payload, "initialize")) return LSP_INITIALIZE;
    if (strstr(payload, "shutdown")) return LSP_SHUTDOWN;
    if (strstr(payload, "completion")) return LSP_COMPLETION;
    if (strstr(payload, "diagnostic")) return LSP_DIAGNOSTIC;
    if (strstr(payload, "hover")) return LSP_HOVER;
    if (strstr(payload, "definition")) return LSP_DEFINITION;
    if (strstr(payload, "references")) return LSP_REFERENCES;
    if (strstr(payload, "documentSymbol")) return LSP_DOCUMENT_SYMBOL;
    if (strstr(payload, "workspaceSymbol")) return LSP_WORKSPACE_SYMBOL;
    if (strstr(payload, "codeAction")) return LSP_CODE_ACTION;
    if (strstr(payload, "formatting")) return LSP_FORMATTING;
    if (strstr(payload, "rename")) return LSP_RENAME;
    return LSP_UNKNOWN;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int agentic_router_bridge_lsp_adapter_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_msgHead, 0);
    InterlockedExchange(&g_msgTail, 0);
    InterlockedExchange(&g_msgCount, 0);
    
    for (int i = 0; i < MAX_ROUTED_MESSAGES; ++i) {
        InterlockedExchange(&g_messageQueue[i].active, 0);
        g_messageQueue[i].type = LSP_UNKNOWN;
        g_messageQueue[i].payload[0] = 0;
        g_messageQueue[i].timestamp = 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) int agentic_router_bridge_lsp_adapter_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int agentic_router_bridge_lsp_adapter_RouteMessage(const char* payload, int* msgType) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!payload) return 0;
    
    LONG count = InterlockedIncrement(&g_msgCount);
    if (count > MAX_ROUTED_MESSAGES) {
        InterlockedDecrement(&g_msgCount);
        return 0; // Queue full
    }
    
    LONG tail = InterlockedIncrement(&g_msgTail) - 1;
    tail %= MAX_ROUTED_MESSAGES;
    
    RoutedMessage* msg = &g_messageQueue[tail];
    
    size_t len = strlen(payload);
    if (len >= MAX_MESSAGE_LEN - 1) len = MAX_MESSAGE_LEN - 1;
    memcpy(msg->payload, payload, len);
    msg->payload[len] = 0;
    msg->type = ParseMessageType(payload);
    msg->timestamp = GetTickCount();
    
    if (msgType) *msgType = static_cast<int>(msg->type);
    
    InterlockedExchange(&msg->active, 1);
    return 1;
}

extern "C" __declspec(dllexport) int agentic_router_bridge_lsp_adapter_GetNextMessage(char* outPayload, int maxLen, int* outType) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!outPayload || maxLen <= 0) return 0;
    
    LONG head = InterlockedCompareExchange(&g_msgHead, 0, 0);
    LONG tail = InterlockedCompareExchange(&g_msgTail, 0, 0);
    
    if (head >= tail) return 0; // Empty
    
    LONG idx = head % MAX_ROUTED_MESSAGES;
    RoutedMessage* msg = &g_messageQueue[idx];
    
    if (InterlockedCompareExchange(&msg->active, 0, 0) == 0) return 0;
    
    size_t len = strlen(msg->payload);
    if (len >= static_cast<size_t>(maxLen)) len = maxLen - 1;
    memcpy(outPayload, msg->payload, len);
    outPayload[len] = 0;
    
    if (outType) *outType = static_cast<int>(msg->type);
    
    InterlockedExchange(&msg->active, 0);
    InterlockedIncrement(&g_msgHead);
    InterlockedDecrement(&g_msgCount);
    
    return 1;
}

extern "C" __declspec(dllexport) int agentic_router_bridge_lsp_adapter_GetQueueDepth() {
    return static_cast<int>(InterlockedCompareExchange(&g_msgCount, 0, 0));
}
