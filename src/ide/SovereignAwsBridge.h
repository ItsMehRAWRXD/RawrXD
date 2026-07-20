/*=============================================================================
 * SovereignAwsBridge.h — Native AWS Bedrock Bridge for RawrXD IDE
 *
 * Treats the remote AWS Bedrock backend as just another execution kernel
 * in the Sovereign orchestration layout. Completions stream through
 * shared memory, exactly like the Deep2 CPU kernel.
 *
 * Architecture:
 *   - Worker thread: WinSock + Schannel TLS → AWS Bedrock
 *   - Shared memory: Response payloads written to mapped view
 *   - Provenance: executionMode = "remote-agent" | "aws-bedrock"
 *   - Tool execution: fsRead, search, etc. intercepted from shared memory
 *
 * Threading:
 *   - Main thread: Initialize, Shutdown, CheckCompletion, GetCompletion
 *   - Worker thread: Network I/O, shared memory writes, callback dispatch
 *===========================================================================*/

#pragma once
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <string>
#include <thread>
#include <functional>

#include "AwsSigV4Signer.h"
#include "AwsBedrockClient.h"

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * CONSTANTS
 *===========================================================================*/

#define AWS_BRIDGE_MAX_TOOL_INPUT     4096
#define AWS_BRIDGE_MAX_TOOL_NAME      128
#define AWS_BRIDGE_MAX_RESPONSE       (256 * 1024)  // 256KB
#define AWS_BRIDGE_MAX_CONTEXT        8192
#define AWS_BRIDGE_DEFAULT_REGION     "us-east-1"
#define AWS_BRIDGE_DEFAULT_MODEL      "anthropic.claude-3-5-sonnet-20241022-v2:0"

/*=============================================================================
 * EXECUTION MODE — Provenance tracking
 *===========================================================================*/

typedef enum {
    EXEC_MODE_UNKNOWN       = 0,
    EXEC_MODE_SYNTHETIC     = 1,  // Local synthetic generation
    EXEC_MODE_GGUF_BACKED   = 2,  // Local GGUF inference
    EXEC_MODE_REMOTE_AGENT  = 3,  // AWS Bedrock remote agent
    EXEC_MODE_AWS_BEDROCK   = 4,  // AWS Bedrock direct
} AwsBridgeExecutionMode;

/*=============================================================================
 * TOOL CALL — Intercepted from model response
 *===========================================================================*/

typedef struct {
    char    toolName[AWS_BRIDGE_MAX_TOOL_NAME];
    char    toolInput[AWS_BRIDGE_MAX_TOOL_INPUT];
    BOOL    hasToolCall;
} AwsBridgeToolCall;

/*=============================================================================
 * COMPLETION RESULT — Written to shared memory
 *===========================================================================*/

typedef struct {
    char    text[AWS_BRIDGE_MAX_RESPONSE];
    float   confidence;
    uint32_t requestVersion;
    uint64_t latencyMs;
    BOOL    success;
    AwsBridgeExecutionMode executionMode;
    char    modelName[128];
    AwsBridgeToolCall toolCall;
} AwsBridgeCompletion;

/*=============================================================================
 * BRIDGE STATE
 *===========================================================================*/

typedef struct {
    // Threading
    std::thread*        workerThread;
    std::atomic<BOOL>   workerRunning;
    std::atomic<BOOL>   requestPending;
    std::atomic<BOOL>   completionReady;
    
    // Request
    char                context[AWS_BRIDGE_MAX_CONTEXT];
    size_t              contextLen;
    uint32_t            requestVersion;
    
    // Completion
    AwsBridgeCompletion completion;
    
    // AWS credentials
    AwsCredentials      credentials;
    char                modelId[128];
    char                region[64];
    
    // Network client
    AwsBedrockClient    bedrockClient;
    
    // IDE window for posting messages
    HWND                hWndIDE;
    UINT                msgCompletionReady;
    
    // Synchronization
    HANDLE              hRequestEvent;
    HANDLE              hCompletionEvent;
    CRITICAL_SECTION    cs;
    
    // Telemetry
    std::atomic<uint64_t> totalRequests;
    std::atomic<uint64_t> totalTokens;
    std::atomic<float>    avgLatencyMs;
    
    // Error state
    char                lastError[512];
    BOOL                initialized;
} SovereignAwsBridge;

/*=============================================================================
 * API FUNCTIONS
 *===========================================================================*/

/**
 * @brief Initialize the AWS Bridge
 *
 * Sets up credentials, creates synchronization primitives,
 * and starts the worker thread.
 *
 * @param bridge        Bridge state structure
 * @param accessKeyId   AWS access key ID
 * @param secretKey     AWS secret access key
 * @param region        AWS region (e.g., "us-east-1")
 * @param modelId       Bedrock model ID (e.g., "anthropic.claude-3-5-sonnet-20241022-v2:0")
 * @param hWndIDE       IDE main window handle (for posting completion messages)
 * @param msgCompletion Custom message ID for completion notification
 * @return TRUE on success
 */
BOOL SovereignAwsBridge_Initialize(
    SovereignAwsBridge* bridge,
    const char* accessKeyId,
    const char* secretKey,
    const char* region,
    const char* modelId,
    HWND hWndIDE,
    UINT msgCompletion
);

/**
 * @brief Request a completion from AWS Bedrock
 *
 * Non-blocking. The request is queued and processed by the worker thread.
 * When complete, the IDE window receives msgCompletionReady.
 *
 * @param bridge    Initialized bridge
 * @param version   Editor version for stale detection
 * @param context   Input context text
 * @param contextLen Length of context
 * @return TRUE if request was queued
 */
BOOL SovereignAwsBridge_RequestCompletion(
    SovereignAwsBridge* bridge,
    uint32_t version,
    const char* context,
    size_t contextLen
);

/**
 * @brief Check if a completion is ready
 */
BOOL SovereignAwsBridge_IsCompletionReady(SovereignAwsBridge* bridge);

/**
 * @brief Get the completion result
 *
 * Caller takes ownership of the returned pointer (must free with delete).
 * Returns nullptr if no completion is ready.
 */
AwsBridgeCompletion* SovereignAwsBridge_GetCompletion(SovereignAwsBridge* bridge);

/**
 * @brief Free a completion result
 */
void SovereignAwsBridge_FreeCompletion(AwsBridgeCompletion* completion);

/**
 * @brief Cancel any pending request
 */
void SovereignAwsBridge_CancelRequest(SovereignAwsBridge* bridge);

/**
 * @brief Execute a tool call and return the result
 *
 * Called by the worker thread when the model returns a tool_use block.
 * Currently supports: fsRead, search, codeAnalysis
 *
 * @param toolName  Name of the tool to execute
 * @param toolInput JSON arguments for the tool
 * @param outResult Buffer for the tool result
 * @param resultSize Size of outResult buffer
 * @return TRUE on success
 */
BOOL SovereignAwsBridge_ExecuteTool(
    const char* toolName,
    const char* toolInput,
    char* outResult,
    size_t resultSize
);

/**
 * @brief Get performance metrics
 */
void SovereignAwsBridge_GetMetrics(
    SovereignAwsBridge* bridge,
    uint64_t* outTotalRequests,
    uint64_t* outTotalTokens,
    float* outAvgLatencyMs
);

/**
 * @brief Get the last error message
 */
const char* SovereignAwsBridge_GetLastError(SovereignAwsBridge* bridge);

/**
 * @brief Shutdown the bridge
 *
 * Signals the worker thread to stop, waits for it to join,
 * and cleans up all resources.
 */
void SovereignAwsBridge_Shutdown(SovereignAwsBridge* bridge);

#ifdef __cplusplus
}
#endif
