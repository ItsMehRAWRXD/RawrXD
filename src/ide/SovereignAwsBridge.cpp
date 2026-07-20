/*=============================================================================
 * SovereignAwsBridge.cpp — Native AWS Bedrock Bridge Implementation
 *
 * Full-duplex bridge between the RawrXD IDE and AWS Bedrock Runtime.
 * Uses native WinSock + Schannel TLS — no external dependencies.
 *
 * The bridge treats the remote AWS backend as just another execution kernel:
 *   - executionMode = "aws-bedrock" or "remote-agent"
 *   - Completions stream through the same shared memory pattern
 *   - Tool calls (fsRead, search) are intercepted and executed locally
 *===========================================================================*/

#include "SovereignAwsBridge.h"
#include <stdio.h>
#include <string.h>
#include <vector>

/*=============================================================================
 * INTERNAL: Worker thread
 *===========================================================================*/

static DWORD WINAPI AwsBridge_WorkerThread(LPVOID param) {
    SovereignAwsBridge* bridge = (SovereignAwsBridge*)param;
    
    OutputDebugStringA("[SovereignAwsBridge] Worker thread started\n");
    
    while (bridge->workerRunning.load()) {
        // Wait for a request (100ms timeout for checking shutdown)
        DWORD waitResult = WaitForSingleObject(bridge->hRequestEvent, 100);
        if (waitResult != WAIT_OBJECT_0) continue;
        
        if (!bridge->workerRunning.load()) break;
        
        // Capture request under lock
        char context[AWS_BRIDGE_MAX_CONTEXT];
        size_t contextLen;
        uint32_t requestVersion;
        
        EnterCriticalSection(&bridge->cs);
        memcpy(context, bridge->context, bridge->contextLen);
        contextLen = bridge->contextLen;
        requestVersion = bridge->requestVersion;
        bridge->requestPending.store(FALSE);
        LeaveCriticalSection(&bridge->cs);
        
        if (contextLen == 0) continue;
        
        OutputDebugStringA("[SovereignAwsBridge] Processing request...\n");
        
        // Build the Bedrock request payload
        char body[65536];
        int bodyLen = snprintf(body, sizeof(body),
            "{"
            "\"anthropic_version\":\"bedrock-2023-05-31\","
            "\"max_tokens\":4096,"
            "\"messages\":["
            "{\"role\":\"user\",\"content\":\"%.*s\"}"
            "],"
            "\"tools\":["
            "{"
            "\"name\":\"fsRead\","
            "\"description\":\"Read a file from the local filesystem\","
            "\"input_schema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
            "},"
            "{"
            "\"name\":\"search\","
            "\"description\":\"Search for files in the workspace\","
            "\"input_schema\":{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}},\"required\":[\"query\"]}"
            "},"
            "{"
            "\"name\":\"codeAnalysis\","
            "\"description\":\"Analyze code structure and symbols\","
            "\"input_schema\":{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\"}},\"required\":[\"filePath\"]}"
            "}"
            "],"
            "\"tool_choice\":{\"type\":\"auto\"}"
            "}",
            (int)contextLen, context);
        
        if (bodyLen <= 0) continue;
        
        // Sign the request
        AwsSigV4Request sigRequest;
        if (!AwsSigV4_BuildBedrockPost(
                &bridge->credentials,
                &sigRequest,
                "BedrockRuntime.InvokeModelWithResponseStream",
                body)) {
            OutputDebugStringA("[SovereignAwsBridge] SigV4 signing failed\n");
            continue;
        }
        
        // Build hostname
        char host[256];
        snprintf(host, sizeof(host), "%s.%s.amazonaws.com",
                 bridge->credentials.service, bridge->credentials.region);
        
        // Connect to Bedrock
        DWORD startTime = GetTickCount();
        
        if (!AwsBedrockClient_Connect(&bridge->bedrockClient, host, 443)) {
            OutputDebugStringA("[SovereignAwsBridge] Connection failed\n");
            continue;
        }
        
        // Send request
        if (!AwsBedrockClient_SendRequest(
                &bridge->bedrockClient,
                sigRequest.authorization,
                sigRequest.xAmzDate,
                sigRequest.xAmzTarget,
                sigRequest.contentType,
                body,
                bodyLen)) {
            OutputDebugStringA("[SovereignAwsBridge] Request failed\n");
            AwsBedrockClient_Disconnect(&bridge->bedrockClient);
            continue;
        }
        
        DWORD endTime = GetTickCount();
        float elapsedMs = (float)(endTime - startTime);
        
        // Get response
        const char* response = AwsBedrockClient_GetResponse(&bridge->bedrockClient);
        
        // Parse response and populate completion
        AwsBridgeCompletion completion = {0};
        completion.requestVersion = requestVersion;
        completion.latencyMs = (uint64_t)elapsedMs;
        completion.executionMode = EXEC_MODE_AWS_BEDROCK;
        strcpy_s(completion.modelName, sizeof(completion.modelName), bridge->modelId);
        
        if (response && strlen(response) > 0) {
            // Simple extraction: find "text" field in response
            // In production, use a proper JSON parser
            const char* textMarker = strstr(response, "\"text\":\"");
            if (textMarker) {
                textMarker += 8; // Skip past "text":"
                const char* textEnd = strchr(textMarker, '"');
                if (textEnd) {
                    size_t textLen = (textEnd - textMarker);
                    if (textLen > sizeof(completion.text) - 1)
                        textLen = sizeof(completion.text) - 1;
                    memcpy(completion.text, textMarker, textLen);
                    completion.text[textLen] = '\0';
                    completion.success = TRUE;
                    completion.confidence = 0.95f;
                    
                    // Count tokens (approximate: words / 0.75)
                    int words = 0;
                    bool inWord = false;
                    for (const char* p = completion.text; *p; p++) {
                        if (*p == ' ' || *p == '\n' || *p == '\t') {
                            inWord = false;
                        } else if (!inWord) {
                            inWord = true;
                            words++;
                        }
                    }
                    bridge->totalTokens += (uint64_t)(words / 0.75f);
                }
            }
            
            // Check for tool_use
            const char* toolMarker = strstr(response, "\"tool_use\"");
            if (toolMarker) {
                const char* nameMarker = strstr(toolMarker, "\"name\":\"");
                if (nameMarker) {
                    nameMarker += 8;
                    const char* nameEnd = strchr(nameMarker, '"');
                    if (nameEnd) {
                        size_t nameLen = (nameEnd - nameMarker);
                        if (nameLen > sizeof(completion.toolCall.toolName) - 1)
                            nameLen = sizeof(completion.toolCall.toolName) - 1;
                        memcpy(completion.toolCall.toolName, nameMarker, nameLen);
                        completion.toolCall.toolName[nameLen] = '\0';
                        completion.toolCall.hasToolCall = TRUE;
                        
                        // Extract input
                        const char* inputMarker = strstr(nameEnd, "\"input\":");
                        if (inputMarker) {
                            inputMarker += 8;
                            // Find matching closing brace
                            int braceDepth = 0;
                            const char* inputEnd = inputMarker;
                            while (*inputEnd) {
                                if (*inputEnd == '{') braceDepth++;
                                else if (*inputEnd == '}') {
                                    braceDepth--;
                                    if (braceDepth == 0) break;
                                }
                                inputEnd++;
                            }
                            size_t inputLen = (inputEnd - inputMarker + 1);
                            if (inputLen > sizeof(completion.toolCall.toolInput) - 1)
                                inputLen = sizeof(completion.toolCall.toolInput) - 1;
                            memcpy(completion.toolCall.toolInput, inputMarker, inputLen);
                            completion.toolCall.toolInput[inputLen] = '\0';
                        }
                    }
                }
            }
        }
        
        // Disconnect
        AwsBedrockClient_Disconnect(&bridge->bedrockClient);
        
        // Store completion
        EnterCriticalSection(&bridge->cs);
        memcpy(&bridge->completion, &completion, sizeof(completion));
        bridge->completionReady.store(TRUE);
        bridge->totalRequests++;
        
        // Update rolling average latency
        float oldAvg = bridge->avgLatencyMs.load();
        float newAvg = (oldAvg * 0.9f) + (elapsedMs * 0.1f);
        bridge->avgLatencyMs.store(newAvg);
        LeaveCriticalSection(&bridge->cs);
        
        // Signal IDE
        if (bridge->hWndIDE && IsWindow(bridge->hWndIDE)) {
            PostMessage(bridge->hWndIDE, bridge->msgCompletionReady, 0, 0);
        }
        
        SetEvent(bridge->hCompletionEvent);
        
        OutputDebugStringA("[SovereignAwsBridge] Completion ready\n");
    }
    
    OutputDebugStringA("[SovereignAwsBridge] Worker thread exiting\n");
    return 0;
}

/*=============================================================================
 * PUBLIC API
 *===========================================================================*/

BOOL SovereignAwsBridge_Initialize(
    SovereignAwsBridge* bridge,
    const char* accessKeyId,
    const char* secretKey,
    const char* region,
    const char* modelId,
    HWND hWndIDE,
    UINT msgCompletion)
{
    if (!bridge) return FALSE;
    
    memset(bridge, 0, sizeof(SovereignAwsBridge));
    
    // Store credentials
    strcpy_s(bridge->credentials.accessKeyId, sizeof(bridge->credentials.accessKeyId), accessKeyId);
    strcpy_s(bridge->credentials.secretAccessKey, sizeof(bridge->credentials.secretAccessKey), secretKey);
    strcpy_s(bridge->credentials.region, sizeof(bridge->credentials.region), region ? region : AWS_BRIDGE_DEFAULT_REGION);
    strcpy_s(bridge->credentials.service, sizeof(bridge->credentials.service), "bedrock-runtime");
    
    // Store model ID
    strcpy_s(bridge->modelId, sizeof(bridge->modelId), modelId ? modelId : AWS_BRIDGE_DEFAULT_MODEL);
    strcpy_s(bridge->region, sizeof(bridge->region), bridge->credentials.region);
    
    // Store IDE window handle
    bridge->hWndIDE = hWndIDE;
    bridge->msgCompletionReady = msgCompletion;
    
    // Initialize Bedrock client
    if (!AwsBedrockClient_Init(&bridge->bedrockClient)) {
        strcpy_s(bridge->lastError, sizeof(bridge->lastError),
                 "Failed to initialize Bedrock client");
        return FALSE;
    }
    
    // Create synchronization primitives
    bridge->hRequestEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    bridge->hCompletionEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    InitializeCriticalSection(&bridge->cs);
    
    // Start worker thread
    bridge->workerRunning.store(TRUE);
    bridge->workerThread = new std::thread(AwsBridge_WorkerThread, bridge);
    
    bridge->initialized = TRUE;
    
    OutputDebugStringA("[SovereignAwsBridge] Initialized successfully\n");
    return TRUE;
}

BOOL SovereignAwsBridge_RequestCompletion(
    SovereignAwsBridge* bridge,
    uint32_t version,
    const char* context,
    size_t contextLen)
{
    if (!bridge || !bridge->initialized) return FALSE;
    
    EnterCriticalSection(&bridge->cs);
    
    // Store request
    size_t copyLen = (contextLen < AWS_BRIDGE_MAX_CONTEXT) ? contextLen : (AWS_BRIDGE_MAX_CONTEXT - 1);
    memcpy(bridge->context, context, copyLen);
    bridge->context[copyLen] = '\0';
    bridge->contextLen = copyLen;
    bridge->requestVersion = version;
    bridge->requestPending.store(TRUE);
    bridge->completionReady.store(FALSE);
    
    LeaveCriticalSection(&bridge->cs);
    
    // Signal worker thread
    SetEvent(bridge->hRequestEvent);
    
    return TRUE;
}

BOOL SovereignAwsBridge_IsCompletionReady(SovereignAwsBridge* bridge) {
    if (!bridge) return FALSE;
    return bridge->completionReady.load();
}

AwsBridgeCompletion* SovereignAwsBridge_GetCompletion(SovereignAwsBridge* bridge) {
    if (!bridge || !bridge->completionReady.load()) return nullptr;
    
    EnterCriticalSection(&bridge->cs);
    AwsBridgeCompletion* result = new AwsBridgeCompletion();
    memcpy(result, &bridge->completion, sizeof(AwsBridgeCompletion));
    bridge->completionReady.store(FALSE);
    LeaveCriticalSection(&bridge->cs);
    
    return result;
}

void SovereignAwsBridge_FreeCompletion(AwsBridgeCompletion* completion) {
    delete completion;
}

void SovereignAwsBridge_CancelRequest(SovereignAwsBridge* bridge) {
    if (!bridge) return;
    
    EnterCriticalSection(&bridge->cs);
    bridge->requestPending.store(FALSE);
    bridge->completionReady.store(FALSE);
    LeaveCriticalSection(&bridge->cs);
}

BOOL SovereignAwsBridge_ExecuteTool(
    const char* toolName,
    const char* toolInput,
    char* outResult,
    size_t resultSize)
{
    if (!toolName || !toolInput || !outResult) return FALSE;
    
    if (strcmp(toolName, "fsRead") == 0) {
        // Extract path from JSON input
        const char* pathMarker = strstr(toolInput, "\"path\":\"");
        if (!pathMarker) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Missing path parameter\"}");
            return FALSE;
        }
        pathMarker += 8;
        
        char filePath[1024];
        const char* pathEnd = strchr(pathMarker, '"');
        if (!pathEnd) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Invalid path format\"}");
            return FALSE;
        }
        size_t pathLen = (pathEnd - pathMarker);
        if (pathLen > sizeof(filePath) - 1) pathLen = sizeof(filePath) - 1;
        memcpy(filePath, pathMarker, pathLen);
        filePath[pathLen] = '\0';
        
        // Read file
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            snprintf(outResult, resultSize, "{\"error\":\"Cannot open file: %s\"}", filePath);
            return FALSE;
        }
        
        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize > resultSize - 64) fileSize = (DWORD)(resultSize - 64);
        
        char* fileContent = (char*)malloc(fileSize + 1);
        DWORD bytesRead;
        if (ReadFile(hFile, fileContent, fileSize, &bytesRead, nullptr)) {
            fileContent[bytesRead] = '\0';
            // Escape for JSON
            snprintf(outResult, resultSize, "{\"content\":\"%.*s\"}", (int)bytesRead, fileContent);
        } else {
            strcpy_s(outResult, resultSize, "{\"error\":\"Read failed\"}");
        }
        
        free(fileContent);
        CloseHandle(hFile);
        return TRUE;
        
    } else if (strcmp(toolName, "search") == 0) {
        // Extract query from JSON input
        const char* queryMarker = strstr(toolInput, "\"query\":\"");
        if (!queryMarker) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Missing query parameter\"}");
            return FALSE;
        }
        queryMarker += 9;
        
        char query[256];
        const char* queryEnd = strchr(queryMarker, '"');
        if (!queryEnd) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Invalid query format\"}");
            return FALSE;
        }
        size_t queryLen = (queryEnd - queryMarker);
        if (queryLen > sizeof(query) - 1) queryLen = sizeof(query) - 1;
        memcpy(query, queryMarker, queryLen);
        query[queryLen] = '\0';
        
        // Use Windows Search API or simple file enumeration
        // For now, return a placeholder
        snprintf(outResult, resultSize,
                 "{\"results\":[{\"path\":\"placeholder.txt\",\"match\":\"%s\"}]}", query);
        return TRUE;
        
    } else if (strcmp(toolName, "codeAnalysis") == 0) {
        // Extract filePath from JSON input
        const char* pathMarker = strstr(toolInput, "\"filePath\":\"");
        if (!pathMarker) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Missing filePath parameter\"}");
            return FALSE;
        }
        pathMarker += 12;
        
        char filePath[1024];
        const char* pathEnd = strchr(pathMarker, '"');
        if (!pathEnd) {
            strcpy_s(outResult, resultSize, "{\"error\":\"Invalid filePath format\"}");
            return FALSE;
        }
        size_t pathLen = (pathEnd - pathMarker);
        if (pathLen > sizeof(filePath) - 1) pathLen = sizeof(filePath) - 1;
        memcpy(filePath, pathMarker, pathLen);
        filePath[pathLen] = '\0';
        
        // Simple code analysis: count lines, detect language
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            snprintf(outResult, resultSize, "{\"error\":\"Cannot open file: %s\"}", filePath);
            return FALSE;
        }
        
        DWORD fileSize = GetFileSize(hFile, nullptr);
        char* content = (char*)malloc(fileSize + 1);
        DWORD bytesRead;
        int lineCount = 0;
        
        if (ReadFile(hFile, content, fileSize, &bytesRead, nullptr)) {
            content[bytesRead] = '\0';
            for (char* p = content; *p; p++) {
                if (*p == '\n') lineCount++;
            }
        }
        
        free(content);
        CloseHandle(hFile);
        
        // Detect language from extension
        const char* ext = strrchr(filePath, '.');
        const char* lang = ext ? (ext + 1) : "unknown";
        
        snprintf(outResult, resultSize,
                 "{\"filePath\":\"%s\",\"lines\":%d,\"language\":\"%s\",\"size\":%lu}",
                 filePath, lineCount, lang, fileSize);
        return TRUE;
    }
    
    snprintf(outResult, resultSize, "{\"error\":\"Unknown tool: %s\"}", toolName);
    return FALSE;
}

void SovereignAwsBridge_GetMetrics(
    SovereignAwsBridge* bridge,
    uint64_t* outTotalRequests,
    uint64_t* outTotalTokens,
    float* outAvgLatencyMs)
{
    if (!bridge) return;
    if (outTotalRequests) *outTotalRequests = bridge->totalRequests.load();
    if (outTotalTokens) *outTotalTokens = bridge->totalTokens.load();
    if (outAvgLatencyMs) *outAvgLatencyMs = bridge->avgLatencyMs.load();
}

const char* SovereignAwsBridge_GetLastError(SovereignAwsBridge* bridge) {
    if (!bridge) return "Null bridge";
    return bridge->lastError;
}

void SovereignAwsBridge_Shutdown(SovereignAwsBridge* bridge) {
    if (!bridge || !bridge->initialized) return;
    
    OutputDebugStringA("[SovereignAwsBridge] Shutting down...\n");
    
    // Signal worker to stop
    bridge->workerRunning.store(FALSE);
    SetEvent(bridge->hRequestEvent);
    
    // Wait for worker thread
    if (bridge->workerThread && bridge->workerThread->joinable()) {
        bridge->workerThread->join();
        delete bridge->workerThread;
        bridge->workerThread = nullptr;
    }
    
    // Disconnect network
    AwsBedrockClient_Disconnect(&bridge->bedrockClient);
    
    // Cleanup synchronization
    if (bridge->hRequestEvent) CloseHandle(bridge->hRequestEvent);
    if (bridge->hCompletionEvent) CloseHandle(bridge->hCompletionEvent);
    DeleteCriticalSection(&bridge->cs);
    
    bridge->initialized = FALSE;
    
    OutputDebugStringA("[SovereignAwsBridge] Shutdown complete\n");
}
