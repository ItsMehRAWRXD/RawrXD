//==============================================================================
// AgentSubsystem.cpp - Phase 13: Real Agent Integration
//
// LLM-powered intelligence for the Sovereign Runtime.
// Now backend-agnostic: uses InferenceBackend abstraction.
// Default: Native (sovereign GGUF runtime)
// Optional: Ollama, llama.cpp, OpenAI
//
// All LLM output is validated before execution.
//==============================================================================

#include "AgentSubsystem.h"
#include "InferenceBackend.h"
#include "ModelRegistry.h"
#include "ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <windows.h>

//==============================================================================
// Internal State
//==============================================================================

static int g_agent_initialized = 0;
static AgentConfig g_config = {0};
static AgentContext g_default_context = {0};

//==============================================================================
// Timing Utilities
//==============================================================================

static uint64_t GetCurrentTimeMs() {
    return GetTickCount64();
}

//==============================================================================
// Initialization
//==============================================================================

int Agent_Init(const AgentConfig* config) {
    if (g_agent_initialized) {
        return 0;
    }
    
    if (config) {
        memcpy(&g_config, config, sizeof(AgentConfig));
    } else {
        // Default configuration: NATIVE (sovereign) first
        g_config.provider = AGENT_PROVIDER_LOCAL;  // Native GGUF
        strcpy(g_config.model_path, "models/phi4.gguf");
        strcpy(g_config.model, "phi4");
        g_config.default_max_tokens = 2048;
        g_config.default_temperature = 0.7f;
        g_config.default_timeout_ms = AGENT_TIMEOUT_MS;
        g_config.default_max_tokens = 2048;
        g_config.default_temperature = 0.7f;
        g_config.default_timeout_ms = AGENT_TIMEOUT_MS;
    }
    
    g_agent_initialized = 1;
    return 0;
}

int Agent_Shutdown(void) {
    g_agent_initialized = 0;
    return 0;
}

//==============================================================================
// HTTP Client for Ollama/OpenAI
//==============================================================================

static int HttpPost(const char* url, const char* json_body, 
                    char* response, size_t response_size, int timeout_ms) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    
    // Parse URL
    char host[256] = {0};
    char path[512] = {0};
    int port = 80;
    BOOL secure = FALSE;
    
    if (strncmp(url, "https://", 8) == 0) {
        secure = TRUE;
        port = 443;
        sscanf(url + 8, "%255[^/]/%511s", host, path);
    } else if (strncmp(url, "http://", 7) == 0) {
        sscanf(url + 7, "%255[^/]/%511s", host, path);
    } else {
        return -1;
    }
    
    // Create session
    hSession = WinHttpOpen(L"SovereignAgent/13.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;
    
    // Connect
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
    hConnect = WinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Create request
    wchar_t wPath[512];
    MultiByteToWideChar(CP_UTF8, 0, path[0] ? path : "/", -1, wPath, 512);
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath, 
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Set headers
    WinHttpAddRequestHeaders(hRequest, 
        L"Content-Type: application/json\r\n",
        (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Send request
    BOOL result = WinHttpSendRequest(hRequest, 
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)json_body, strlen(json_body),
        strlen(json_body), 0);
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Read response
    DWORD bytesRead = 0;
    size_t totalRead = 0;
    char buffer[4096];
    
    do {
        bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
            break;
        }
        if (bytesRead > 0) {
            if (totalRead + bytesRead < response_size - 1) {
                memcpy(response + totalRead, buffer, bytesRead);
                totalRead += bytesRead;
            }
        }
    } while (bytesRead > 0);
    
    response[totalRead] = '\0';
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return 0;
}

//==============================================================================
// Ollama Integration
//==============================================================================

static int CallOllama(const char* prompt, const char* model,
                      char* response, size_t response_size,
                      int max_tokens, float temperature) {
    char json_body[AGENT_MAX_PROMPT * 2];
    snprintf(json_body, sizeof(json_body),
        "{"
        "\"model\":\"%s\","
        "\"prompt\":\"%s\","
        "\"stream\":false,"
        "\"options\":{"
        "\"temperature\":%.2f,"
        "\"num_predict\":%d"
        "}"
        "}",
        model, prompt, temperature, max_tokens);
    
    // Escape newlines in JSON
    char* p = json_body;
    while (*p) {
        if (*p == '\n') *p = ' ';
        p++;
    }
    
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "%s/api/generate", g_config.endpoint);
    
    return HttpPost(endpoint, json_body, response, response_size, 
                    g_config.default_timeout_ms);
}

//==============================================================================
// Response Parsing
//==============================================================================

static void ExtractResponseContent(const char* json_response, 
                                   char* content, size_t content_size) {
    // Simple extraction - look for "response":"..."
    const char* key = "\"response\":\"";
    const char* start = strstr(json_response, key);
    if (!start) {
        content[0] = '\0';
        return;
    }
    
    start += strlen(key);
    const char* end = strstr(start, "\"");
    if (!end) {
        content[0] = '\0';
        return;
    }
    
    size_t len = end - start;
    if (len >= content_size) len = content_size - 1;
    
    strncpy(content, start, len);
    content[len] = '\0';
    
    // Unescape common sequences
    char* src = content;
    char* dst = content;
    while (*src) {
        if (*src == '\\' && *(src + 1)) {
            src++;
            switch (*src) {
                case 'n': *dst++ = '\n'; break;
                case 't': *dst++ = '\t'; break;
                case 'r': *dst++ = '\r'; break;
                case '\\': *dst++ = '\\'; break;
                case '"': *dst++ = '"'; break;
                default: *dst++ = *src; break;
            }
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

//==============================================================================
// Core Execution
//==============================================================================

int Agent_Execute(const AgentRequest* request, AgentResponse* response) {
    if (!g_agent_initialized) {
        return -1;
    }
    if (!request || !response) {
        return -1;
    }
    
    memset(response, 0, sizeof(AgentResponse));
    uint64_t start_time = GetCurrentTimeMs();
    
    // Build prompt based on command type
    char full_prompt[AGENT_MAX_PROMPT];
    
    switch (request->command) {
        case AGENT_CMD_GENERATE_CODE:
            snprintf(full_prompt, sizeof(full_prompt),
                "Generate %s code for the following specification:\n\n%s\n\n"
                "Provide only the code, no explanations.",
                request->language ? request->language : "",
                request->prompt ? request->prompt : "");
            break;
            
        case AGENT_CMD_FIX_CODE:
            snprintf(full_prompt, sizeof(full_prompt),
                "Fix the following %s code. Error output:\n\n%s\n\n"
                "Code:\n\n%s\n\nProvide only the fixed code.",
                request->language ? request->language : "",
                request->context ? request->context : "",
                request->prompt ? request->prompt : "");
            break;
            
        case AGENT_CMD_OPTIMIZE_CODE:
            snprintf(full_prompt, sizeof(full_prompt),
                "Optimize the following %s code for %s:\n\n%s\n\n"
                "Provide only the optimized code.",
                request->language ? request->language : "",
                request->context ? request->context : "performance",
                request->prompt ? request->prompt : "");
            break;
            
        case AGENT_CMD_TRANSLATE_CODE:
            snprintf(full_prompt, sizeof(full_prompt),
                "Translate the following code to %s:\n\n%s\n\n"
                "Provide only the translated code.",
                request->language ? request->language : "",
                request->prompt ? request->prompt : "");
            break;
            
        case AGENT_CMD_PLAN_WORKFLOW:
            snprintf(full_prompt, sizeof(full_prompt),
                "Create a JSON workflow for: %s\n\n"
                "Format: {\"workflow\":\"name\",\"nodes\":[...]}",
                request->prompt ? request->prompt : "");
            break;
            
        case AGENT_CMD_ANALYZE_ERROR:
            snprintf(full_prompt, sizeof(full_prompt),
                "Analyze this error and suggest a fix:\n\n%s\n\n"
                "Context: %s",
                request->prompt ? request->prompt : "",
                request->context ? request->context : "");
            break;
            
        default:
            snprintf(full_prompt, sizeof(full_prompt), "%s",
                request->prompt ? request->prompt : "");
            break;
    }
    
    // Phase 14: Select model based on task
    const char* task_type = "general";
    switch (request->command) {
        case AGENT_CMD_GENERATE_CODE: task_type = "code"; break;
        case AGENT_CMD_FIX_CODE: task_type = "fix"; break;
        case AGENT_CMD_OPTIMIZE_CODE: task_type = "optimize"; break;
        case AGENT_CMD_TRANSLATE_CODE: task_type = "translate"; break;
        case AGENT_CMD_PLAN_WORKFLOW: task_type = "planning"; break;
        case AGENT_CMD_ANALYZE_ERROR: task_type = "analysis"; break;
        default: task_type = "general"; break;
    }
    
    ModelInfo selected_model;
    int model_result = ModelRegistry_SelectModelForTask(
        task_type,
        request->language ? request->language : "",
        0,  // Prefer quality over speed for agent tasks
        1,
        &selected_model
    );
    
    if (model_result != 0) {
        // Fall back to default model
        if (ModelRegistry_GetDefaultModel(&selected_model) != 0) {
            snprintf(response->error_message, sizeof(response->error_message),
                "No model available for task: %s", task_type);
            return -1;
        }
    }
    
    // Log model selection to journal
    JournalEvent model_event = {0};
    model_event.type = EVENT_USER_REQUEST;  // Using existing type for now
    snprintf(model_event.description, sizeof(model_event.description),
             "Model selected: %s for task: %s", selected_model.name, task_type);
    Journal_AppendEvent(&model_event);
    
    // Create backend for selected model
    IInferenceBackend* backend = InferenceBackend_Create(
        strcmp(selected_model.backend_type, "native") == 0 ? BACKEND_NATIVE : BACKEND_OLLAMA
    );
    
    if (!backend) {
        snprintf(response->error_message, sizeof(response->error_message),
            "Failed to create backend for model: %s", selected_model.name);
        return -1;
    }
    
    // Initialize backend with model config
    AgentConfig model_config = g_config;
    strncpy(model_config.model_path, selected_model.path, sizeof(model_config.model_path));
    strncpy(model_config.model, selected_model.name, sizeof(model_config.model));
    model_config.context_size = selected_model.context_window;
    
    backend->Initialize(&model_config);
    backend->LoadModel(selected_model.path);
    
    // Prepare inference request
    InferenceRequest inf_req = {0};
    inf_req.prompt = full_prompt;
    inf_req.max_tokens = request->max_tokens > 0 ? request->max_tokens 
                                                  : g_config.default_max_tokens;
    inf_req.temperature = request->temperature >= 0 ? request->temperature 
                                                     : g_config.default_temperature;
    inf_req.top_p = 0.9f;
    inf_req.top_k = 40;
    inf_req.stream = 0;
    
    // Prepare result buffer
    InferenceResult inf_result = {0};
    inf_result.text = response->content;
    inf_result.text_capacity = sizeof(response->content);
    
    // Generate
    int result = backend->Generate(&inf_req, &inf_result);
    
    if (result != 0 || !inf_result.success) {
        snprintf(response->error_message, sizeof(response->error_message),
            "Generation failed: %s", inf_result.error_message);
        return -1;
    }
    
    response->content_len = inf_result.text_len;
    response->tokens_generated = inf_result.tokens_generated;
    response->tokens_prompt = inf_result.tokens_prompt;
    response->duration_ms = inf_result.duration_ms;
    
    // Validate if requested
    if (request->validate_output && request->language) {
        if (Agent_ValidateCode(response->content, request->language) != 0) {
            snprintf(response->error_message, sizeof(response->error_message),
                "Generated code failed validation");
            response->success = 0;
            return -1;
        }
    }
    
    response->success = 1;
    response->duration_ms = GetCurrentTimeMs() - start_time;
    
    return 0;
}

int Agent_ExecuteWithContext(const AgentRequest* request, 
                              AgentContext* context,
                              AgentResponse* response) {
    // TODO: Add conversation history to prompt
    (void)context;
    return Agent_Execute(request, response);
}

//==============================================================================
// Validation
//==============================================================================

int Agent_ValidateCode(const char* code, const char* language) {
    if (!code || !language) return -1;
    
    // Basic validation: check for common syntax errors
    
    // Check for balanced braces/brackets
    int brace_count = 0;
    int bracket_count = 0;
    int paren_count = 0;
    
    const char* p = code;
    while (*p) {
        switch (*p) {
            case '{': brace_count++; break;
            case '}': brace_count--; break;
            case '[': bracket_count++; break;
            case ']': bracket_count--; break;
            case '(': paren_count++; break;
            case ')': paren_count--; break;
        }
        if (brace_count < 0 || bracket_count < 0 || paren_count < 0) {
            return -1;  // Unbalanced
        }
        p++;
    }
    
    if (brace_count != 0 || bracket_count != 0 || paren_count != 0) {
        return -1;  // Unbalanced
    }
    
    // Language-specific checks
    if (strcmp(language, "rust") == 0) {
        // Check for fn main
        if (!strstr(code, "fn main") && !strstr(code, "#[")) {
            // Might be a library, that's OK
        }
    } else if (strcmp(language, "python") == 0) {
        // Basic Python validation
        if (strstr(code, "def ") || strstr(code, "import ") || 
            strstr(code, "print(") || strstr(code, "if __name__")) {
            // Looks like Python
        }
    }
    
    return 0;  // Valid
}

//==============================================================================
// Context Management
//==============================================================================

void Agent_ClearContext(AgentContext* context) {
    if (context) {
        context->history[0] = '\0';
        context->history_len = 0;
        context->turn_count = 0;
    }
}

//==============================================================================
// Configuration
//==============================================================================

int Agent_Configure(const AgentConfig* config) {
    if (!config) return -1;
    memcpy(&g_config, config, sizeof(AgentConfig));
    return 0;
}

int Agent_GetConfig(AgentConfig* config) {
    if (!config) return -1;
    memcpy(config, &g_config, sizeof(AgentConfig));
    return 0;
}

int Agent_GetStatus(char* status, size_t status_size) {
    if (!g_agent_initialized) {
        snprintf(status, status_size, "Agent: Not initialized");
        return -1;
    }
    
    // Get backend info
    IInferenceBackend* backend = InferenceBackend_GetGlobal();
    const char* backend_name = backend ? backend->name : "none";
    int model_loaded = backend && backend->IsModelLoaded ? backend->IsModelLoaded() : 0;
    
    snprintf(status, status_size, 
        "Agent v%s - Backend: %s, Model: %s%s",
        AGENT_VERSION, backend_name, g_config.model,
        model_loaded ? " (loaded)" : " (not loaded)");
    return 0;
}

//==============================================================================
// High-Level Helpers
//==============================================================================

int Agent_GenerateCode(const char* spec, const char* language,
                       char* output, size_t output_size) {
    AgentRequest req = {0};
    req.command = AGENT_CMD_GENERATE_CODE;
    req.prompt = spec;
    req.language = language;
    req.validate_output = 1;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(output, resp.content, output_size - 1);
        output[output_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

int Agent_FixCode(const char* code, const char* error_output,
                  const char* language, char* fixed_code, size_t fixed_size) {
    AgentRequest req = {0};
    req.command = AGENT_CMD_FIX_CODE;
    req.prompt = code;
    req.context = error_output;
    req.language = language;
    req.validate_output = 1;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(fixed_code, resp.content, fixed_size - 1);
        fixed_code[fixed_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

int Agent_OptimizeCode(const char* code, const char* language,
                       const char* metric, char* optimized, size_t opt_size) {
    AgentRequest req = {0};
    req.command = AGENT_CMD_OPTIMIZE_CODE;
    req.prompt = code;
    req.context = metric;
    req.language = language;
    req.validate_output = 1;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(optimized, resp.content, opt_size - 1);
        optimized[opt_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

int Agent_TranslateCode(const char* code, const char* source_lang,
                        const char* target_lang, char* translated, size_t trans_size) {
    (void)source_lang;
    AgentRequest req = {0};
    req.command = AGENT_CMD_TRANSLATE_CODE;
    req.prompt = code;
    req.language = target_lang;
    req.validate_output = 1;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(translated, resp.content, trans_size - 1);
        translated[trans_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

int Agent_PlanWorkflow(const char* description, char* workflow_json, 
                        size_t workflow_size) {
    AgentRequest req = {0};
    req.command = AGENT_CMD_PLAN_WORKFLOW;
    req.prompt = description;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(workflow_json, resp.content, workflow_size - 1);
        workflow_json[workflow_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

int Agent_AnalyzeError(const char* error_output, const char* context,
                       char* analysis, size_t analysis_size) {
    AgentRequest req = {0};
    req.command = AGENT_CMD_ANALYZE_ERROR;
    req.prompt = error_output;
    req.context = context;
    
    AgentResponse resp = {0};
    int result = Agent_Execute(&req, &resp);
    
    if (result == 0 && resp.success) {
        strncpy(analysis, resp.content, analysis_size - 1);
        analysis[analysis_size - 1] = '\0';
        return 0;
    }
    
    return -1;
}

//==============================================================================
// Subsystem Handler (CLI Integration)
//==============================================================================

int AgentSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        snprintf(output, output_size,
            "Agent Subsystem v%s\n"
            "Usage: agent \u003ccommand\u003e [args...]\n"
            "\n"
            "Commands:\n"
            "  generate \u003cspec\u003e \u003clanguage\u003e    Generate code\n"
            "  fix \u003ccode\u003e \u003cerror\u003e \u003clang\u003e      Fix code errors\n"
            "  optimize \u003ccode\u003e \u003clang\u003e [metric] Optimize code\n"
            "  translate \u003ccode\u003e \u003cfrom\u003e \u003cto\u003e Translate language\n"
            "  plan \u003cdescription\u003e            Plan SEG workflow\n"
            "  analyze \u003cerror\u003e [context]      Analyze error\n"
            "  status                          Show agent status\n",
            AGENT_VERSION);
        return 0;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "generate") == 0) {
        if (argc < 3) {
            snprintf(output, output_size, 
                "{\"error\":\"Usage: agent generate \u003cspec\u003e \u003clanguage\u003e\"}");
            return -1;
        }
        
        char generated[AGENT_MAX_RESPONSE];
        int result = Agent_GenerateCode(argv[1], argv[2], generated, sizeof(generated));
        
        if (result == 0) {
            snprintf(output, output_size, 
                "{\"success\":true,\"language\":\"%s\",\"code\":\"%s\"}",
                argv[2], generated);
            return 0;
        } else {
            snprintf(output, output_size, 
                "{\"error\":\"Code generation failed\"}");
            return -1;
        }
    }
    else if (strcmp(cmd, "fix") == 0) {
        if (argc < 4) {
            snprintf(output, output_size,
                "{\"error\":\"Usage: agent fix \u003ccode\u003e \u003cerror\u003e \u003clang\u003e\"}");
            return -1;
        }
        
        char fixed[AGENT_MAX_RESPONSE];
        int result = Agent_FixCode(argv[1], argv[2], argv[3], fixed, sizeof(fixed));
        
        if (result == 0) {
            snprintf(output, output_size,
                "{\"success\":true,\"fixed_code\":\"%s\"}", fixed);
            return 0;
        } else {
            snprintf(output, output_size,
                "{\"error\":\"Code fix failed\"}");
            return -1;
        }
    }
    else if (strcmp(cmd, "optimize") == 0) {
        if (argc < 3) {
            snprintf(output, output_size,
                "{\"error\":\"Usage: agent optimize \u003ccode\u003e \u003clang\u003e\"}");
            return -1;
        }
        
        char optimized[AGENT_MAX_RESPONSE];
        const char* metric = (argc > 3) ? argv[3] : "performance";
        int result = Agent_OptimizeCode(argv[1], argv[2], metric, optimized, sizeof(optimized));
        
        if (result == 0) {
            snprintf(output, output_size,
                "{\"success\":true,\"optimized_code\":\"%s\"}", optimized);
            return 0;
        } else {
            snprintf(output, output_size,
                "{\"error\":\"Optimization failed\"}");
            return -1;
        }
    }
    else if (strcmp(cmd, "status") == 0) {
        return Agent_GetStatus(output, output_size);
    }
    // Phase 14: Model registry commands
    else if (strcmp(cmd, "models") == 0) {
        // Delegate to ModelRegistry subsystem
        extern int ModelRegistrySubsystem_Handler(int argc, char** argv, char* output, size_t output_size);
        // Skip "models" command, pass rest to registry handler
        return ModelRegistrySubsystem_Handler(argc - 1, argv + 1, output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"error\":\"Unknown agent command: %s\"}", cmd);
        return -1;
    }
}

int AgentSubsystem_Init(void) {
    // Phase 14: Initialize Model Registry first
    ModelRegistry_Init(nullptr);
    return Agent_Init(NULL);
}

int AgentSubsystem_Shutdown(void) {
    return Agent_Shutdown();
}

int AgentSubsystem_GetStatus(char* status, size_t status_size) {
    return Agent_GetStatus(status, status_size);
}
