//=============================================================================
// RawrXD DAP Adapter Implementation
//=============================================================================
#include "DAPAdapter.hpp"
#include "DebugBridge.hpp"
#include <windows.h>
#include <stdlib.h>

namespace RawrXD {
namespace DAP {

//=============================================================================
// Constructor / Destructor
//=============================================================================

DAPAdapter::DAPAdapter() = default;
DAPAdapter::~DAPAdapter() = default;

void DAPAdapter::AttachSession(DebugSession* session) {
    m_session = session;
}

void DAPAdapter::DetachSession() {
    m_session = nullptr;
}

void DAPAdapter::Stop() {
    m_running = false;
}

//=============================================================================
// Main Loop
//=============================================================================

void DAPAdapter::Run() {
    m_running = true;
    char buffer[65536];
    
    while (m_running) {
        size_t len = 0;
        if (!m_transport.ReadMessage(buffer, sizeof(buffer), len)) {
            // EOF or error
            break;
        }
        
        ProcessMessage(buffer);
    }
}

void DAPAdapter::RunSingleTest(const char* json) {
    ProcessMessage(json);
}

//=============================================================================
// Message Processing
//=============================================================================

void DAPAdapter::ProcessMessage(const char* json) {
    JSONParser parser(json);
    
    char command[256];
    int seq = 0;
    
    if (!parser.GetString("command", command, sizeof(command))) {
        // Might be an event from client (rare)
        return;
    }
    
    parser.GetInt("seq", seq);
    
    DispatchRequest(json, command, seq);
}

void DAPAdapter::DispatchRequest(const char* json, const char* command, int seq) {
    if (strcmp(command, "initialize") == 0) {
        HandleInitialize(seq, json);
    } else if (strcmp(command, "launch") == 0) {
        HandleLaunch(seq, json);
    } else if (strcmp(command, "attach") == 0) {
        HandleAttach(seq, json);
    } else if (strcmp(command, "disconnect") == 0) {
        HandleDisconnect(seq, json);
    } else if (strcmp(command, "configurationDone") == 0) {
        HandleConfigurationDone(seq, json);
    } else if (strcmp(command, "setBreakpoints") == 0) {
        HandleSetBreakpoints(seq, json);
    } else if (strcmp(command, "continue") == 0) {
        HandleContinue(seq, json);
    } else if (strcmp(command, "next") == 0) {
        HandleNext(seq, json);
    } else if (strcmp(command, "stepIn") == 0) {
        HandleStepIn(seq, json);
    } else if (strcmp(command, "stepOut") == 0) {
        HandleStepOut(seq, json);
    } else if (strcmp(command, "pause") == 0) {
        HandlePause(seq, json);
    } else if (strcmp(command, "stackTrace") == 0) {
        HandleStackTrace(seq, json);
    } else if (strcmp(command, "scopes") == 0) {
        HandleScopes(seq, json);
    } else if (strcmp(command, "variables") == 0) {
        HandleVariables(seq, json);
    } else if (strcmp(command, "threads") == 0) {
        HandleThreads(seq, json);
    } else if (strcmp(command, "readMemory") == 0) {
        HandleReadMemory(seq, json);
    } else {
        // Unknown command - send empty success response
        SendEmptyResponse(seq, command);
    }
}

//=============================================================================
// Request Handlers
//=============================================================================

void DAPAdapter::HandleInitialize(int seq, const char* json) {
    m_initialized = true;
    SendInitializeResponse(seq);
}

void DAPAdapter::HandleLaunch(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "launch", false, "No debug session");
        return;
    }
    
    JSONParser parser(json);
    char program[512] = {};
    parser.GetString("program", program, sizeof(program));
    
    // Extract program from arguments if needed
    // DAP sends program in arguments object
    const char* args = strstr(json, "\"program\"");
    if (args) {
        args = strchr(args, ':');
        if (args) {
            args = strchr(args, '"');
            if (args) {
                args++;
                const char* end = strchr(args, '"');
                if (end && end - args < sizeof(program)) {
                    memcpy(program, args, end - args);
                    program[end - args] = 0;
                }
            }
        }
    }
    
    if (strlen(program) == 0) {
        SendResponse(seq, "launch", false, "No program specified");
        return;
    }
    
    // Convert to wide string for LaunchProcess
    wchar_t wprogram[512];
    MultiByteToWideChar(CP_UTF8, 0, program, -1, wprogram, 512);
    
    if (m_session->LaunchProcess(wprogram)) {
        SendResponse(seq, "launch", true);
    } else {
        SendResponse(seq, "launch", false, "Failed to launch process");
    }
}

void DAPAdapter::HandleAttach(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "attach", false, "No debug session");
        return;
    }
    
    JSONParser parser(json);
    int pid = 0;
    parser.GetInt("processId", pid);
    
    if (pid == 0) {
        SendResponse(seq, "attach", false, "No processId specified");
        return;
    }
    
    if (m_session->AttachProcess(pid)) {
        SendResponse(seq, "attach", true);
    } else {
        SendResponse(seq, "attach", false, "Failed to attach to process");
    }
}

void DAPAdapter::HandleDisconnect(int seq, const char* json) {
    if (m_session) {
        m_session->DetachProcess();
    }
    SendResponse(seq, "disconnect", true);
    m_running = false;
}

void DAPAdapter::HandleConfigurationDone(int seq, const char* json) {
    m_configured = true;
    SendResponse(seq, "configurationDone", true);
    
    // If we have a session and it's stopped, send stopped event
    if (m_session && m_session->IsActive()) {
        SendStoppedEvent("entry", m_currentThreadId, 0);
    }
}

void DAPAdapter::HandleSetBreakpoints(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "setBreakpoints", false, "No debug session");
        return;
    }
    
    // Parse source path
    char sourcePath[512] = {};
    JSONParser parser(json);
    
    // Find source.path in JSON
    const char* source = strstr(json, "\"source\"");
    if (source) {
        const char* path = strstr(source, "\"path\"");
        if (path) {
            path = strchr(path, ':');
            if (path) {
                path = strchr(path, '"');
                if (path) {
                    path++;
                    const char* end = strchr(path, '"');
                    if (end && end - path < sizeof(sourcePath)) {
                        memcpy(sourcePath, path, end - path);
                        sourcePath[end - path] = 0;
                    }
                }
            }
        }
    }
    
    // Clear existing breakpoints for this source
    // (In real implementation, track by source)
    
    // Parse breakpoints array
    // For now, just send empty response
    SendSetBreakpointsResponse(seq, json);
}

void DAPAdapter::HandleContinue(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "continue", false, "No debug session");
        return;
    }
    
    if (m_session->ContinueExecution()) {
        // Build continue response
        char response[512];
        JSONWriter writer(response, sizeof(response));
        writer.BeginObject();
        writer.Key("seq"); writer.Int(++m_seq);
        writer.Key("type"); writer.String("response");
        writer.Key("request_seq"); writer.Int(seq);
        writer.Key("success"); writer.Bool(true);
        writer.Key("command"); writer.String("continue");
        writer.Key("body");
        writer.BeginObject();
        writer.Key("allThreadsContinued"); writer.Bool(true);
        writer.EndObject();
        writer.EndObject();
        
        m_transport.WriteMessage(response);
    } else {
        SendResponse(seq, "continue", false, "Failed to continue");
    }
}

void DAPAdapter::HandleNext(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "next", false, "No debug session");
        return;
    }
    
    if (m_session->StepOver()) {
        SendResponse(seq, "next", true);
    } else {
        SendResponse(seq, "next", false, "Failed to step over");
    }
}

void DAPAdapter::HandleStepIn(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "stepIn", false, "No debug session");
        return;
    }
    
    if (m_session->StepInto()) {
        SendResponse(seq, "stepIn", true);
    } else {
        SendResponse(seq, "stepIn", false, "Failed to step in");
    }
}

void DAPAdapter::HandleStepOut(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "stepOut", false, "No debug session");
        return;
    }
    
    if (m_session->StepOut()) {
        SendResponse(seq, "stepOut", true);
    } else {
        SendResponse(seq, "stepOut", false, "Failed to step out");
    }
}

void DAPAdapter::HandlePause(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "pause", false, "No debug session");
        return;
    }
    
    if (m_session->BreakExecution()) {
        SendResponse(seq, "pause", true);
    } else {
        SendResponse(seq, "pause", false, "Failed to break");
    }
}

void DAPAdapter::HandleStackTrace(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "stackTrace", false, "No debug session");
        return;
    }
    
    JSONParser parser(json);
    int threadId = 0;
    parser.GetInt("threadId", threadId);
    
    SendStackTraceResponse(seq, threadId);
}

void DAPAdapter::HandleScopes(int seq, const char* json) {
    JSONParser parser(json);
    int frameId = 0;
    parser.GetInt("frameId", frameId);
    
    SendScopesResponse(seq, frameId);
}

void DAPAdapter::HandleVariables(int seq, const char* json) {
    JSONParser parser(json);
    int variablesReference = 0;
    parser.GetInt("variablesReference", variablesReference);
    
    SendVariablesResponse(seq, variablesReference);
}

void DAPAdapter::HandleThreads(int seq, const char* json) {
    SendThreadsResponse(seq);
}

void DAPAdapter::HandleReadMemory(int seq, const char* json) {
    if (!m_session) {
        SendResponse(seq, "readMemory", false, "No debug session");
        return;
    }
    
    JSONParser parser(json);
    
    // Parse memoryReference (address as hex string)
    char addrStr[32] = {};
    parser.GetString("memoryReference", addrStr, sizeof(addrStr));
    uint64_t addr = strtoull(addrStr, nullptr, 0);
    
    int offset = 0;
    parser.GetInt("offset", offset);
    
    int count = 256;
    parser.GetInt("count", count);
    
    addr += offset;
    
    uint8_t buffer[4096];
    size_t toRead = count < sizeof(buffer) ? count : sizeof(buffer);
    
    if (m_session->ReadMemory(addr, buffer, toRead)) {
        SendReadMemoryResponse(seq, addr, buffer, toRead);
    } else {
        SendResponse(seq, "readMemory", false, "Failed to read memory");
    }
}

//=============================================================================
// Response Builders
//=============================================================================

void DAPAdapter::SendResponse(int seq, const char* command, bool success, const char* message) {
    char response[1024];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(success);
    writer.Key("command"); writer.String(command);
    if (message) {
        writer.Key("message"); writer.String(message);
    }
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendInitializeResponse(int seq) {
    char response[4096];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("initialize");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("supportsConfigurationDoneRequest"); writer.Bool(true);
    writer.Key("supportsFunctionBreakpoints"); writer.Bool(true);
    writer.Key("supportsConditionalBreakpoints"); writer.Bool(true);
    writer.Key("supportsHitConditionalBreakpoints"); writer.Bool(true);
    writer.Key("supportsEvaluateForHovers"); writer.Bool(true);
    writer.Key("supportsSetVariable"); writer.Bool(true);
    writer.Key("supportsExceptionInfoRequest"); writer.Bool(true);
    writer.Key("supportsTerminateDebuggee"); writer.Bool(true);
    writer.Key("supportsLogPoints"); writer.Bool(true);
    writer.Key("supportsReadMemoryRequest"); writer.Bool(true);
    writer.Key("supportsWriteMemoryRequest"); writer.Bool(true);
    writer.Key("supportsDisassembleRequest"); writer.Bool(true);
    writer.Key("supportsInstructionBreakpoints"); writer.Bool(true);
    writer.Key("supportsExceptionFilterOptions"); writer.Bool(true);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendEmptyResponse(int seq, const char* command) {
    SendResponse(seq, command, true);
}

void DAPAdapter::SendSetBreakpointsResponse(int seq, const char* json) {
    // Parse breakpoints from request and build response
    char response[8192];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("setBreakpoints");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("breakpoints");
    writer.BeginArray();
    
    // For now, return empty breakpoints
    // In full implementation, parse breakpoints array and return verified status
    
    writer.EndArray();
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendStackTraceResponse(int seq, int threadId) {
    char response[16384];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("stackTrace");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("stackFrames");
    writer.BeginArray();
    
    if (m_session) {
        auto stack = m_session->GetCallStack();
        int frameId = m_nextFrameId++;
        
        for (size_t i = 0; i < stack.size() && i < 50; ++i) {
            const auto& frame = stack[i];
            
            writer.BeginObject();
            writer.Key("id"); writer.Int(frameId++);
            writer.Key("name"); writer.String(frame.functionName.empty() ? "<unknown>" : frame.functionName.c_str());
            writer.Key("source");
            writer.BeginObject();
            if (!frame.sourceFile.empty()) {
                writer.Key("name"); writer.String(frame.sourceFile.c_str());
                writer.Key("path"); writer.String(frame.sourceFile.c_str());
            }
            writer.EndObject();
            writer.Key("line"); writer.Int(frame.sourceLine);
            writer.Key("column"); writer.Int(0);
            writer.Key("instructionPointerReference"); writer.UInt64(frame.instructionPointer);
            writer.EndObject();
        }
    }
    
    writer.EndArray();
    writer.Key("totalFrames"); writer.Int(m_session ? (int)m_session->GetCallStack().size() : 0);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendScopesResponse(int seq, int frameId) {
    char response[1024];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("scopes");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("scopes");
    writer.BeginArray();
    
    // Locals scope
    writer.BeginObject();
    writer.Key("name"); writer.String("Locals");
    writer.Key("variablesReference"); writer.Int(m_nextVariablesRef++);
    writer.Key("expensive"); writer.Bool(false);
    writer.EndObject();
    
    // Registers scope
    writer.BeginObject();
    writer.Key("name"); writer.String("Registers");
    writer.Key("variablesReference"); writer.Int(m_nextVariablesRef++);
    writer.Key("expensive"); writer.Bool(false);
    writer.EndObject();
    
    writer.EndArray();
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendVariablesResponse(int seq, int variablesReference) {
    char response[8192];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("variables");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("variables");
    writer.BeginArray();
    
    if (m_session) {
        // For now, return registers if this is a registers scope
        // In full implementation, track scope type by variablesReference
        
        RegisterContext ctx;
        if (m_session->GetRegisters(ctx)) {
            struct { const char* name; uint64_t value; } regs[] = {
                { "rax", ctx.rax }, { "rcx", ctx.rcx }, { "rdx", ctx.rdx }, { "rbx", ctx.rbx },
                { "rsp", ctx.rsp }, { "rbp", ctx.rbp }, { "rsi", ctx.rsi }, { "rdi", ctx.rdi },
                { "r8", ctx.r8 }, { "r9", ctx.r9 }, { "r10", ctx.r10 }, { "r11", ctx.r11 },
                { "r12", ctx.r12 }, { "r13", ctx.r13 }, { "r14", ctx.r14 }, { "r15", ctx.r15 },
                { "rip", ctx.rip }
            };
            
            for (int i = 0; i < 17; ++i) {
                writer.BeginObject();
                writer.Key("name"); writer.String(regs[i].name);
                char val[32];
                snprintf(val, sizeof(val), "0x%016llX", regs[i].value);
                writer.Key("value"); writer.String(val);
                writer.Key("type"); writer.String("register");
                writer.EndObject();
            }
        }
    }
    
    writer.EndArray();
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendThreadsResponse(int seq) {
    char response[512];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("threads");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("threads");
    writer.BeginArray();
    
    writer.BeginObject();
    writer.Key("id"); writer.Int(m_currentThreadId);
    writer.Key("name"); writer.String("Main Thread");
    writer.EndObject();
    
    writer.EndArray();
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
}

void DAPAdapter::SendReadMemoryResponse(int seq, uint64_t addr, const void* data, size_t len) {
    // Base64 encode the data
    static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char* encoded = (char*)malloc((len + 2) / 3 * 4 + 1);
    if (!encoded) {
        SendResponse(seq, "readMemory", false, "Memory allocation failed");
        return;
    }
    
    const uint8_t* bytes = (const uint8_t*)data;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = bytes[i] << 16;
        if (i + 1 < len) val |= bytes[i + 1] << 8;
        if (i + 2 < len) val |= bytes[i + 2];
        
        encoded[j++] = base64[(val >> 18) & 0x3F];
        encoded[j++] = base64[(val >> 12) & 0x3F];
        encoded[j++] = (i + 1 < len) ? base64[(val >> 6) & 0x3F] : '=';
        encoded[j++] = (i + 2 < len) ? base64[val & 0x3F] : '=';
    }
    encoded[j] = 0;
    
    char response[8192];
    JSONWriter writer(response, sizeof(response));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("response");
    writer.Key("request_seq"); writer.Int(seq);
    writer.Key("success"); writer.Bool(true);
    writer.Key("command"); writer.String("readMemory");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("address"); writer.String("0x0");  // Would format actual address
    writer.Key("data"); writer.String(encoded);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(response);
    free(encoded);
}

//=============================================================================
// Event Builders
//=============================================================================

void DAPAdapter::SendEvent(const DAPEvent& event) {
    // Base event sending - derived classes handle specifics
}

void DAPAdapter::SendStoppedEvent(const char* reason, int threadId, uint64_t addr) {
    char event[1024];
    JSONWriter writer(event, sizeof(event));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("event");
    writer.Key("event"); writer.String("stopped");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("reason"); writer.String(reason);
    writer.Key("threadId"); writer.Int(threadId);
    writer.Key("allThreadsStopped"); writer.Bool(true);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(event);
}

void DAPAdapter::SendOutputEvent(const char* category, const char* output) {
    char event[4096];
    JSONWriter writer(event, sizeof(event));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("event");
    writer.Key("event"); writer.String("output");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("category"); writer.String(category);
    writer.Key("output"); writer.String(output);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(event);
}

void DAPAdapter::SendExitedEvent(int exitCode) {
    char event[512];
    JSONWriter writer(event, sizeof(event));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("event");
    writer.Key("event"); writer.String("exited");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("exitCode"); writer.Int(exitCode);
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(event);
}

void DAPAdapter::SendTerminatedEvent() {
    char event[256];
    JSONWriter writer(event, sizeof(event));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("event");
    writer.Key("event"); writer.String("terminated");
    writer.EndObject();
    
    m_transport.WriteMessage(event);
}

void DAPAdapter::SendBreakpointEvent(int id, bool verified, const char* reason) {
    char event[512];
    JSONWriter writer(event, sizeof(event));
    writer.BeginObject();
    writer.Key("seq"); writer.Int(++m_seq);
    writer.Key("type"); writer.String("event");
    writer.Key("event"); writer.String("breakpoint");
    writer.Key("body");
    writer.BeginObject();
    writer.Key("reason"); writer.String(reason);
    writer.Key("breakpoint");
    writer.BeginObject();
    writer.Key("id"); writer.Int(id);
    writer.Key("verified"); writer.Bool(verified);
    writer.EndObject();
    writer.EndObject();
    writer.EndObject();
    
    m_transport.WriteMessage(event);
}

} // namespace DAP
} // namespace RawrXD
