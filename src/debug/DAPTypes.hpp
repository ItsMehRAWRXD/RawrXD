//=============================================================================
// RawrXD DAP Types
// Debug Adapter Protocol message structures
// Zero external dependencies - POD types only
//=============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace RawrXD {
namespace DAP {

//=============================================================================
// Base Types
//=============================================================================

struct DAPMessage {
    int seq = 0;
    const char* type = nullptr;  // "request", "response", "event"
};

struct DAPRequest : DAPMessage {
    const char* command = nullptr;
};

struct DAPResponse : DAPMessage {
    int request_seq = 0;
    bool success = false;
    const char* command = nullptr;
    const char* message = nullptr;  // Error message if success=false
};

struct DAPEvent : DAPMessage {
    const char* event = nullptr;
};

//=============================================================================
// Initialize
//=============================================================================

struct InitializeRequest : DAPRequest {
    const char* clientID = nullptr;
    const char* clientName = nullptr;
    const char* adapterID = nullptr;
    const char* locale = nullptr;
    bool linesStartAt1 = true;
    bool columnsStartAt1 = true;
    const char* pathFormat = nullptr;  // "path" or "uri"
    bool supportsVariableType = true;
    bool supportsVariablePaging = false;
    bool supportsRunInTerminalRequest = false;
    bool supportsMemoryReferences = true;
    bool supportsProgressReporting = false;
    bool supportsInvalidatedEvent = false;
};

struct Capabilities {
    bool supportsConfigurationDoneRequest = true;
    bool supportsFunctionBreakpoints = true;
    bool supportsConditionalBreakpoints = true;
    bool supportsHitConditionalBreakpoints = true;
    bool supportsEvaluateForHovers = true;
    bool exceptionBreakpointFilters = false;
    bool supportsStepBack = false;
    bool supportsSetVariable = true;
    bool supportsRestartFrame = false;
    bool supportsGotoTargetsRequest = false;
    bool supportsStepInTargetsRequest = false;
    bool supportsCompletionsRequest = false;
    bool completionTriggerCharacters = false;
    bool supportsModulesRequest = false;
    bool supportsRestartRequest = false;
    bool supportsExceptionOptions = true;
    bool supportsValueFormattingOptions = true;
    bool supportsExceptionInfoRequest = true;
    bool supportTerminateDebuggee = true;
    bool supportSuspendDebuggee = false;
    bool supportsDelayedStackTraceFetching = false;
    bool supportsLoadedSourcesRequest = false;
    bool supportsLogPoints = true;
    bool supportsTerminateThreadsRequest = false;
    bool supportsSetExpression = false;
    bool supportsDataBreakpoints = false;
    bool supportsReadMemoryRequest = true;
    bool supportsWriteMemoryRequest = true;
    bool supportsDisassembleRequest = true;
    bool supportsClipboardContext = false;
    bool supportsSteppingGranularity = false;
    bool supportsInstructionBreakpoints = true;
    bool supportsExceptionFilterOptions = true;
    bool supportsSingleThreadExecutionRequests = false;
};

struct InitializeResponse : DAPResponse {
    Capabilities body;
};

//=============================================================================
// Launch/Attach
//=============================================================================

struct LaunchRequest : DAPRequest {
    const char* program = nullptr;
    const char* args = nullptr;
    const char* cwd = nullptr;
    const char* env = nullptr;
    bool stopOnEntry = false;
    const char* console = nullptr;  // "internalConsole", "integratedTerminal", "externalTerminal"
};

struct AttachRequest : DAPRequest {
    uint32_t processId = 0;
    const char* program = nullptr;
    bool stopOnEntry = false;
};

struct ConfigurationDoneRequest : DAPRequest {
};

struct DisconnectRequest : DAPRequest {
    bool terminateDebuggee = true;
    bool suspendDebuggee = false;
};

//=============================================================================
// Breakpoints
//=============================================================================

struct Source {
    const char* name = nullptr;
    const char* path = nullptr;
    int sourceReference = 0;
};

struct Breakpoint {
    int id = 0;
    bool verified = false;
    const char* message = nullptr;
    Source source;
    int line = 0;
    int column = 0;
    uint64_t instructionReference = 0;
    int offset = 0;
};

struct SourceBreakpoint {
    int line = 0;
    int column = 0;
    const char* condition = nullptr;
    const char* hitCondition = nullptr;
    const char* logMessage = nullptr;
};

struct SetBreakpointsRequest : DAPRequest {
    Source source;
    SourceBreakpoint* breakpoints = nullptr;
    int breakpointCount = 0;
};

struct SetBreakpointsResponse : DAPResponse {
    Breakpoint* breakpoints = nullptr;
    int breakpointCount = 0;
};

struct BreakpointEvent : DAPEvent {
    const char* reason = nullptr;  // "changed", "new", "removed"
    Breakpoint breakpoint;
};

//=============================================================================
// Execution Control
//=============================================================================

struct ContinueRequest : DAPRequest {
    int threadId = 0;
    bool singleThread = false;
};

struct ContinueResponse : DAPResponse {
    bool allThreadsContinued = true;
};

struct NextRequest : DAPRequest {
    int threadId = 0;
    int granularity = 0;  // 0=statement, 1=line, 2=instruction
};

struct StepInRequest : DAPRequest {
    int threadId = 0;
    int targetId = 0;
    int granularity = 0;
};

struct StepOutRequest : DAPRequest {
    int threadId = 0;
    int granularity = 0;
};

struct PauseRequest : DAPRequest {
    int threadId = 0;
};

//=============================================================================
// Stack Trace
//=============================================================================

struct StackFrame {
    int id = 0;
    const char* name = nullptr;
    Source source;
    int line = 0;
    int column = 0;
    uint64_t instructionPointerReference = 0;
    const char* moduleId = nullptr;
    bool presentationHint = false;  // true=label, false=normal, subtle
};

struct StackTraceRequest : DAPRequest {
    int threadId = 0;
    int startFrame = 0;
    int levels = 0;  // 0 = all
};

struct StackTraceResponse : DAPResponse {
    StackFrame* stackFrames = nullptr;
    int totalFrames = 0;
};

//=============================================================================
// Scopes & Variables
//=============================================================================

struct Scope {
    const char* name = nullptr;
    int variablesReference = 0;
    bool expensive = false;
    const char* source = nullptr;  // "locals", "registers", "globals"
};

struct ScopesRequest : DAPRequest {
    int frameId = 0;
};

struct ScopesResponse : DAPResponse {
    Scope* scopes = nullptr;
    int scopeCount = 0;
};

struct Variable {
    const char* name = nullptr;
    const char* value = nullptr;
    const char* type = nullptr;
    int variablesReference = 0;  // >0 if has children
    int namedVariables = 0;
    int indexedVariables = 0;
    const char* evaluateName = nullptr;
    uint64_t memoryReference = 0;
};

struct VariablesRequest : DAPRequest {
    int variablesReference = 0;
    const char* filter = nullptr;  // "indexed" or "named"
    int start = 0;
    int count = 0;
    const char* format = nullptr;
};

struct VariablesResponse : DAPResponse {
    Variable* variables = nullptr;
    int variableCount = 0;
};

//=============================================================================
// Threads
//=============================================================================

struct Thread {
    int id = 0;
    const char* name = nullptr;
};

struct ThreadsRequest : DAPRequest {
};

struct ThreadsResponse : DAPResponse {
    Thread* threads = nullptr;
    int threadCount = 0;
};

//=============================================================================
// Stopped Event
//=============================================================================

struct StoppedEvent : DAPEvent {
    const char* reason = nullptr;  // "step", "breakpoint", "exception", "pause", "entry", "goto", "function breakpoint", "data breakpoint"
    const char* description = nullptr;
    int threadId = 0;
    bool preserveFocusHint = false;
    const char* text = nullptr;
    bool allThreadsStopped = true;
    uint64_t hitBreakpointIds = 0;
};

//=============================================================================
// Output Event
//=============================================================================

struct OutputEvent : DAPEvent {
    const char* category = nullptr;  // "console", "stdout", "stderr", "telemetry"
    const char* output = nullptr;
    int group = 0;  // 0=start, 1=end, 2=more
    uint64_t data = 0;
};

//=============================================================================
// Terminated/Exited Events
//=============================================================================

struct ExitedEvent : DAPEvent {
    int exitCode = 0;
};

struct TerminatedEvent : DAPEvent {
    bool restart = false;
};

//=============================================================================
// Memory
//=============================================================================

struct ReadMemoryRequest : DAPRequest {
    uint64_t memoryReference = 0;
    int offset = 0;
    int count = 0;
};

struct ReadMemoryResponse : DAPResponse {
    const char* address = nullptr;
    int unreadableBytes = 0;
    const char* data = nullptr;  // Base64 encoded
};

} // namespace DAP
} // namespace RawrXD
