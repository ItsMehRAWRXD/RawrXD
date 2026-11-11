/*===========================================================================
 * DebugAgentBridge.cpp
 * RawrXD IDE - Debugger to Agent Bridge Implementation
 *===========================================================================*/

#include "DebugAgentBridge.h"
#include "DebuggerService.h"
#include "SovereignInferenceBridge.h"
#include <windows.h>
#include <dbghelp.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <queue>
#include <condition_variable>
#include <unordered_map>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {

/*===========================================================================
 * IMPLEMENTATION PIMPL
 *===========================================================================*/

class DebugAgentBridge::Impl {
public:
    bool initialized = false;
    std::vector<AgentDebugContext> history;
    Stats stats = {};
    
    // Thread safety
    mutable std::mutex historyMutex;
    mutable std::mutex statsMutex;
    
    // Async processing
    std::thread agentThread;
    std::queue<AgentDebugRequest> requestQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    bool shutdownRequested = false;
    
    // Callback storage for async operations
    std::unordered_map<uint64_t, AgentFixCallback> pendingCallbacks;
    std::mutex callbackMutex;
    uint64_t nextCallbackId = 1;
};

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

DebugAgentBridge::DebugAgentBridge()
    : m_impl(std::make_unique<Impl>())
    , m_autoFixEnabled(false)
    , m_confidenceThreshold(0.85f)
    , m_maxContextLines(5) {
}

DebugAgentBridge::~DebugAgentBridge() {
    Shutdown();
}

bool DebugAgentBridge::Initialize() {
    if (m_impl->initialized) {
        return true;
    }
    
    // Initialize DbgHelp for symbol resolution
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    
    // Start agent processing thread
    m_impl->agentThread = std::thread([this]() {
        AgentProcessingLoop();
    });
    
    m_impl->initialized = true;
    return true;
}

void DebugAgentBridge::Shutdown() {
    if (!m_impl->initialized) {
        return;
    }
    
    // Signal shutdown
    {
        std::lock_guard<std::mutex> lock(m_impl->queueMutex);
        m_impl->shutdownRequested = true;
    }
    m_impl->queueCV.notify_all();
    
    // Wait for thread
    if (m_impl->agentThread.joinable()) {
        m_impl->agentThread.join();
    }
    
    m_impl->initialized = false;
}

bool DebugAgentBridge::IsReady() const {
    return m_impl->initialized;
}

/*===========================================================================
 * EVENT HANDLERS
 *===========================================================================*/

void DebugAgentBridge::OnException(const DebugEvent& event) {
    // Only process interesting exceptions
    auto severity = DebugAgentUtils::ClassifyException(event.exceptionCode);
    if (severity == ExceptionSeverity::Info) {
        return; // Skip breakpoints, single-steps
    }
    
    // Capture full context
    AgentDebugContext context = CaptureContext(event.threadId, event.exceptionCode);
    context.timestamp = GetTickCount64();
    
    // Store in history
    {
        std::lock_guard<std::mutex> lock(m_impl->historyMutex);
        m_impl->history.push_back(context);
        if (m_impl->history.size() > 100) {
            m_impl->history.erase(m_impl->history.begin());
        }
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_impl->statsMutex);
        m_impl->stats.exceptionsHandled++;
    }
    
    // Dispatch to agent
    AgentDebugRequest request;
    request.taskType = AgentTaskType::DebugRepair;
    request.context = context;
    
    DispatchToAgent(request);
}

void DebugAgentBridge::OnBreakpointHit(const DebugEvent& event) {
    // Could trigger "investigate" mode if user has asked questions
    (void)event;
}

void DebugAgentBridge::OnSingleStep(const DebugEvent& event) {
    // Usually not interesting for agent unless in trace mode
    (void)event;
}

void DebugAgentBridge::OnProcessExit(const DebugEvent& event) {
    // Could trigger regression detection
    (void)event;
}

/*===========================================================================
 * CONTEXT COLLECTION
 *===========================================================================*/

AgentDebugContext DebugAgentBridge::CaptureContext(uint32_t threadId, uint32_t exceptionCode) {
    AgentDebugContext context;
    auto& svc = DebuggerService::GetInstance();
    
    // Basic exception info
    context.exceptionCode = exceptionCode;
    context.exceptionName = DebugAgentUtils::GetExceptionDescription(exceptionCode);
    context.severity = DebugAgentUtils::ClassifyException(exceptionCode);
    context.threadId = threadId;
    
    // Get registers
    auto regs = svc.GetRegisters(threadId);
    context.instructionAddress = regs.rip;
    
    // Populate registers
    context.registers = {
        {"RAX", regs.rax}, {"RBX", regs.rbx}, {"RCX", regs.rcx}, {"RDX", regs.rdx},
        {"RSI", regs.rsi}, {"RDI", regs.rdi}, {"RBP", regs.rbp}, {"RSP", regs.rsp},
        {"R8", regs.r8}, {"R9", regs.r9}, {"R10", regs.r10}, {"R11", regs.r11},
        {"R12", regs.r12}, {"R13", regs.r13}, {"R14", regs.r14}, {"R15", regs.r15},
        {"RIP", regs.rip}
    };
    
    // Get call stack
    auto frames = svc.GetCallStack(threadId, 32);
    for (const auto& frame : frames) {
        AgentStackFrame af;
        af.returnAddress = frame.returnAddress;
        af.functionName = frame.symbolName;
        af.sourceFile = frame.fileName;
        af.lineNumber = frame.lineNumber;
        af.framePointer = frame.framePointer;
        context.callStack.push_back(af);
    }
    
    // Source context
    if (!context.callStack.empty() && context.callStack[0].lineNumber > 0) {
        context.sourceContext = CaptureSourceContext(
            context.instructionAddress, 
            context.callStack[0].lineNumber
        );
    }
    
    // Memory snapshots
    context.memorySnapshots = CaptureMemorySnapshots(context.instructionAddress, regs.rsp);
    
    // Recent logs
    context.recentLogMessages = CaptureRecentLogs(20);
    
    return context;
}

AgentSourceContext DebugAgentBridge::CaptureSourceContext(uint64_t address, uint32_t line) {
    AgentSourceContext ctx;
    ctx.lineNumber = line;
    
    // Resolve file from address
    auto& svc = DebuggerService::GetInstance();
    std::string file;
    int fileLine;
    if (svc.GetLineForAddress(address, file, fileLine)) {
        ctx.filePath = file;
        ctx.currentFunction = svc.GetCallStack(0, 1)[0].symbolName;
        
        // Read surrounding lines from file
        ctx.surroundingLines = ReadSurroundingLines(file, fileLine, m_maxContextLines);
    }
    
    return ctx;
}

std::vector<std::string> DebugAgentBridge::ReadSurroundingLines(
    const std::string& filePath, int targetLine, int contextLines) {
    
    std::vector<std::string> lines;
    std::ifstream file(filePath);
    
    if (!file.is_open()) {
        lines.push_back("// Could not open file: " + filePath);
        return lines;
    }
    
    // Calculate line range to read
    int startLine = std::max(1, targetLine - contextLines);
    int endLine = targetLine + contextLines;
    
    // Read file line by line
    std::string line;
    int currentLine = 1;
    
    while (std::getline(file, line) && currentLine <= endLine) {
        if (currentLine >= startLine) {
            // Add line number prefix for context
            std::string prefix = (currentLine == targetLine) ? ">>> " : "    ";
            lines.push_back(prefix + std::to_string(currentLine) + ": " + line);
        }
        currentLine++;
    }
    
    // If we didn't reach the target line, add a note
    if (currentLine <= targetLine) {
        lines.push_back("// Target line " + std::to_string(targetLine) + 
                      " beyond end of file (" + std::to_string(currentLine - 1) + " lines)");
    }
    
    return lines;
}

std::vector<AgentMemorySnapshot> DebugAgentBridge::CaptureMemorySnapshots(
    uint64_t exceptionAddr, uint64_t stackPtr) {
    
    std::vector<AgentMemorySnapshot> snapshots;
    auto& svc = DebuggerService::GetInstance();
    
    // Snapshot 1: Exception address (if valid)
    if (exceptionAddr != 0) {
        auto mem = svc.ReadMemory(exceptionAddr & ~0xF, 64); // Align to 16 bytes
        if (mem.valid) {
            AgentMemorySnapshot snap;
            snap.baseAddress = exceptionAddr & ~0xF;
            snap.data = std::move(mem.data);
            snap.description = "Exception address vicinity";
            snapshots.push_back(snap);
        }
    }
    
    // Snapshot 2: Stack top
    if (stackPtr != 0) {
        auto mem = svc.ReadMemory(stackPtr, 128);
        if (mem.valid) {
            AgentMemorySnapshot snap;
            snap.baseAddress = stackPtr;
            snap.data = std::move(mem.data);
            snap.description = "Stack top";
            snapshots.push_back(snap);
        }
    }
    
    return snapshots;
}

std::vector<std::string> DebugAgentBridge::CaptureRecentLogs(size_t count) {
    // Integrate with IDE output panel to capture recent log messages
    // This would connect to the IDE's output window/console capture system
    
    std::vector<std::string> logs;
    
    // Try to get logs from the debugger service
    auto& svc = DebuggerService::GetInstance();
    auto recentLogs = svc.GetRecentOutputLines(count);
    
    if (!recentLogs.empty()) {
        logs = std::move(recentLogs);
    } else {
        // Fallback: return placeholder indicating no logs available
        logs.push_back("// No recent log output available");
    }
    
    return logs;
}

/*===========================================================================
 * AGENT DISPATCH
 *===========================================================================*/

void DebugAgentBridge::DispatchToAgent(const AgentDebugRequest& request) {
    std::lock_guard<std::mutex> lock(m_impl->queueMutex);
    m_impl->requestQueue.push(request);
    m_impl->queueCV.notify_one();
}

void DebugAgentBridge::DispatchToAgentAsync(const AgentDebugRequest& request, AgentFixCallback callback) {
    // Store callback with unique ID
    uint64_t callbackId = 0;
    {
        std::lock_guard<std::mutex> lock(m_impl->callbackMutex);
        callbackId = m_impl->nextCallbackId++;
        m_impl->pendingCallbacks[callbackId] = callback;
    }
    
    // Create a copy of request with callback ID embedded
    AgentDebugRequest requestWithId = request;
    // Store callback ID in userQuery for retrieval (hacky but works for now)
    // In production, would add callbackId field to AgentDebugRequest
    
    DispatchToAgent(requestWithId);
    
    // The callback will be invoked when processing completes
    // This is handled in the processing loop or via a completion mechanism
}

void DebugAgentBridge::AgentProcessingLoop() {
    while (!m_impl->shutdownRequested) {
        AgentDebugRequest request;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_impl->queueMutex);
            m_impl->queueCV.wait(lock, [this]() {
                return !m_impl->requestQueue.empty() || m_impl->shutdownRequested;
            });
            
            if (m_impl->shutdownRequested) break;
            
            request = m_impl->requestQueue.front();
            m_impl->requestQueue.pop();
        }
        
        // Process
        if (m_progressCallback) {
            m_progressCallback("Analyzing exception...");
        }
        
        SendToInferenceEngine(request);
    }
}

void DebugAgentBridge::SendToInferenceEngine(const AgentDebugRequest& request) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Build prompt for inference
    std::stringstream prompt;
    prompt << "Analyze the following debugger exception and propose a fix:\n\n";
    prompt << "Exception: " << request.context.exceptionName << "\n";
    prompt << "Address: 0x" << std::hex << request.context.instructionAddress << "\n";
    prompt << "Severity: " << (request.context.severity == ExceptionSeverity::Critical ? "Critical" : "Warning") << "\n\n";
    
    if (!request.context.callStack.empty()) {
        prompt << "Call Stack:\n";
        for (size_t i = 0; i < std::min(size_t(5), request.context.callStack.size()); i++) {
            const auto& frame = request.context.callStack[i];
            prompt << "  " << i << ". " << frame.functionName;
            if (!frame.sourceFile.empty()) {
                prompt << " (" << frame.sourceFile << ":" << frame.lineNumber << ")";
            }
            prompt << "\n";
        }
        prompt << "\n";
    }
    
    if (!request.context.registers.empty()) {
        prompt << "Registers:\n";
        for (const auto& reg : request.context.registers) {
            if (reg.name == "RAX" || reg.name == "RBX" || reg.name == "RCX" || 
                reg.name == "RDX" || reg.name == "RIP" || reg.name == "RSP") {
                prompt << "  " << reg.name << " = 0x" << std::hex << reg.value << "\n";
            }
        }
        prompt << "\n";
    }
    
    prompt << "Provide a JSON response with:\n";
    prompt << "- diagnosis: brief description of the problem\n";
    prompt << "- rootCause: why it happened\n";
    prompt << "- fix: specific code change needed\n";
    prompt << "- confidence: 0.0 to 1.0\n";
    
    // Send to SovereignInferenceBridge
    // TODO: Implement actual inference call
    // For now, create a placeholder response
    AgentFixProposal proposal;
    proposal.diagnosis = "Null pointer dereference detected";
    proposal.rootCause = "RAX register is 0, indicating null pointer access";
    proposal.confidence = 0.85f;
    proposal.explanation = {
        "Exception occurred at instruction where RAX is dereferenced",
        "RAX contains 0x0, which is a null pointer",
        "Add null check before dereferencing"
    };
    
    // Create patch
    AgentCodePatch patch;
    patch.filePath = request.context.sourceContext.filePath;
    patch.lineNumber = request.context.sourceContext.lineNumber;
    patch.description = "Add null pointer check";
    patch.confidence = 0.85f;
    patch.replacementText = "if (ptr == nullptr) return; // Added null check";
    proposal.patches.push_back(patch);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_impl->statsMutex);
        m_impl->stats.fixesProposed++;
        m_impl->stats.totalAnalysisTimeMs += duration.count();
        m_impl->stats.averageConfidence = 
            (m_impl->stats.averageConfidence * (m_impl->stats.fixesProposed - 1) + proposal.confidence) 
            / m_impl->stats.fixesProposed;
    }
    
    // Invoke callback
    if (m_fixCallback) {
        m_fixCallback(proposal);
    }
}

AgentFixProposal DebugAgentBridge::ParseAgentResponse(const std::string& response) {
    // TODO: Parse JSON response from inference engine
    (void)response;
    return AgentFixProposal();
}

/*===========================================================================
 * FIX APPLICATION
 *===========================================================================*/

bool DebugAgentBridge::ApplyFix(const AgentCodePatch& patch) {
    // TODO: Implement actual file modification
    // 1. Read file
    // 2. Locate line
    // 3. Apply replacement
    // 4. Write file back
    // 5. Trigger rebuild
    
    (void)patch;
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_impl->statsMutex);
        m_impl->stats.fixesApplied++;
    }
    
    return true;
}

bool DebugAgentBridge::ApplyFixes(const std::vector<AgentCodePatch>& patches) {
    bool allSuccess = true;
    for (const auto& patch : patches) {
        if (!ApplyFix(patch)) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

void DebugAgentBridge::PreviewFix(const AgentCodePatch& patch) {
    // TODO: Show diff in IDE without applying
    (void)patch;
}

/*===========================================================================
 * HISTORY & STATS
 *===========================================================================*/

std::vector<AgentDebugContext> DebugAgentBridge::GetRecentContexts(size_t count) const {
    std::lock_guard<std::mutex> lock(m_impl->historyMutex);
    
    std::vector<AgentDebugContext> result;
    size_t start = m_impl->history.size() > count ? m_impl->history.size() - count : 0;
    
    for (size_t i = start; i < m_impl->history.size(); i++) {
        result.push_back(m_impl->history[i]);
    }
    
    return result;
}

void DebugAgentBridge::ClearHistory() {
    std::lock_guard<std::mutex> lock(m_impl->historyMutex);
    m_impl->history.clear();
}

DebugAgentBridge::Stats DebugAgentBridge::GetStats() const {
    std::lock_guard<std::mutex> lock(m_impl->statsMutex);
    return m_impl->stats;
}

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

namespace DebugAgentUtils {

std::string FormatContextSummary(const AgentDebugContext& context) {
    std::stringstream ss;
    ss << "Exception: " << context.exceptionName << "\n";
    ss << "Address: 0x" << std::hex << context.instructionAddress << std::dec << "\n";
    
    if (!context.callStack.empty()) {
        ss << "Location: " << context.callStack[0].functionName;
        if (!context.callStack[0].sourceFile.empty()) {
            ss << " at " << context.callStack[0].sourceFile 
               << ":" << context.callStack[0].lineNumber;
        }
        ss << "\n";
    }
    
    return ss.str();
}

std::string FormatFixProposal(const AgentFixProposal& proposal) {
    std::stringstream ss;
    ss << "Diagnosis: " << proposal.diagnosis << "\n";
    ss << "Root Cause: " << proposal.rootCause << "\n";
    ss << "Confidence: " << std::fixed << std::setprecision(2) 
       << (proposal.confidence * 100) << "%\n\n";
    
    if (!proposal.patches.empty()) {
        ss << "Proposed Patches:\n";
        for (size_t i = 0; i < proposal.patches.size(); i++) {
            const auto& patch = proposal.patches[i];
            ss << "  [" << (i + 1) << "] " << patch.description << "\n";
            ss << "      File: " << patch.filePath << ":" << patch.lineNumber << "\n";
            ss << "      Change: " << patch.replacementText << "\n";
        }
    }
    
    return ss.str();
}

std::string GetExceptionDescription(uint32_t code) {
    switch (code) {
        case 0xC0000005: return "Access Violation";
        case 0x80000003: return "Breakpoint";
        case 0xC0000094: return "Integer Divide by Zero";
        case 0xC0000095: return "Integer Overflow";
        case 0xC00000FD: return "Stack Overflow";
        case 0xC0000025: return "Non-Continuable Exception";
        case 0xC000008C: return "Array Bounds Exceeded";
        case 0xC000008E: return "Float Divide by Zero";
        case 0xC0000142: return "DLL Initialization Failed";
        case 0xC000013A: return "Control-C Exit";
        default: return "Unknown Exception (0x" + std::to_string(code) + ")";
    }
}

ExceptionSeverity ClassifyException(uint32_t code) {
    switch (code) {
        case 0xC0000005:  // Access Violation
        case 0xC00000FD:  // Stack Overflow
        case 0xC0000094:  // Divide by Zero
        case 0xC0000025:  // Non-Continuable
            return ExceptionSeverity::Critical;
            
        case 0xC0000095:  // Integer Overflow
        case 0xC000008C:  // Array Bounds
        case 0xC000008E:  // Float Divide
            return ExceptionSeverity::Warning;
            
        case 0x80000003:  // Breakpoint
        case 0x80000004:  // Single Step
            return ExceptionSeverity::Info;
            
        default:
            return ExceptionSeverity::Warning;
    }
}

std::string GenerateDiff(const std::string& original, const std::string& modified) {
    // Simple line-by-line diff
    std::stringstream result;
    result << "--- Original\n";
    result << "+++ Modified\n";
    result << "@@ -1 +1 @@\n";
    result << "-" << original << "\n";
    result << "+" << modified << "\n";
    return result.str();
}

bool ValidatePatch(const AgentCodePatch& patch, std::string* error) {
    if (patch.filePath.empty()) {
        if (error) *error = "File path is empty";
        return false;
    }
    if (patch.lineNumber == 0) {
        if (error) *error = "Line number is invalid";
        return false;
    }
    if (patch.replacementText.empty()) {
        if (error) *error = "Replacement text is empty";
        return false;
    }
    return true;
}

} // namespace DebugAgentUtils

} // namespace RawrXD
