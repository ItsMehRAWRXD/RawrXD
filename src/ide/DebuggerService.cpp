/*===========================================================================
 * DebuggerService.cpp
 * RawrXD IDE Debugger Service Implementation
 *===========================================================================*/

#include "DebuggerService.h"
#include "DebugAgentBridge.h"
#include "../debugger/SovereignCDB_Engine.h"
#include <windows.h>
#include <dbghelp.h>
#include <queue>
#include <atomic>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {

/*===========================================================================
 * SPSC RING BUFFER FOR EVENTS
 *===========================================================================*/

template<typename T, size_t Size>
class SPSCRingBuffer {
public:
    static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
    
    SPSCRingBuffer() : m_writeIdx(0), m_readIdx(0) {}
    
    bool Push(const T& item) {
        size_t writeIdx = m_writeIdx.load(std::memory_order_relaxed);
        size_t nextIdx = (writeIdx + 1) & (Size - 1);
        
        if (nextIdx == m_readIdx.load(std::memory_order_acquire)) {
            return false; // Full
        }
        
        m_buffer[writeIdx] = item;
        m_writeIdx.store(nextIdx, std::memory_order_release);
        return true;
    }
    
    bool Pop(T& item) {
        size_t readIdx = m_readIdx.load(std::memory_order_relaxed);
        
        if (readIdx == m_writeIdx.load(std::memory_order_acquire)) {
            return false; // Empty
        }
        
        item = m_buffer[readIdx];
        m_readIdx.store((readIdx + 1) & (Size - 1), std::memory_order_release);
        return true;
    }
    
    bool Empty() const {
        return m_readIdx.load(std::memory_order_acquire) == 
               m_writeIdx.load(std::memory_order_acquire);
    }
    
    size_t Count() const {
        return (m_writeIdx.load(std::memory_order_acquire) - 
                m_readIdx.load(std::memory_order_acquire)) & (Size - 1);
    }

private:
    T m_buffer[Size];
    alignas(64) std::atomic<size_t> m_writeIdx;
    alignas(64) std::atomic<size_t> m_readIdx;
};

/*===========================================================================
 * DEBUGGER SERVICE IMPLEMENTATION
 *===========================================================================*/

struct DebuggerService::Impl {
    // CDB Engine callback wrapper
    static void OnCDBEventWrapper(const CDB_DebugEvent* event, void* userData) {
        auto* self = static_cast<DebuggerService*>(userData);
        self->OnCDBEvent(event);
    }
    
    // Event ring buffer (SPSC: CDB thread -> UI thread)
    SPSCRingBuffer<DebugEvent, 256> eventQueue;
    
    // Current thread context (updated on break)
    uint32_t currentThreadId = 0;
    bool hasContext = false;
};

// Singleton
DebuggerService& DebuggerService::GetInstance() {
    static DebuggerService instance;
    return instance;
}

DebuggerService::DebuggerService() 
    : m_impl(new Impl())
    , m_state(DebugState::Idle)
    , m_nextBreakpointId(1) {
}

DebuggerService::~DebuggerService() {
    Shutdown();
    delete m_impl;
}

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

bool DebuggerService::Initialize() {
    if (IsInitialized()) {
        return true;
    }
    
    // Initialize CDB engine
    CDB_Config config = {};
    config.breakOnEntry = false;  // We'll handle entry point ourselves
    config.breakOnException = true;
    
    if (!CDB_Initialize(&config)) {
        std::lock_guard<std::mutex> lock(m_errorMutex);
        m_lastError = CDB_GetLastError();
        return false;
    }
    
    // Set CDB event callback
    CDB_SetEventCallback(Impl::OnCDBEventWrapper, this);
    
    return true;
}

void DebuggerService::Shutdown() {
    if (m_state != DebugState::Idle) {
        Terminate();
    }
    
    CDB_Shutdown();
    
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    m_breakpoints.clear();
}

bool DebuggerService::IsInitialized() const {
    return CDB_IsReady();
}

/*===========================================================================
 * SESSION CONTROL
 *===========================================================================*/

bool DebuggerService::LaunchProcess(const std::string& exePath,
                                     const std::string& cmdLine,
                                     const std::string& workingDir) {
    if (!IsInitialized()) {
        std::lock_guard<std::mutex> lock(m_errorMutex);
        m_lastError = "Debugger not initialized";
        return false;
    }
    
    UpdateState(DebugState::Launching);
    
    if (!CDB_LaunchProcess(exePath.c_str(), 
                           cmdLine.empty() ? nullptr : cmdLine.c_str(),
                           workingDir.empty() ? nullptr : workingDir.c_str(),
                           nullptr)) {
        std::lock_guard<std::mutex> lock(m_errorMutex);
        m_lastError = CDB_GetLastError();
        UpdateState(DebugState::Idle);
        return false;
    }
    
    // Resolve any pending breakpoints
    ResolvePendingBreakpoints();
    
    UpdateState(DebugState::Running);
    return true;
}

bool DebuggerService::AttachToProcess(uint32_t processId) {
    if (!IsInitialized()) {
        std::lock_guard<std::mutex> lock(m_errorMutex);
        m_lastError = "Debugger not initialized";
        return false;
    }
    
    UpdateState(DebugState::Launching);
    
    if (!CDB_AttachProcess(processId)) {
        std::lock_guard<std::mutex> lock(m_errorMutex);
        m_lastError = CDB_GetLastError();
        UpdateState(DebugState::Idle);
        return false;
    }
    
    ResolvePendingBreakpoints();
    UpdateState(DebugState::Running);
    return true;
}

void DebuggerService::Detach() {
    if (m_state == DebugState::Idle) {
        return;
    }
    
    CDB_Detach();
    UpdateState(DebugState::Idle);
}

void DebuggerService::Terminate(uint32_t exitCode) {
    if (m_state == DebugState::Idle) {
        return;
    }
    
    CDB_Terminate(exitCode);
    UpdateState(DebugState::Terminated);
}

/*===========================================================================
 * EXECUTION CONTROL
 *===========================================================================*/

void DebuggerService::Continue() {
    if (m_state != DebugState::Paused && m_state != DebugState::Stepping) {
        return;
    }
    
    InvalidateThreadCache();
    CDB_Continue(m_impl->currentThreadId, false);
    UpdateState(DebugState::Running);
}

void DebuggerService::Pause() {
    if (m_state != DebugState::Running) {
        return;
    }
    
    CDB_Break();
}

void DebuggerService::StepInto() {
    if (m_state != DebugState::Paused) {
        return;
    }
    
    InvalidateThreadCache();
    CDB_StepInto(m_impl->currentThreadId);
    UpdateState(DebugState::Stepping);
}

void DebuggerService::StepOver() {
    if (m_state != DebugState::Paused) {
        return;
    }
    
    InvalidateThreadCache();
    CDB_StepOver(m_impl->currentThreadId);
    UpdateState(DebugState::Stepping);
}

void DebuggerService::StepOut() {
    if (m_state != DebugState::Paused) {
        return;
    }
    
    InvalidateThreadCache();
    CDB_StepOut(m_impl->currentThreadId);
    UpdateState(DebugState::Stepping);
}

/*===========================================================================
 * STATE QUERIES
 *===========================================================================*/

DebugState DebuggerService::GetState() const {
    std::lock_guard<std::mutex> lock(m_stateMutex);
    return m_state;
}

bool DebuggerService::IsRunning() const {
    return GetState() == DebugState::Running;
}

bool DebuggerService::IsPaused() const {
    auto state = GetState();
    return state == DebugState::Paused || state == DebugState::Stepping;
}

uint32_t DebuggerService::GetProcessId() const {
    // Get from CDB engine
    return 0; // TODO: Expose from CDB
}

std::string DebuggerService::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_errorMutex);
    return m_lastError;
}

/*===========================================================================
 * BREAKPOINT MANAGEMENT (Shadow Table)
 *===========================================================================*/

uint32_t DebuggerService::SetBreakpoint(const std::string& filePath, int lineNumber) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    // Check if already exists
    for (const auto& bp : m_breakpoints) {
        if (bp.filePath == filePath && bp.lineNumber == lineNumber) {
            return bp.id;
        }
    }
    
    // Create new breakpoint
    BreakpointInfo bp;
    bp.id = m_nextBreakpointId++;
    bp.filePath = filePath;
    bp.lineNumber = lineNumber;
    bp.enabled = true;
    bp.resolved = false;
    
    // Try to resolve address
    {
        std::lock_guard<std::mutex> mapLock(m_sourceMapMutex);
        auto it = m_sourceToAddr.find({filePath, lineNumber});
        if (it != m_sourceToAddr.end()) {
            bp.address = it->second;
            bp.resolved = true;
        }
    }
    
    m_breakpoints.push_back(bp);
    
    // If resolved and running, set in engine
    if (bp.resolved && m_state != DebugState::Idle) {
        SyncBreakpointToEngine(bp.id);
    }
    
    return bp.id;
}

uint32_t DebuggerService::SetBreakpointByAddress(uint64_t address) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    // Check if already exists
    for (const auto& bp : m_breakpoints) {
        if (bp.address == address) {
            return bp.id;
        }
    }
    
    BreakpointInfo bp;
    bp.id = m_nextBreakpointId++;
    bp.address = address;
    bp.enabled = true;
    bp.resolved = true;
    
    m_breakpoints.push_back(bp);
    
    if (m_state != DebugState::Idle) {
        SyncBreakpointToEngine(bp.id);
    }
    
    return bp.id;
}

void DebuggerService::RemoveBreakpoint(uint32_t bpId) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); ++it) {
        if (it->id == bpId) {
            RemoveBreakpointFromEngine(bpId);
            m_breakpoints.erase(it);
            return;
        }
    }
}

void DebuggerService::EnableBreakpoint(uint32_t bpId, bool enable) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (auto& bp : m_breakpoints) {
        if (bp.id == bpId) {
            bp.enabled = enable;
            CDB_EnableBreakpoint(bpId, enable);
            return;
        }
    }
}

void DebuggerService::ToggleBreakpoint(const std::string& filePath, int lineNumber) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (auto& bp : m_breakpoints) {
        if (bp.filePath == filePath && bp.lineNumber == lineNumber) {
            bp.enabled = !bp.enabled;
            CDB_EnableBreakpoint(bp.id, bp.enabled);
            return;
        }
    }
    
    // Not found, create new
    SetBreakpoint(filePath, lineNumber);
}

bool DebuggerService::HasBreakpoint(const std::string& filePath, int lineNumber) const {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (const auto& bp : m_breakpoints) {
        if (bp.filePath == filePath && bp.lineNumber == lineNumber && bp.enabled) {
            return true;
        }
    }
    return false;
}

const std::vector<BreakpointInfo>& DebuggerService::GetBreakpoints() const {
    return m_breakpoints;
}

void DebuggerService::ResolvePendingBreakpoints() {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (auto& bp : m_breakpoints) {
        if (!bp.resolved) {
            // Try to resolve by symbol
            if (!bp.symbolName.empty()) {
                uint64_t addr;
                if (ResolveSymbol(bp.symbolName, addr)) {
                    bp.address = addr;
                    bp.resolved = true;
                }
            }
            
            // Try to resolve by source mapping
            if (!bp.resolved) {
                std::lock_guard<std::mutex> mapLock(m_sourceMapMutex);
                auto it = m_sourceToAddr.find({bp.filePath, bp.lineNumber});
                if (it != m_sourceToAddr.end()) {
                    bp.address = it->second;
                    bp.resolved = true;
                }
            }
            
            // Sync to engine if resolved
            if (bp.resolved) {
                SyncBreakpointToEngine(bp.id);
            }
        }
    }
}

void DebuggerService::SyncBreakpointToEngine(uint32_t bpId) {
    for (const auto& bp : m_breakpoints) {
        if (bp.id == bpId && bp.resolved && bp.enabled) {
            CDB_SetBreakpoint(bp.address, bp.symbolName.c_str());
            return;
        }
    }
}

void DebuggerService::RemoveBreakpointFromEngine(uint32_t bpId) {
    CDB_RemoveBreakpoint(bpId);
}

/*===========================================================================
 * MEMORY ACCESS
 *===========================================================================*/

MemoryRange DebuggerService::ReadMemory(uint64_t address, size_t size) {
    MemoryRange result;
    result.baseAddress = address;
    result.data.resize(size);
    result.valid = false;
    
    size_t read = CDB_ReadMemory(address, result.data.data(), size);
    if (read > 0) {
        result.data.resize(read);
        result.valid = true;
    }
    
    return result;
}

bool DebuggerService::WriteMemory(uint64_t address, const void* data, size_t size) {
    return CDB_WriteMemory(address, data, size) == size;
}

/*===========================================================================
 * REGISTER ACCESS
 *===========================================================================*/

RegisterSet DebuggerService::GetRegisters(uint32_t threadId) {
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_threadCache.find(threadId);
        if (it != m_threadCache.end()) {
            return it->second;
        }
    }
    
    // Fetch from engine
    CDB_ThreadContext ctx;
    if (!CDB_GetThreadContext(threadId, &ctx)) {
        return RegisterSet();
    }
    
    RegisterSet regs;
    regs.rax = ctx.rax;
    regs.rbx = ctx.rbx;
    regs.rcx = ctx.rcx;
    regs.rdx = ctx.rdx;
    regs.rsi = ctx.rsi;
    regs.rdi = ctx.rdi;
    regs.rbp = ctx.rbp;
    regs.rsp = ctx.rsp;
    regs.r8 = ctx.r8;
    regs.r9 = ctx.r9;
    regs.r10 = ctx.r10;
    regs.r11 = ctx.r11;
    regs.r12 = ctx.r12;
    regs.r13 = ctx.r13;
    regs.r14 = ctx.r14;
    regs.r15 = ctx.r15;
    regs.rip = ctx.rip;
    regs.eflags = ctx.eflags;
    
    // Cache it
    CacheThreadContext(threadId);
    
    return regs;
}

void DebuggerService::SetRegisters(uint32_t threadId, const RegisterSet& regs) {
    CDB_ThreadContext ctx;
    ctx.rax = regs.rax;
    ctx.rbx = regs.rbx;
    ctx.rcx = regs.rcx;
    ctx.rdx = regs.rdx;
    ctx.rsi = regs.rsi;
    ctx.rdi = regs.rdi;
    ctx.rbp = regs.rbp;
    ctx.rsp = regs.rsp;
    ctx.r8 = regs.r8;
    ctx.r9 = regs.r9;
    ctx.r10 = regs.r10;
    ctx.r11 = regs.r11;
    ctx.r12 = regs.r12;
    ctx.r13 = regs.r13;
    ctx.r14 = regs.r14;
    ctx.r15 = regs.r15;
    ctx.rip = regs.rip;
    ctx.eflags = regs.eflags;
    
    CDB_SetThreadContext(threadId, &ctx);
    
    // Update cache
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_threadCache[threadId] = regs;
}

uint64_t DebuggerService::GetRegisterValue(uint32_t threadId, const std::string& regName) {
    auto regs = GetRegisters(threadId);
    return CDB_GetRegisterValue(reinterpret_cast<CDB_ThreadContext*>(&regs), regName.c_str());
}

void DebuggerService::SetRegisterValue(uint32_t threadId, const std::string& regName, uint64_t value) {
    auto regs = GetRegisters(threadId);
    CDB_SetRegisterValue(reinterpret_cast<CDB_ThreadContext*>(&regs), regName.c_str(), value);
    SetRegisters(threadId, regs);
}

void DebuggerService::CacheThreadContext(uint32_t threadId) {
    // Called internally after fetching from engine
}

void DebuggerService::InvalidateThreadCache() {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_threadCache.clear();
}

/*===========================================================================
 * CALL STACK
 *===========================================================================*/

std::vector<StackFrame> DebuggerService::GetCallStack(uint32_t threadId, uint32_t maxFrames) {
    std::vector<StackFrame> frames;
    
    // Get context for thread
    auto regs = GetRegisters(threadId);
    
    // Setup stack walk
    STACKFRAME64 stackFrame = {};
    CONTEXT context = {};
    context.Rip = regs.rip;
    context.Rsp = regs.rsp;
    context.Rbp = regs.rbp;
    
    stackFrame.AddrPC.Offset = regs.rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = regs.rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = regs.rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    
    HANDLE hProcess = GetCurrentProcess(); // TODO: Get from CDB
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
    if (!hThread) {
        return frames;
    }
    
    for (uint32_t i = 0; i < maxFrames; i++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                         &stackFrame, &context, nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
            break;
        }
        
        StackFrame frame;
        frame.returnAddress = stackFrame.AddrReturn.Offset;
        frame.framePointer = stackFrame.AddrFrame.Offset;
        frame.stackPointer = stackFrame.AddrStack.Offset;
        
        // Resolve symbol
        char symbolBuffer[sizeof(IMAGEHLP_SYMBOL64) + 256];
        PIMAGEHLP_SYMBOL64 symbol = reinterpret_cast<PIMAGEHLP_SYMBOL64>(symbolBuffer);
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
        symbol->MaxNameLength = 255;
        
        DWORD64 displacement;
        if (SymGetSymFromAddr64(hProcess, stackFrame.AddrPC.Offset, &displacement, symbol)) {
            frame.symbolName = symbol->Name;
        }
        
        // Resolve line info
        IMAGEHLP_LINE64 line = {};
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        DWORD lineDisplacement;
        if (SymGetLineFromAddr64(hProcess, stackFrame.AddrPC.Offset, &lineDisplacement, &line)) {
            frame.fileName = line.FileName;
            frame.lineNumber = line.LineNumber;
        }
        
        frames.push_back(frame);
    }
    
    CloseHandle(hThread);
    return frames;
}

/*===========================================================================
 * SYMBOL RESOLUTION
 *===========================================================================*/

bool DebuggerService::ResolveSymbol(const std::string& symbolName, uint64_t& outAddress) {
    // Use DbgHelp to resolve
    char buffer[sizeof(IMAGEHLP_SYMBOL64) + 256];
    PIMAGEHLP_SYMBOL64 symbol = reinterpret_cast<PIMAGEHLP_SYMBOL64>(buffer);
    symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    symbol->MaxNameLength = 255;
    
    HANDLE hProcess = GetCurrentProcess(); // TODO: Get from CDB
    
    if (SymGetSymFromName64(hProcess, symbolName.c_str(), symbol)) {
        outAddress = symbol->Address;
        return true;
    }
    
    return false;
}

bool DebuggerService::ResolveLineInfo(uint64_t address, std::string& outFile, int& outLine) {
    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    
    HANDLE hProcess = GetCurrentProcess(); // TODO: Get from CDB
    DWORD displacement;
    
    if (SymGetLineFromAddr64(hProcess, address, &displacement, &line)) {
        outFile = line.FileName;
        outLine = line.LineNumber;
        return true;
    }
    
    return false;
}

/*===========================================================================
 * EVENT HANDLING
 *===========================================================================*/

void DebuggerService::OnCDBEvent(const CDB_DebugEvent* event) {
    DebugEvent ideEvent;
    ideEvent.processId = event->processId;
    ideEvent.threadId = event->threadId;
    ideEvent.timestamp = event->timestamp;
    ideEvent.address = event->address;
    ideEvent.exceptionCode = event->exceptionCode;
    ideEvent.description = event->description;
    
    // Map CDB event type to IDE event type
    switch (event->type) {
        case 1: // CDB_EVENT_PROCESS_CREATE
            ideEvent.type = DebugEventType::ProcessStarted;
            break;
        case 2: // CDB_EVENT_PROCESS_EXIT
            ideEvent.type = DebugEventType::ProcessExited;
            UpdateState(DebugState::Terminated);
            break;
        case 3: // CDB_EVENT_THREAD_CREATE
            ideEvent.type = DebugEventType::ThreadCreated;
            break;
        case 4: // CDB_EVENT_THREAD_EXIT
            ideEvent.type = DebugEventType::ThreadExited;
            break;
        case 5: // CDB_EVENT_BREAKPOINT
            ideEvent.type = DebugEventType::BreakpointHit;
            m_impl->currentThreadId = event->threadId;
            m_impl->hasContext = true;
            CacheThreadContext(event->threadId);
            UpdateState(DebugState::Paused);
            break;
        case 6: // CDB_EVENT_EXCEPTION
            ideEvent.type = DebugEventType::ExceptionRaised;
            m_impl->currentThreadId = event->threadId;
            m_impl->hasContext = true;
            UpdateState(DebugState::Paused);
            break;
        case 7: // CDB_EVENT_MODULE_LOAD
            ideEvent.type = DebugEventType::ModuleLoaded;
            // Try to resolve pending breakpoints after module load
            ResolvePendingBreakpoints();
            break;
        case 8: // CDB_EVENT_MODULE_UNLOAD
            ideEvent.type = DebugEventType::ModuleUnloaded;
            break;
        case 9: // CDB_EVENT_OUTPUT
            ideEvent.type = DebugEventType::OutputDebugString;
            break;
        default:
            ideEvent.type = DebugEventType::None;
            break;
    }
    
    // Push to ring buffer
    m_impl->eventQueue.Push(ideEvent);
    
    // Post message to IDE window (if available)
    // TODO: Get IDE window handle and post WM_DEBUG_EVENT
    // PostMessage(g_hIdeWnd, WM_DEBUG_EVENT, 0, 0);
}

void DebuggerService::PollEvents() {
    DebugEvent event;
    while (m_impl->eventQueue.Pop(event)) {
        if (m_eventCallback) {
            m_eventCallback(event);
        }
    }
}

void DebuggerService::UpdateState(DebugState newState) {
    DebugState oldState;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        oldState = m_state;
        m_state = newState;
    }
    
    if (m_stateCallback && oldState != newState) {
        m_stateCallback(oldState, newState);
    }
}

void DebuggerService::SetEventCallback(DebugEventCallback callback) {
    m_eventCallback = callback;
}

void DebuggerService::SetStateChangeCallback(StateChangeCallback callback) {
    m_stateCallback = callback;
}

void DebuggerService::UpdateUI() {
    // Trigger refresh of all debug views
    PollEvents();
}

/*===========================================================================
 * SOURCE MAPPING
 *===========================================================================*/

void DebuggerService::MapSourceToAddress(const std::string& filePath, int lineNumber, uint64_t address) {
    std::lock_guard<std::mutex> lock(m_sourceMapMutex);
    m_sourceToAddr[{filePath, lineNumber}] = address;
    m_addrToSource[address] = {filePath, lineNumber};
}

bool DebuggerService::GetAddressForLine(const std::string& filePath, int lineNumber, uint64_t& outAddress) {
    std::lock_guard<std::mutex> lock(m_sourceMapMutex);
    auto it = m_sourceToAddr.find({filePath, lineNumber});
    if (it != m_sourceToAddr.end()) {
        outAddress = it->second;
        return true;
    }
    return false;
}

bool DebuggerService::GetLineForAddress(uint64_t address, std::string& outFile, int& outLine) {
    std::lock_guard<std::mutex> lock(m_sourceMapMutex);
    auto it = m_addrToSource.find(address);
    if (it != m_addrToSource.end()) {
        outFile = it->second.first;
        outLine = it->second.second;
        return true;
    }
    return false;
}

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

namespace DebuggerUtils {

std::string FormatAddress(uint64_t address) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%016llX", address);
    return std::string(buffer);
}

std::string FormatBytes(const uint8_t* data, size_t size, size_t bytesPerGroup) {
    std::string result;
    for (size_t i = 0; i < size; i++) {
        if (i > 0) {
            if (i % bytesPerGroup == 0) {
                result += "  ";
            } else {
                result += " ";
            }
        }
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    return result;
}

std::string GetExceptionName(uint32_t code) {
    switch (code) {
        case 0xC0000005: return "Access Violation";
        case 0x80000003: return "Breakpoint";
        case 0xC0000094: return "Integer Divide by Zero";
        case 0xC0000095: return "Integer Overflow";
        case 0xC00000FD: return "Stack Overflow";
        case 0xC0000025: return "Non-Continuable Exception";
        case 0xC000008C: return "Array Bounds Exceeded";
        case 0xC000008E: return "Float Divide by Zero";
        default: return "Unknown Exception";
    }
}

std::string GetRegisterName(uint32_t index) {
    static const char* names[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
    };
    if (index < sizeof(names) / sizeof(names[0])) {
        return names[index];
    }
    return "UNKNOWN";
}

std::string FormatMemoryLine(uint64_t addr, const uint8_t* data, size_t size) {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "%016llX  ", addr);
    std::string result = buffer;
    
    // Hex bytes
    for (size_t i = 0; i < 16; i++) {
        if (i < size) {
            snprintf(buffer, sizeof(buffer), "%02X ", data[i]);
        } else {
            snprintf(buffer, sizeof(buffer), "   ");
        }
        result += buffer;
        if (i == 7) result += " ";
    }
    
    result += " |";
    
    // ASCII
    for (size_t i = 0; i < 16 && i < size; i++) {
        char c = data[i];
        result += (c >= 32 && c < 127) ? c : '.';
    }
    
    result += "|";
    return result;
}

std::string FormatAsciiDump(const uint8_t* data, size_t size) {
    std::string result;
    for (size_t i = 0; i < size; i++) {
        char c = data[i];
        result += (c >= 32 && c < 127) ? c : '.';
    }
    return result;
}

} // namespace DebuggerUtils

} // namespace RawrXD
