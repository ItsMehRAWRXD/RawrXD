//=============================================================================
// RawrXD Debug Backend Implementation
// Professional Windows Debugger with DbgHelp Integration
//=============================================================================
#include "DebugBackend.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Debug {

//=============================================================================
// DebugSession Implementation
//=============================================================================

DebugSession::DebugSession() {
    // Initialize symbol handler when needed
}

DebugSession::~DebugSession() {
    if (m_active) {
        DetachProcess();
    }
    CleanupSymbols();
}

bool DebugSession::InitializeSymbols() {
    if (m_symbolsInitialized) {
        return true;
    }
    
    // Get symbol path from backend
    std::wstring symbolPath = DebugBackend::Instance().GetSymbolPath();
    if (symbolPath.empty()) {
        symbolPath = L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
    }
    
    // Initialize DbgHelp
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    
    if (!SymInitializeW(m_hProcess, symbolPath.c_str(), TRUE)) {
        return false;
    }
    
    m_symbolsInitialized = true;
    return true;
}

void DebugSession::CleanupSymbols() {
    if (m_symbolsInitialized && m_hProcess) {
        SymCleanup(m_hProcess);
        m_symbolsInitialized = false;
    }
}

bool DebugSession::LaunchProcess(const wchar_t* executable, const wchar_t* arguments,
                                  const wchar_t* workingDirectory) {
    if (m_active) {
        return false; // Already have an active session
    }
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    DWORD creationFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
    
    // Build command line
    std::wstring cmdLine;
    if (arguments && wcslen(arguments) > 0) {
        cmdLine = std::wstring(executable) + L" " + arguments;
    } else {
        cmdLine = executable;
    }
    
    // Create the process
    BOOL result = CreateProcessW(
        nullptr,                    // Application name (use command line)
        &cmdLine[0],               // Command line
        nullptr,                    // Process security attributes
        nullptr,                    // Thread security attributes
        FALSE,                      // Inherit handles
        creationFlags,              // Creation flags
        nullptr,                    // Environment
        workingDirectory,           // Working directory
        &si,                       // Startup info
        &pi                       // Process info
    );
    
    if (!result) {
        return false;
    }
    
    // Store handles
    m_hProcess = pi.hProcess;
    m_hMainThread = pi.hThread;
    m_processId = pi.dwProcessId;
    m_mainThreadId = pi.dwThreadId;
    
    m_active = true;
    m_attached = true;
    m_running = true;
    
    // Initialize symbols
    InitializeSymbols();
    
    return true;
}

bool DebugSession::AttachProcess(uint32_t processId) {
    if (m_active) {
        return false;
    }
    
    // Enable debug privilege first
    if (!DebugBackend::EnableDebugPrivilege()) {
        // Log warning but continue - may still work for owned processes
    }
    
    // Attach to process
    if (!DebugActiveProcess(processId)) {
        return false;
    }
    
    // Open process handle
    m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!m_hProcess) {
        DebugActiveProcessStop(processId);
        return false;
    }
    
    m_processId = processId;
    m_active = true;
    m_attached = true;
    m_running = true;
    
    // Initialize symbols
    InitializeSymbols();
    
    return true;
}

bool DebugSession::DetachProcess() {
    if (!m_active || !m_attached) {
        return false;
    }
    
    // Remove all breakpoints first
    ClearAllBreakpoints();
    
    // Detach from process
    if (m_processId > 0) {
        DebugActiveProcessStop(m_processId);
    }
    
    // Close handles
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    
    if (m_hMainThread) {
        CloseHandle(m_hMainThread);
        m_hMainThread = nullptr;
    }
    
    CleanupSymbols();
    
    m_active = false;
    m_attached = false;
    m_running = false;
    m_detached = true;
    
    return true;
}

bool DebugSession::TerminateProcess(uint32_t exitCode) {
    if (!m_active || !m_hProcess) {
        return false;
    }
    
    return ::TerminateProcess(m_hProcess, exitCode) != FALSE;
}

bool DebugSession::ContinueExecution() {
    if (!m_active) {
        return false;
    }
    
    // Continue all threads
    if (!ContinueDebugEvent(m_processId, 0, DBG_CONTINUE)) {
        return false;
    }
    
    m_running = true;
    return true;
}

bool DebugSession::BreakExecution() {
    if (!m_active || !m_hProcess) {
        return false;
    }
    
    // Break into the debugger
    return DebugBreakProcess(m_hProcess) != FALSE;
}

bool DebugSession::StepInto() {
    if (!m_active) {
        return false;
    }
    
    // Set single step flag on main thread
    if (!SetSingleStepFlag(m_mainThreadId, true)) {
        return false;
    }
    
    m_running = true;
    return ContinueExecution();
}

bool DebugSession::StepOver() {
    if (!m_active) {
        return false;
    }
    
    // Get current context
    RegisterContext ctx;
    if (!GetRegisters(ctx)) {
        return false;
    }
    
    // Compute address of next instruction
    uint64_t nextAddr;
    if (!ComputeStepOverAddress(ctx.rip, nextAddr)) {
        // Fall back to step into if we can't compute
        return StepInto();
    }
    
    // Set temporary breakpoint at next instruction
    if (!SetBreakpoint(nextAddr)) {
        return false;
    }
    
    // Mark as temporary step-over breakpoint
    m_stepOverBreakpoint = nextAddr;
    
    m_running = true;
    return ContinueExecution();
}

bool DebugSession::StepOut() {
    if (!m_active) {
        return false;
    }
    
    // Get call stack
    auto stack = GetCallStack();
    if (stack.size() < 2) {
        // Already at top level, just continue
        return ContinueExecution();
    }
    
    // Set breakpoint at return address (second frame)
    uint64_t returnAddr = stack[1].instructionPointer;
    if (!SetBreakpoint(returnAddr)) {
        return false;
    }
    
    m_stepOverBreakpoint = returnAddr;
    m_running = true;
    return ContinueExecution();
}

bool DebugSession::SetBreakpoint(uint64_t address) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    // Check if already exists
    if (m_breakpoints.find(address) != m_breakpoints.end()) {
        return true; // Already set
    }
    
    Breakpoint bp;
    bp.address = address;
    bp.active = false;
    bp.temporary = false;
    
    // Read original byte
    if (!ReadMemory(address, &bp.originalByte, 1)) {
        return false;
    }
    
    // Write INT3
    uint8_t int3 = 0xCC;
    if (!WriteMemory(address, &int3, 1)) {
        return false;
    }
    
    bp.active = true;
    m_breakpoints[address] = bp;
    
    return true;
}

bool DebugSession::RemoveBreakpoint(uint64_t address) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    auto it = m_breakpoints.find(address);
    if (it == m_breakpoints.end()) {
        return false;
    }
    
    // Restore original byte
    if (it->second.active) {
        WriteMemory(address, &it->second.originalByte, 1);
    }
    
    m_breakpoints.erase(it);
    return true;
}

void DebugSession::ClearAllBreakpoints() {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    for (auto& pair : m_breakpoints) {
        if (pair.second.active) {
            WriteMemory(pair.first, &pair.second.originalByte, 1);
        }
    }
    
    m_breakpoints.clear();
}

std::vector<Breakpoint> DebugSession::GetBreakpoints() {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    
    std::vector<Breakpoint> result;
    for (const auto& pair : m_breakpoints) {
        result.push_back(pair.second);
    }
    return result;
}

bool DebugSession::ReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytesRead) {
    if (!m_hProcess) {
        return false;
    }
    
    SIZE_T read = 0;
    BOOL result = ReadProcessMemory(m_hProcess, (LPCVOID)address, buffer, size, &read);
    
    if (bytesRead) {
        *bytesRead = read;
    }
    
    return result != FALSE;
}

bool DebugSession::WriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytesWritten) {
    if (!m_hProcess) {
        return false;
    }
    
    SIZE_T written = 0;
    BOOL result = WriteProcessMemory(m_hProcess, (LPVOID)address, buffer, size, &written);
    
    if (bytesWritten) {
        *bytesWritten = written;
    }
    
    return result != FALSE;
}

bool DebugSession::GetRegisters(RegisterContext& context) {
    return GetThreadContext(m_mainThreadId, context);
}

bool DebugSession::SetRegisters(const RegisterContext& context) {
    return SetThreadContext(m_mainThreadId, context);
}

bool DebugSession::GetThreadContext(uint32_t threadId, RegisterContext& context) {
    if (!m_hProcess) {
        return false;
    }
    
    // Open thread
    HANDLE hThread = ::OpenThread(THREAD_GET_CONTEXT, FALSE, (DWORD)threadId);
    if (!hThread) {
        return false;
    }
    
    // Get context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    
    if (!::GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }
    
    CloseHandle(hThread);
    
    // Convert to our format
    context.rax = ctx.Rax;
    context.rcx = ctx.Rcx;
    context.rdx = ctx.Rdx;
    context.rbx = ctx.Rbx;
    context.rsp = ctx.Rsp;
    context.rbp = ctx.Rbp;
    context.rsi = ctx.Rsi;
    context.rdi = ctx.Rdi;
    context.r8 = ctx.R8;
    context.r9 = ctx.R9;
    context.r10 = ctx.R10;
    context.r11 = ctx.R11;
    context.r12 = ctx.R12;
    context.r13 = ctx.R13;
    context.r14 = ctx.R14;
    context.r15 = ctx.R15;
    context.rip = ctx.Rip;
    context.eflags = ctx.EFlags;
    context.cs = ctx.SegCs;
    context.ds = ctx.SegDs;
    context.es = ctx.SegEs;
    context.fs = ctx.SegFs;
    context.gs = ctx.SegGs;
    context.ss = ctx.SegSs;
    context.dr0 = ctx.Dr0;
    context.dr1 = ctx.Dr1;
    context.dr2 = ctx.Dr2;
    context.dr3 = ctx.Dr3;
    context.dr6 = ctx.Dr6;
    context.dr7 = ctx.Dr7;
    
    return true;
}

bool DebugSession::SetThreadContext(uint32_t threadId, const RegisterContext& context) {
    if (!m_hProcess) {
        return false;
    }
    
    // Open thread
    HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, (DWORD)threadId);
    if (!hThread) {
        return false;
    }
    
    // Build context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    
    ctx.Rax = context.rax;
    ctx.Rcx = context.rcx;
    ctx.Rdx = context.rdx;
    ctx.Rbx = context.rbx;
    ctx.Rsp = context.rsp;
    ctx.Rbp = context.rbp;
    ctx.Rsi = context.rsi;
    ctx.Rdi = context.rdi;
    ctx.R8 = context.r8;
    ctx.R9 = context.r9;
    ctx.R10 = context.r10;
    ctx.R11 = context.r11;
    ctx.R12 = context.r12;
    ctx.R13 = context.r13;
    ctx.R14 = context.r14;
    ctx.R15 = context.r15;
    ctx.Rip = context.rip;
    ctx.EFlags = context.eflags;
    ctx.SegCs = context.cs;
    ctx.SegDs = context.ds;
    ctx.SegEs = context.es;
    ctx.SegFs = context.fs;
    ctx.SegGs = context.gs;
    ctx.SegSs = context.ss;
    ctx.Dr0 = context.dr0;
    ctx.Dr1 = context.dr1;
    ctx.Dr2 = context.dr2;
    ctx.Dr3 = context.dr3;
    ctx.Dr6 = context.dr6;
    ctx.Dr7 = context.dr7;
    
    BOOL result = ::SetThreadContext(hThread, &ctx);
    CloseHandle(hThread);
    
    return result != FALSE;
}

std::vector<StackFrame> DebugSession::GetCallStack(uint32_t threadId) {
    RegisterContext ctx;
    if (!GetThreadContext(threadId, ctx)) {
        return {};
    }
    return GetCallStack(ctx);
}

std::vector<StackFrame> DebugSession::GetCallStack(const RegisterContext& context) {
    std::vector<StackFrame> frames;
    
    if (!m_symbolsInitialized) {
        return frames;
    }
    
    // Initialize stack frame
    STACKFRAME64 stackFrame = {};
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
    
    stackFrame.AddrPC.Offset = context.rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    
    stackFrame.AddrFrame.Offset = context.rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    
    stackFrame.AddrStack.Offset = context.rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    
    // Walk the stack
    CONTEXT ctx = {};
    ctx.Rip = context.rip;
    ctx.Rbp = context.rbp;
    ctx.Rsp = context.rsp;
    
    while (frames.size() < 100) { // Limit to 100 frames
        BOOL result = StackWalk64(
            machineType,
            m_hProcess,
            nullptr, // Use current thread
            &stackFrame,
            &ctx,
            nullptr, // ReadMemoryRoutine - use default
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            nullptr
        );
        
        if (!result || stackFrame.AddrPC.Offset == 0) {
            break;
        }
        
        StackFrame frame;
        frame.instructionPointer = stackFrame.AddrPC.Offset;
        frame.stackPointer = stackFrame.AddrStack.Offset;
        frame.framePointer = stackFrame.AddrFrame.Offset;
        
        // Resolve symbol
        ResolveSymbol(frame.instructionPointer, frame.functionName, frame.moduleName);
        ResolveSourceLocation(frame.instructionPointer, frame.sourceFile, 
                            frame.sourceLine, frame.sourceColumn);
        
        frames.push_back(frame);
    }
    
    return frames;
}

bool DebugSession::ResolveSymbol(uint64_t address, std::string& symbolName, std::string& moduleName) {
    if (!m_symbolsInitialized) {
        return false;
    }
    
    // Get symbol info
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
    PSYMBOL_INFO pSym = (PSYMBOL_INFO)buffer;
    pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSym->MaxNameLen = MAX_SYM_NAME;
    
    DWORD64 displacement = 0;
    if (SymFromAddr(m_hProcess, address, &displacement, pSym)) {
        symbolName = pSym->Name;
        
        // Get module name
        IMAGEHLP_MODULE64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        if (SymGetModuleInfo64(m_hProcess, pSym->ModBase, &moduleInfo)) {
            moduleName = moduleInfo.ModuleName;
        }
        
        return true;
    }
    
    return false;
}

bool DebugSession::ResolveSourceLocation(uint64_t address, std::string& file, 
                                         uint32_t& line, uint32_t& column) {
    if (!m_symbolsInitialized) {
        return false;
    }
    
    IMAGEHLP_LINE64 lineInfo = {};
    lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    
    DWORD displacement = 0;
    if (SymGetLineFromAddr64(m_hProcess, address, &displacement, &lineInfo)) {
        file = lineInfo.FileName ? lineInfo.FileName : "";
        line = lineInfo.LineNumber;
        column = 0; // DbgHelp doesn't provide column info
        return true;
    }
    
    return false;
}

bool DebugSession::SetSingleStepFlag(uint32_t threadId, bool enable) {
    RegisterContext ctx;
    if (!GetThreadContext(threadId, ctx)) {
        return false;
    }
    
    if (enable) {
        ctx.eflags |= 0x100; // Set Trap Flag
    } else {
        ctx.eflags &= ~0x100; // Clear Trap Flag
    }
    
    return SetThreadContext(threadId, ctx);
}

bool DebugSession::ComputeStepOverAddress(uint64_t currentRip, uint64_t& nextAddress) {
    // Read instruction at current RIP
    uint8_t buffer[15] = {}; // Max x64 instruction length
    size_t read = 0;
    
    if (!ReadMemory(currentRip, buffer, sizeof(buffer), &read) || read == 0) {
        return false;
    }
    
    // Simple instruction length calculation
    // This is a simplified version - a real implementation needs full x64 decoder
    size_t length = 1; // Minimum
    
    // Check for prefixes
    size_t i = 0;
    while (i < read && i < 4) {
        if (buffer[i] == 0x66 || buffer[i] == 0x67 || buffer[i] == 0xF0 ||
            buffer[i] == 0xF2 || buffer[i] == 0xF3 ||
            (buffer[i] >= 0x40 && buffer[i] <= 0x4F)) {
            i++;
            length++;
        } else {
            break;
        }
    }
    
    // Basic opcode length estimation
    if (i < read) {
        uint8_t opcode = buffer[i];
        
        // Check for multi-byte opcodes
        if (opcode == 0x0F) {
            length++; // Two-byte opcode
            i++;
        }
        
        // ModR/M byte present for many instructions
        if (opcode >= 0x00 && opcode <= 0x3F) {
            length++; // ModR/M
        } else if (opcode >= 0x80 && opcode <= 0x8F) {
            length++; // ModR/M
        } else if (opcode >= 0xC0 && opcode <= 0xFE) {
            length++; // ModR/M
        }
        
        // Immediate operands
        if (opcode >= 0xB0 && opcode <= 0xBF) {
            length += (opcode >= 0xB8) ? 8 : 1; // MOV r64, imm64 or MOV r8, imm8
        }
    }
    
    nextAddress = currentRip + length;
    return true;
}

void DebugSession::ProcessDebugEvent(const DEBUG_EVENT& event) {
    DebugEvent debugEvent;
    debugEvent.type = DebugEventType::Exception;
    debugEvent.processId = event.dwProcessId;
    debugEvent.threadId = event.dwThreadId;
    
    switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            debugEvent.type = DebugEventType::ProcessCreated;
            // Store process info
            break;
            
        case EXIT_PROCESS_DEBUG_EVENT:
            debugEvent.type = DebugEventType::ProcessExited;
            debugEvent.exitCode = event.u.ExitProcess.dwExitCode;
            m_running = false;
            break;
            
        case CREATE_THREAD_DEBUG_EVENT:
            debugEvent.type = DebugEventType::ThreadCreated;
            break;
            
        case EXIT_THREAD_DEBUG_EVENT:
            debugEvent.type = DebugEventType::ThreadExited;
            break;
            
        case LOAD_DLL_DEBUG_EVENT:
            debugEvent.type = DebugEventType::LoadDll;
            // Load symbols for DLL
            break;
            
        case UNLOAD_DLL_DEBUG_EVENT:
            debugEvent.type = DebugEventType::UnloadDll;
            break;
            
        case EXCEPTION_DEBUG_EVENT:
            HandleBreakpointEvent(event);
            return; // Event handled
            
        case OUTPUT_DEBUG_STRING_EVENT:
            debugEvent.type = DebugEventType::OutputDebugString;
            break;
            
        default:
            debugEvent.type = DebugEventType::Exception;
            break;
    }
    
    // Get context
    GetThreadContext(event.dwThreadId, debugEvent.registers);
    debugEvent.callStack = GetCallStack(debugEvent.registers);
    
    // Notify callback
    if (m_eventCallback) {
        m_eventCallback(debugEvent);
    }
}

bool DebugSession::HandleBreakpointEvent(const DEBUG_EVENT& event) {
    const EXCEPTION_RECORD& exc = event.u.Exception.ExceptionRecord;
    
    if (exc.ExceptionCode == EXCEPTION_BREAKPOINT) {
        uint64_t address = (uint64_t)exc.ExceptionAddress;
        
        std::lock_guard<std::mutex> lock(m_breakpointMutex);
        
        auto it = m_breakpoints.find(address);
        if (it != m_breakpoints.end()) {
            // Our breakpoint - restore original byte
            WriteMemory(address, &it->second.originalByte, 1);
            it->second.active = false;
            
            // Adjust RIP to re-execute the instruction
            HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, 
                                       FALSE, event.dwThreadId);
            if (hThread) {
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_CONTROL;
                ::GetThreadContext(hThread, &ctx);
                ctx.Rip = address; // Step back to execute original instruction
                ::SetThreadContext(hThread, &ctx);
                CloseHandle(hThread);
            }
            
            // Build event
            DebugEvent debugEvent;
            debugEvent.type = DebugEventType::BreakpointHit;
            debugEvent.processId = event.dwProcessId;
            debugEvent.threadId = event.dwThreadId;
            debugEvent.exceptionAddress = address;
            
            GetThreadContext(event.dwThreadId, debugEvent.registers);
            debugEvent.callStack = GetCallStack(debugEvent.registers);
            
            if (m_eventCallback) {
                m_eventCallback(debugEvent);
            }
            
            m_running = false;
            return true;
        }
    } else if (exc.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        DebugEvent debugEvent;
        debugEvent.type = DebugEventType::SingleStep;
        debugEvent.processId = event.dwProcessId;
        debugEvent.threadId = event.dwThreadId;
        debugEvent.exceptionAddress = (uint64_t)exc.ExceptionAddress;
        
        GetThreadContext(event.dwThreadId, debugEvent.registers);
        debugEvent.callStack = GetCallStack(debugEvent.registers);
        
        if (m_eventCallback) {
            m_eventCallback(debugEvent);
        }
        
        m_running = false;
        return true;
    }
    
    return false;
}

void DebugSession::SetEventCallback(EventCallback callback) {
    m_eventCallback = callback;
}

//=============================================================================
// DebugBackend Implementation
//=============================================================================

DebugBackend::DebugBackend() {
    // Set default symbol path
    m_symbolPath = L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
}

DebugBackend::~DebugBackend() {
    // Cleanup any remaining sessions
}

DebugBackend& DebugBackend::Instance() {
    static DebugBackend instance;
    return instance;
}

std::shared_ptr<DebugSession> DebugBackend::CreateSession() {
    auto session = std::make_shared<DebugSession>();
    
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    m_sessions.push_back(session);
    
    return session;
}

void DebugBackend::DestroySession(std::shared_ptr<DebugSession> session) {
    if (session) {
        session->DetachProcess();
    }
    
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    m_sessions.erase(
        std::remove_if(m_sessions.begin(), m_sessions.end(),
            [session](const std::weak_ptr<DebugSession>& weak) {
                auto shared = weak.lock();
                return !shared || shared == session;
            }),
        m_sessions.end()
    );
}

std::vector<std::shared_ptr<DebugSession>> DebugBackend::GetActiveSessions() {
    std::vector<std::shared_ptr<DebugSession>> result;
    
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    for (auto& weak : m_sessions) {
        if (auto session = weak.lock()) {
            if (session->IsActive()) {
                result.push_back(session);
            }
        }
    }
    
    return result;
}

void DebugBackend::SetSymbolPath(const std::wstring& path) {
    m_symbolPath = path;
}

std::wstring DebugBackend::GetSymbolPath() const {
    return m_symbolPath;
}

std::string DebugBackend::GetLastErrorString() {
    DWORD error = GetLastError();
    if (error == 0) {
        return "No error";
    }
    
    LPWSTR buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        nullptr
    );
    
    if (size == 0 || buffer == nullptr) {
        return "Unknown error " + std::to_string(error);
    }
    
    std::wstring wide(buffer, size);
    LocalFree(buffer);
    
    // Convert to UTF-8
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(utf8Size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], utf8Size, nullptr, nullptr);
    
    return result;
}

bool DebugBackend::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

//=============================================================================
// Utility Functions
//=============================================================================

namespace Utils {

std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size == 0) return "";
    
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
    
    return result;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size == 0) return L"";
    
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    
    return result;
}

std::string FormatAddress(uint64_t address) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(16) << address;
    return oss.str();
}

std::string FormatBytes(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        if (i > 0) oss << " ";
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

bool IsExecutableAddress(uint64_t address, HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

} // namespace Utils

} // namespace Debug
} // namespace RawrXD
