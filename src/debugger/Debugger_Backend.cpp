// Debugger_Backend.cpp
// Phase 23: CDB/WinDbg Integration Implementation
// ============================================================================

#include "Debugger_Backend.h"
#include <dbghelp.h>
#include <tlhelp32.h>
#include <sstream>
#include <iomanip>
#include <memory>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {
namespace Debugger {

namespace {
std::wstring FormatWin32Error(DWORD code) {
    if (code == 0) {
        return L"";
    }

    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(
        flags,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );

    std::wstringstream ss;
    ss << L"error=" << code;
    if (length > 0 && buffer) {
        std::wstring message(buffer, length);
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
        if (!message.empty()) {
            ss << L" (" << message << L")";
        }
    }

    if (buffer) {
        LocalFree(buffer);
    }
    return ss.str();
}
}

// Symbol resolver implementation using DbgHelp
class DbgHelpSymbolResolver : public SymbolResolver {
public:
    bool Initialize(const std::wstring& symbolPath) override {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        std::string symbolPathA;
        PCSTR userSearchPath = nullptr;
        if (!symbolPath.empty()) {
            symbolPathA.assign(symbolPath.begin(), symbolPath.end());
            userSearchPath = symbolPathA.c_str();
        }
        
        // Initialize symbols for current process (will be used as template)
        if (!SymInitialize(GetCurrentProcess(), userSearchPath, TRUE)) {
            return false;
        }
        
        return true;
    }
    
    void Shutdown() override {
        SymCleanup(GetCurrentProcess());
    }
    
    std::optional<uint64_t> ResolveSymbol(const std::wstring& symbolName) override {
        // Implementation would use SymFromName
        return std::nullopt;
    }
    
    std::optional<SymbolInfo> ResolveAddress(uint64_t address) override {
        SymbolInfo info;
        
        // Get symbol from address
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        
        DWORD64 displacement = 0;
        if (SymFromAddr(GetCurrentProcess(), address, &displacement, pSymbol)) {
            info.address = pSymbol->Address;
            info.size = pSymbol->Size;
            
            // Convert name to wide string
            int len = MultiByteToWideChar(CP_ACP, 0, pSymbol->Name, -1, nullptr, 0);
            if (len > 0) {
                std::vector<wchar_t> wideName(len);
                MultiByteToWideChar(CP_ACP, 0, pSymbol->Name, -1, wideName.data(), len);
                info.name = wideName.data();
            }
            
            // Get line info
            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD lineDisplacement = 0;
            
            if (SymGetLineFromAddr64(GetCurrentProcess(), address, &lineDisplacement, &line)) {
                info.lineNumber = line.LineNumber;
                
                int fileLen = MultiByteToWideChar(CP_ACP, 0, line.FileName, -1, nullptr, 0);
                if (fileLen > 0) {
                    std::vector<wchar_t> wideFile(fileLen);
                    MultiByteToWideChar(CP_ACP, 0, line.FileName, -1, wideFile.data(), fileLen);
                    info.filePath = wideFile.data();
                }
            }
            
            return info;
        }
        
        return std::nullopt;
    }
    
    bool LoadModuleSymbols(const std::wstring& modulePath, uint64_t baseAddress) override {
        // Implementation would use SymLoadModuleEx
        return false;
    }
    
    std::optional<uint64_t> ResolveSourceLine(const std::wstring& filePath, uint32_t lineNumber) {
        // This would require iterating symbols to find matching line
        // Simplified implementation
        return std::nullopt;
    }
};

// DebugSession implementation
class DebugSession::Impl {
public:
    HANDLE hProcess_ = nullptr;
    bool symbolsInitialized_ = false;
    
    bool InitializeDebugSymbols() {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        
        if (!SymInitialize(hProcess_, nullptr, TRUE)) {
            return false;
        }
        
        symbolsInitialized_ = true;
        return true;
    }
    
    void CleanupDebugSymbols() {
        if (symbolsInitialized_) {
            SymCleanup(hProcess_);
            symbolsInitialized_ = false;
        }
    }
};

DebugSession::DebugSession() : pImpl_(std::make_unique<Impl>()) {}
DebugSession::~DebugSession() { Shutdown(); }

bool DebugSession::Initialize() {
    symbolResolver_ = std::make_unique<DbgHelpSymbolResolver>();
    return true;
}

void DebugSession::Shutdown() {
    if (IsActive()) {
        Terminate();
    }
    
    if (pImpl_) {
        pImpl_->CleanupDebugSymbols();
    }
}

bool DebugSession::LaunchProcess(const std::wstring& executable,
                                  const std::wstring& arguments,
                                  const std::wstring& workingDirectory) {
    lastError_.clear();
    if (executable.empty()) {
        lastError_ = L"LaunchProcess: executable path is empty";
        return false;
    }

    std::wstring commandLine = L"\"" + executable + L"\"";
    if (!arguments.empty()) {
        commandLine += L" " + arguments;
    }

    std::vector<wchar_t> commandLineBuffer(commandLine.begin(), commandLine.end());
    commandLineBuffer.push_back(L'\0');
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    DWORD creationFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
    
    BOOL result = CreateProcessW(
        nullptr,
        commandLineBuffer.data(),
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        nullptr,
        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
        &si,
        &pi
    );
    
    if (!result) {
        const DWORD error = ::GetLastError();
        std::wstringstream ss;
        ss << L"CreateProcessW failed for '" << executable << L"': " << FormatWin32Error(error);
        lastError_ = ss.str();
        return false;
    }
    
    processHandle_ = pi.hProcess;
    threadHandle_ = pi.hThread;
    processId_ = pi.dwProcessId;
    threadId_ = pi.dwThreadId;
    pImpl_->hProcess_ = pi.hProcess;
    
    if (!pImpl_->InitializeDebugSymbols()) {
        const DWORD error = ::GetLastError();
        std::wstringstream ss;
        ss << L"Launch succeeded but SymInitialize failed: " << FormatWin32Error(error);
        lastError_ = ss.str();
    }
    
    return true;
}

bool DebugSession::AttachToProcess(uint32_t processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    if (!DebugActiveProcess(processId)) {
        CloseHandle(hProcess);
        return false;
    }
    
    processHandle_ = hProcess;
    processId_ = processId;
    pImpl_->hProcess_ = hProcess;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    threadId_ = te.th32ThreadID;
                    threadHandle_ = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId_);
                    break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
    
    if (!pImpl_->InitializeDebugSymbols()) {
        DebugActiveProcessStop(processId);
        return false;
    }
    
    return true;
}

bool DebugSession::Detach() {
    if (!IsActive()) return false;
    
    for (const auto& bp : breakpoints_) {
        if (bp.enabled) {
            RemoveSoftwareBreakpoint(bp.address);
        }
    }
    breakpoints_.clear();
    
    if (DebugActiveProcessStop(processId_)) {
        processHandle_ = nullptr;
        threadHandle_ = nullptr;
        processId_ = 0;
        threadId_ = 0;
        return true;
    }
    
    return false;
}

bool DebugSession::Terminate() {
    if (!IsActive()) return false;
    
    TerminateProcess(processHandle_, 1);
    
    CloseHandle(processHandle_);
    if (threadHandle_) CloseHandle(threadHandle_);
    
    processHandle_ = nullptr;
    threadHandle_ = nullptr;
    processId_ = 0;
    threadId_ = 0;
    
    return true;
}

bool DebugSession::ContinueExecution() {
    if (!IsActive()) return false;
    return ContinueDebugEvent(processId_, threadId_, DBG_CONTINUE);
}

bool DebugSession::StepInto() {
    if (!IsActive() || !threadHandle_) return false;
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;
    
    if (!GetThreadContext(threadHandle_, &ctx)) {
        return false;
    }
    
    ctx.EFlags |= 0x100;
    
    return SetThreadContext(threadHandle_, &ctx) && 
           ContinueDebugEvent(processId_, threadId_, DBG_CONTINUE);
}

bool DebugSession::StepOver() {
    return StepInto();
}

bool DebugSession::StepOut() {
    return ContinueExecution();
}

bool DebugSession::BreakExecution() {
    if (!IsActive()) return false;
    return DebugBreakProcess(processHandle_);
}

std::optional<Breakpoint> DebugSession::SetBreakpoint(const std::wstring& filePath,
                                                       uint32_t lineNumber) {
    // Would resolve file:line to address via symbol resolver
    return std::nullopt;
}

std::optional<Breakpoint> DebugSession::SetBreakpointAtAddress(uint64_t address) {
    Breakpoint bp;
    bp.id = nextBreakpointId_++;
    bp.address = address;
    bp.enabled = true;
    bp.isHardware = false;
    
    if (!SetSoftwareBreakpoint(address)) {
        return std::nullopt;
    }
    
    breakpoints_.push_back(bp);
    return bp;
}

bool DebugSession::SetSoftwareBreakpoint(uint64_t address) {
    if (!IsActive()) return false;
    
    uint8_t originalByte = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(processHandle_, (LPCVOID)address, &originalByte, 1, &read)) {
        return false;
    }
    
    uint8_t int3 = 0xCC;
    SIZE_T written = 0;
    if (!WriteProcessMemory(processHandle_, (LPVOID)address, &int3, 1, &written)) {
        return false;
    }
    
    FlushInstructionCache(processHandle_, (LPCVOID)address, 1);
    
    // Store original byte in breakpoint
    for (auto& bp : breakpoints_) {
        if (bp.address == address) {
            bp.originalByte = originalByte;
            break;
        }
    }
    
    return true;
}

bool DebugSession::RemoveSoftwareBreakpoint(uint64_t address) {
    for (auto& bp : breakpoints_) {
        if (bp.address == address && bp.enabled) {
            SIZE_T written = 0;
            WriteProcessMemory(processHandle_, (LPVOID)address, &bp.originalByte, 1, &written);
            FlushInstructionCache(processHandle_, (LPCVOID)address, 1);
            return true;
        }
    }
    return false;
}

bool DebugSession::RemoveBreakpoint(uint64_t breakpointId) {
    for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
        if (it->id == breakpointId) {
            if (it->enabled) {
                RemoveSoftwareBreakpoint(it->address);
            }
            breakpoints_.erase(it);
            return true;
        }
    }
    return false;
}

bool DebugSession::EnableBreakpoint(uint64_t breakpointId, bool enable) {
    for (auto& bp : breakpoints_) {
        if (bp.id == breakpointId) {
            if (bp.enabled != enable) {
                if (enable) {
                    SetSoftwareBreakpoint(bp.address);
                } else {
                    RemoveSoftwareBreakpoint(bp.address);
                }
                bp.enabled = enable;
            }
            return true;
        }
    }
    return false;
}

std::vector<Breakpoint> DebugSession::GetBreakpoints() const {
    return breakpoints_;
}

std::vector<StackFrame> DebugSession::GetCallStack(uint32_t maxFrames) {
    std::vector<StackFrame> frames;
    
    if (!IsActive() || !threadHandle_) return frames;
    
    STACKFRAME64 stackFrame = {};
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(threadHandle_, &ctx)) {
        return frames;
    }
    
    stackFrame.AddrPC.Offset = ctx.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = ctx.Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = ctx.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    
    for (uint32_t i = 0; i < maxFrames; i++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, processHandle_, threadHandle_,
                        &stackFrame, &ctx, nullptr, 
                        SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
            break;
        }
        
        if (stackFrame.AddrPC.Offset == 0) break;
        
        StackFrame frame;
        frame.frameNumber = i;
        frame.instructionPointer = stackFrame.AddrPC.Offset;
        frame.stackPointer = stackFrame.AddrStack.Offset;
        frame.framePointer = stackFrame.AddrFrame.Offset;
        
        auto symbolInfo = symbolResolver_->ResolveAddress(frame.instructionPointer);
        if (symbolInfo) {
            frame.functionName = symbolInfo->name;
            frame.moduleName = symbolInfo->module;
            frame.filePath = symbolInfo->filePath;
            frame.lineNumber = symbolInfo->lineNumber;
            frame.displacement = symbolInfo->address - frame.instructionPointer;
        }
        
        frames.push_back(frame);
    }
    
    return frames;
}

std::vector<RegisterValue> DebugSession::GetRegisters() {
    std::vector<RegisterValue> regs;
    
    if (!IsActive() || !threadHandle_) return regs;
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(threadHandle_, &ctx)) {
        return regs;
    }
    
    auto addReg = [&](const wchar_t* name, uint64_t value, uint32_t size) {
        RegisterValue rv;
        rv.name = name;
        rv.value = value;
        rv.size = size;
        rv.formatted = FormatAddress(value);
        regs.push_back(rv);
    };
    
    addReg(L"rax", ctx.Rax, 8);
    addReg(L"rbx", ctx.Rbx, 8);
    addReg(L"rcx", ctx.Rcx, 8);
    addReg(L"rdx", ctx.Rdx, 8);
    addReg(L"rsi", ctx.Rsi, 8);
    addReg(L"rdi", ctx.Rdi, 8);
    addReg(L"rbp", ctx.Rbp, 8);
    addReg(L"rsp", ctx.Rsp, 8);
    addReg(L"rip", ctx.Rip, 8);
    addReg(L"r8", ctx.R8, 8);
    addReg(L"r9", ctx.R9, 8);
    addReg(L"r10", ctx.R10, 8);
    addReg(L"r11", ctx.R11, 8);
    addReg(L"r12", ctx.R12, 8);
    addReg(L"r13", ctx.R13, 8);
    addReg(L"r14", ctx.R14, 8);
    addReg(L"r15", ctx.R15, 8);
    addReg(L"eflags", ctx.EFlags, 4);
    
    return regs;
}

bool DebugSession::SetRegister(const std::wstring& name, uint64_t value) {
    if (!IsActive() || !threadHandle_) return false;
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(threadHandle_, &ctx)) {
        return false;
    }
    
    if (name == L"rax") ctx.Rax = value;
    else if (name == L"rbx") ctx.Rbx = value;
    else if (name == L"rcx") ctx.Rcx = value;
    else if (name == L"rdx") ctx.Rdx = value;
    else if (name == L"rsi") ctx.Rsi = value;
    else if (name == L"rdi") ctx.Rdi = value;
    else if (name == L"rbp") ctx.Rbp = value;
    else if (name == L"rsp") ctx.Rsp = value;
    else if (name == L"rip") ctx.Rip = value;
    else if (name == L"r8") ctx.R8 = value;
    else if (name == L"r9") ctx.R9 = value;
    else if (name == L"r10") ctx.R10 = value;
    else if (name == L"r11") ctx.R11 = value;
    else if (name == L"r12") ctx.R12 = value;
    else if (name == L"r13") ctx.R13 = value;
    else if (name == L"r14") ctx.R14 = value;
    else if (name == L"r15") ctx.R15 = value;
    else return false;
    
    return SetThreadContext(threadHandle_, &ctx);
}

std::vector<uint8_t> DebugSession::ReadMemory(uint64_t address, size_t size) {
    std::vector<uint8_t> data(size);
    SIZE_T read = 0;
    
    if (ReadProcessMemory(processHandle_, (LPCVOID)address, data.data(), size, &read)) {
        data.resize(read);
    } else {
        data.clear();
    }
    
    return data;
}

bool DebugSession::WriteMemory(uint64_t address, const std::vector<uint8_t>& data) {
    SIZE_T written = 0;
    return WriteProcessMemory(processHandle_, (LPVOID)address, data.data(), data.size(), &written);
}

void DebugSession::SetEventCallback(DebugEventCallback callback) {
    eventCallback_ = callback;
}

bool DebugSession::WaitForDebugEvent(DEBUG_EVENT& event, uint32_t timeoutMs) {
    return ::WaitForDebugEvent(&event, timeoutMs) != FALSE;
}

void DebugSession::ProcessEvents(uint32_t timeoutMs) {
    DEBUG_EVENT event;
    if (WaitForDebugEvent(event, timeoutMs)) {
        HandleDebugEvent(event);
    }
}

void DebugSession::RunEventLoop() {
    DEBUG_EVENT event;
    while (IsActive()) {
        if (WaitForDebugEvent(event, INFINITE)) {
            if (!HandleDebugEvent(event)) {
                break;
            }
        }
    }
}

bool DebugSession::HandleDebugEvent(const DEBUG_EVENT& event) {
    switch (event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            auto& exception = event.u.Exception;
            
            if (exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                uint64_t address = (uint64_t)exception.ExceptionRecord.ExceptionAddress;
                currentAddress_ = address;
                
                if (eventCallback_) {
                    eventCallback_(DebugEventType::Breakpoint, &address, this);
                }
                
                return true;
            }
            else if (exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                if (eventCallback_) {
                    eventCallback_(DebugEventType::StepComplete, nullptr, this);
                }
                return true;
            }
            else {
                if (eventCallback_) {
                    eventCallback_(DebugEventType::Exception, &exception, this);
                }
                return ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            }
        }
        
        case CREATE_PROCESS_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ModuleLoad, &event.u.CreateProcessInfo, this);
            }
            break;
            
        case EXIT_PROCESS_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ProcessExit, &event.u.ExitProcess, this);
            }
            return false;
            
        case LOAD_DLL_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ModuleLoad, &event.u.LoadDll, this);
            }
            break;
            
        case UNLOAD_DLL_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ModuleUnload, &event.u.UnloadDll, this);
            }
            break;
            
        case CREATE_THREAD_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ThreadCreate, &event.u.CreateThread, this);
            }
            break;
            
        case EXIT_THREAD_DEBUG_EVENT:
            if (eventCallback_) {
                eventCallback_(DebugEventType::ThreadExit, &event.u.ExitThread, this);
            }
            break;
            
        case OUTPUT_DEBUG_STRING_EVENT: {
            if (eventCallback_) {
                eventCallback_(DebugEventType::OutputDebugString, &event.u.DebugString, this);
            }
            break;
        }
    }
    
    return ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
}

uint64_t DebugSession::GetCurrentInstructionPointer() const {
    return currentAddress_;
}

// Utility functions
std::wstring FormatAddress(uint64_t address) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::uppercase << std::setfill(L'0') << std::setw(16) << address;
    return oss.str();
}

std::wstring FormatBytes(const std::vector<uint8_t>& bytes, size_t maxBytes) {
    std::wostringstream oss;
    size_t count = std::min(bytes.size(), maxBytes);
    
    for (size_t i = 0; i < count; i++) {
        if (i > 0) oss << L" ";
        oss << std::hex << std::uppercase << std::setfill(L'0') << std::setw(2) << (int)bytes[i];
    }
    
    if (bytes.size() > maxBytes) {
        oss << L" ...";
    }
    
    return oss.str();
}

} // namespace Debugger
} // namespace RawrXD
