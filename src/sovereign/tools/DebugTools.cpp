// ============================================================================
// DebugTools.cpp - Debugger Integration Implementation
// ============================================================================

#include "DebugTools.hpp"
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

namespace Sovereign {

DebugTools::DebugTools() = default;
DebugTools::~DebugTools() {
    if (attached_) Detach();
}

bool DebugTools::Attach(uint64_t pid) {
#ifdef _WIN32
    if (!DebugActiveProcess(pid)) {
        return false;
    }
    pid_ = pid;
    attached_ = true;
    return true;
#else
    return false;
#endif
}

bool DebugTools::Detach() {
#ifdef _WIN32
    if (attached_) {
        DebugActiveProcessStop(pid_);
        attached_ = false;
        return true;
    }
#endif
    return false;
}

bool DebugTools::Launch(const std::string& executable, const std::vector<std::string>& args) {
#ifdef _WIN32
    std::string cmdLine = executable;
    for (const auto& arg : args) {
        cmdLine += " " + arg;
    }
    
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    if (!CreateProcess(NULL, &cmdLine[0], NULL, NULL, FALSE, 
                       DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        return false;
    }
    
    pid_ = pi.dwProcessId;
    attached_ = true;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
#else
    return false;
#endif
}

bool DebugTools::Terminate() {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid_);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        attached_ = false;
        return true;
    }
#endif
    return false;
}

bool DebugTools::IsAttached() const {
    return attached_;
}

uint64_t DebugTools::SetBreakpoint(const std::string& file, int line, const std::string& condition) {
    Breakpoint bp;
    bp.id = rand() | (static_cast<uint64_t>(rand()) << 32);
    bp.file = file;
    bp.line = line;
    bp.condition = condition;
    bp.enabled = true;
    return bp.id;
}

bool DebugTools::RemoveBreakpoint(uint64_t id) {
    return true;
}

std::vector<StackFrame> DebugTools::GetStackTrace(int maxDepth) {
    std::vector<StackFrame> frames;
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);
    HANDLE hThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (hProcess) {
        STACKFRAME64 sf = {};
        // Simplified stack walk
        for (int i = 0; i < maxDepth; ++i) {
            StackFrame frame;
            frame.id = i;
            frame.function = "unknown_" + std::to_string(i);
            frame.line = i * 10;
            frames.push_back(frame);
        }
        CloseHandle(hProcess);
    }
#endif
    return frames;
}

std::vector<DebugVariable> DebugTools::GetLocals() {
    return {};
}

DebugVariable DebugTools::GetVariable(const std::string& name) {
    DebugVariable var;
    var.name = name;
    var.value = "<unknown>";
    return var;
}

std::vector<uint8_t> DebugTools::ReadMemory(uint64_t address, size_t size) {
    std::vector<uint8_t> data(size, 0);
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid_);
    if (hProcess) {
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, (LPCVOID)address, data.data(), size, &bytesRead);
        CloseHandle(hProcess);
    }
#endif
    return data;
}

bool DebugTools::WriteMemory(uint64_t address, const std::vector<uint8_t>& data) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid_);
    if (hProcess) {
        SIZE_T bytesWritten;
        WriteProcessMemory(hProcess, (LPVOID)address, data.data(), data.size(), &bytesWritten);
        CloseHandle(hProcess);
        return bytesWritten == data.size();
    }
#endif
    return false;
}

std::vector<std::pair<uint64_t, std::string>> DebugTools::Disassemble(uint64_t address, size_t count) {
    std::vector<std::pair<uint64_t, std::string>> result;
    for (size_t i = 0; i < count; ++i) {
        result.push_back({address + i * 4, "nop"});
    }
    return result;
}

} // namespace Sovereign
