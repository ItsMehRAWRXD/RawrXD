// ============================================================================
// RawrXD Debugger Integration
// ============================================================================
// Provides debugging capabilities for the IDE
// Features:
// - Breakpoint management
// - Stack trace display
// - Variable inspection
// - Step-through debugging
// ============================================================================

#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {
namespace Debugger {

// Breakpoint structure
struct Breakpoint {
    std::wstring file;
    int line;
    bool enabled;
    std::wstring condition;
};

// Stack frame structure
struct StackFrame {
    std::wstring function;
    std::wstring file;
    int line;
    uintptr_t address;
    std::vector<std::pair<std::wstring, std::wstring>> locals;
};

// Variable info
struct Variable {
    std::wstring name;
    std::wstring type;
    std::wstring value;
    bool expandable;
    std::vector<Variable> children;
};

class DebugEngine {
public:
    HANDLE m_hProcess = nullptr;
    DWORD m_processId = 0;
    bool m_isDebugging = false;
    std::vector<Breakpoint> m_breakpoints;
    std::vector<StackFrame> m_stackFrames;
    std::map<std::wstring, Variable> m_variables;
    
    bool Initialize() {
        // Initialize dbghelp
        SymInitialize(GetCurrentProcess(), nullptr, TRUE);
        return true;
    }
    
    void Shutdown() {
        if (m_hProcess) {
            CloseHandle(m_hProcess);
            m_hProcess = nullptr;
        }
        SymCleanup(GetCurrentProcess());
    }
    
    bool AttachToProcess(DWORD pid) {
        m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProcess) return false;
        
        m_processId = pid;
        m_isDebugging = true;
        return true;
    }
    
    bool LaunchProcess(const std::wstring& executable, const std::wstring& args) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        
        std::wstring cmdLine = L"\"" + executable + L"\" " + args;
        
        BOOL result = CreateProcessW(
            nullptr,
            &cmdLine[0],
            nullptr,
            nullptr,
            FALSE,
            DEBUG_ONLY_THIS_PROCESS,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        
        if (!result) return false;
        
        m_hProcess = pi.hProcess;
        m_processId = pi.dwProcessId;
        m_isDebugging = true;
        
        CloseHandle(pi.hThread);
        return true;
    }
    
    void AddBreakpoint(const std::wstring& file, int line, const std::wstring& condition = L"") {
        Breakpoint bp;
        bp.file = file;
        bp.line = line;
        bp.enabled = true;
        bp.condition = condition;
        m_breakpoints.push_back(bp);
    }
    
    void RemoveBreakpoint(const std::wstring& file, int line) {
        m_breakpoints.erase(
            std::remove_if(m_breakpoints.begin(), m_breakpoints.end(),
                [&](const Breakpoint& bp) {
                    return bp.file == file && bp.line == line;
                }),
            m_breakpoints.end()
        );
    }
    
    void ToggleBreakpoint(const std::wstring& file, int line) {
        for (auto& bp : m_breakpoints) {
            if (bp.file == file && bp.line == line) {
                bp.enabled = !bp.enabled;
                return;
            }
        }
        // If not found, add it
        AddBreakpoint(file, line);
    }
    
    bool StepInto() {
        if (!m_isDebugging) return false;
        // Implementation would use ContinueDebugEvent with DBG_CONTINUE
        return true;
    }
    
    bool StepOver() {
        if (!m_isDebugging) return false;
        // Implementation would set temporary breakpoint
        return true;
    }
    
    bool StepOut() {
        if (!m_isDebugging) return false;
        // Implementation would run until return
        return true;
    }
    
    bool Continue() {
        if (!m_isDebugging) return false;
        // ContinueDebugEvent(m_processId, m_threadId, DBG_CONTINUE);
        return true;
    }
    
    bool Pause() {
        if (!m_isDebugging) return false;
        // Suspend all threads
        return DebugBreakProcess(m_hProcess);
    }
    
    void UpdateStackTrace() {
        m_stackFrames.clear();
        
        // Use StackWalk64 to get stack frames
        // This is a simplified version
        STACKFRAME64 stackFrame = {};
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_FULL;
        
        // Get context of current thread
        // GetThreadContext(hThread, &context);
        
        // Walk stack
        // while (StackWalk64(...)) {
        //     StackFrame frame;
        //     frame.address = stackFrame.AddrPC.Offset;
        //     // Resolve symbols
        //     m_stackFrames.push_back(frame);
        // }
    }
    
    void UpdateVariables() {
        m_variables.clear();
        
        // Enumerate local variables from PDB
        // This requires DIA SDK or similar
        
        // Example variable
        Variable var;
        var.name = L"example";
        var.type = L"int";
        var.value = L"42";
        var.expandable = false;
        m_variables[L"example"] = var;
    }
    
    Variable EvaluateExpression(const std::wstring& expression) {
        Variable result;
        result.name = expression;
        result.type = L"unknown";
        result.value = L"<not implemented>";
        result.expandable = false;
        return result;
    }
};

// Debugger UI Panel
class DebuggerPanel {
public:
    HWND m_hwnd = nullptr;
    HWND m_hBreakpoints = nullptr;
    HWND m_hStack = nullptr;
    HWND m_hVariables = nullptr;
    HWND m_hOutput = nullptr;
    
    DebugEngine* m_engine = nullptr;
    
    bool Create(HWND parent, int x, int y, int width, int height) {
        // Create main panel
        m_hwnd = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"Debugger",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            x, y, width, height, parent, nullptr, GetModuleHandle(nullptr), nullptr);
        
        if (!m_hwnd) return false;
        
        int margin = 5;
        int sectionHeight = (height - margin * 5) / 4;
        
        // Breakpoints list
        CreateWindowW(L"STATIC", L"Breakpoints:",
            WS_CHILD | WS_VISIBLE,
            margin, margin, 100, 20, m_hwnd, nullptr, nullptr, nullptr);
        
        m_hBreakpoints = CreateWindowW(L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            margin, margin + 20, width - margin * 2, sectionHeight,
            m_hwnd, (HMENU)4001, nullptr, nullptr);
        
        // Call stack
        CreateWindowW(L"STATIC", L"Call Stack:",
            WS_CHILD | WS_VISIBLE,
            margin, margin + sectionHeight + margin, 100, 20, m_hwnd, nullptr, nullptr, nullptr);
        
        m_hStack = CreateWindowW(L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            margin, margin + sectionHeight + margin + 20, width - margin * 2, sectionHeight,
            m_hwnd, (HMENU)4002, nullptr, nullptr);
        
        // Variables
        CreateWindowW(L"STATIC", L"Variables:",
            WS_CHILD | WS_VISIBLE,
            margin, margin + (sectionHeight + margin) * 2, 100, 20, m_hwnd, nullptr, nullptr, nullptr);
        
        m_hVariables = CreateWindowW(L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
            margin, margin + (sectionHeight + margin) * 2 + 20, width - margin * 2, sectionHeight,
            m_hwnd, (HMENU)4003, nullptr, nullptr);
        
        // Debug output
        CreateWindowW(L"STATIC", L"Output:",
            WS_CHILD | WS_VISIBLE,
            margin, margin + (sectionHeight + margin) * 3, 100, 20, m_hwnd, nullptr, nullptr, nullptr);
        
        m_hOutput = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            margin, margin + (sectionHeight + margin) * 3 + 20, width - margin * 2, sectionHeight - margin,
            m_hwnd, nullptr, nullptr, nullptr);
        
        return true;
    }
    
    void SetEngine(DebugEngine* engine) { m_engine = engine; }
    
    void UpdateBreakpoints() {
        if (!m_engine) return;
        
        SendMessageW(m_hBreakpoints, LB_RESETCONTENT, 0, 0);
        
        for (const auto& bp : m_engine->m_breakpoints) {
            std::wstring text = bp.file + L":" + std::to_wstring(bp.line);
            if (!bp.enabled) text += L" (disabled)";
            if (!bp.condition.empty()) text += L" [" + bp.condition + L"]";
            
            SendMessageW(m_hBreakpoints, LB_ADDSTRING, 0, (LPARAM)text.c_str());
        }
    }
    
    void UpdateStackTrace() {
        if (!m_engine) return;
        
        SendMessageW(m_hStack, LB_RESETCONTENT, 0, 0);
        
        for (const auto& frame : m_engine->m_stackFrames) {
            std::wstring text = frame.function + L" at " + frame.file + L":" + std::to_wstring(frame.line);
            SendMessageW(m_hStack, LB_ADDSTRING, 0, (LPARAM)text.c_str());
        }
    }
    
    void UpdateVariables() {
        if (!m_engine) return;
        
        SendMessageW(m_hVariables, LB_RESETCONTENT, 0, 0);
        
        for (const auto& [name, var] : m_engine->m_variables) {
            std::wstring text = var.type + L" " + var.name + L" = " + var.value;
            SendMessageW(m_hVariables, LB_ADDSTRING, 0, (LPARAM)text.c_str());
        }
    }
    
    void LogOutput(const std::wstring& message) {
        int len = GetWindowTextLengthW(m_hOutput);
        SendMessageW(m_hOutput, EM_SETSEL, len, len);
        SendMessageW(m_hOutput, EM_REPLACESEL, FALSE, (LPARAM)message.c_str());
        SendMessageW(m_hOutput, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    }
};

} // namespace Debugger
} // namespace RawrXD
