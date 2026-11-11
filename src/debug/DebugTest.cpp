//=============================================================================
// RawrXD Debug Backend Test
// Simple console test for the debug backend
//=============================================================================
#include "DebugBackend.h"
#include <iostream>
#include <string>

using namespace RawrXD::Debug;

void PrintRegisters(const RegisterContext& ctx) {
    std::cout << "Registers:\n";
    std::cout << "  RAX: " << Utils::FormatAddress(ctx.rax) << "  RCX: " << Utils::FormatAddress(ctx.rcx) << "  RDX: " << Utils::FormatAddress(ctx.rdx) << "\n";
    std::cout << "  RBX: " << Utils::FormatAddress(ctx.rbx) << "  RSP: " << Utils::FormatAddress(ctx.rsp) << "  RBP: " << Utils::FormatAddress(ctx.rbp) << "\n";
    std::cout << "  RSI: " << Utils::FormatAddress(ctx.rsi) << "  RDI: " << Utils::FormatAddress(ctx.rdi) << "  RIP: " << Utils::FormatAddress(ctx.rip) << "\n";
    std::cout << "  R8:  " << Utils::FormatAddress(ctx.r8)  << "  R9:  " << Utils::FormatAddress(ctx.r9)  << "  R10: " << Utils::FormatAddress(ctx.r10) << "\n";
    std::cout << "  R11: " << Utils::FormatAddress(ctx.r11) << "  R12: " << Utils::FormatAddress(ctx.r12) << "  R13: " << Utils::FormatAddress(ctx.r13) << "\n";
    std::cout << "  R14: " << Utils::FormatAddress(ctx.r14) << "  R15: " << Utils::FormatAddress(ctx.r15) << "  EFL: " << std::hex << ctx.eflags << "\n";
}

void PrintStackFrame(const StackFrame& frame, size_t index) {
    std::cout << "  [" << index << "] " << Utils::FormatAddress(frame.instructionPointer);
    
    if (!frame.functionName.empty()) {
        std::cout << " " << frame.functionName;
        if (!frame.moduleName.empty()) {
            std::cout << " [" << frame.moduleName << "]";
        }
    }
    
    if (!frame.sourceFile.empty()) {
        std::cout << "\n      " << frame.sourceFile << ":" << frame.sourceLine;
    }
    
    std::cout << "\n";
}

void OnDebugEvent(const DebugEvent& event) {
    std::cout << "\n=== Debug Event ===\n";
    std::cout << "Process: " << event.processId << " Thread: " << event.threadId << "\n";
    
    switch (event.type) {
        case DebugEventType::ProcessCreated:
            std::cout << "Type: Process Created\n";
            break;
        case DebugEventType::ProcessExited:
            std::cout << "Type: Process Exited (code: " << event.exitCode << ")\n";
            break;
        case DebugEventType::BreakpointHit:
            std::cout << "Type: Breakpoint Hit at " << Utils::FormatAddress(event.exceptionAddress) << "\n";
            PrintRegisters(event.registers);
            if (!event.callStack.empty()) {
                std::cout << "Call Stack:\n";
                for (size_t i = 0; i < event.callStack.size(); i++) {
                    PrintStackFrame(event.callStack[i], i);
                }
            }
            break;
        case DebugEventType::SingleStep:
            std::cout << "Type: Single Step at " << Utils::FormatAddress(event.exceptionAddress) << "\n";
            PrintRegisters(event.registers);
            break;
        case DebugEventType::Exception:
            std::cout << "Type: Exception 0x" << std::hex << event.exceptionCode << "\n";
            std::cout << "Message: " << event.exceptionMessage << "\n";
            break;
        default:
            std::cout << "Type: Other (" << static_cast<int>(event.type) << ")\n";
            break;
    }
}

void PrintHelp() {
    std::cout << "RawrXD Debug Backend Test\n";
    std::cout << "Commands:\n";
    std::cout << "  launch <exepath> [args]  - Launch and debug process\n";
    std::cout << "  attach <pid>             - Attach to running process\n";
    std::cout << "  break <address>         - Set breakpoint\n";
    std::cout << "  go                       - Continue execution\n";
    std::cout << "  step                     - Step into\n";
    std::cout << "  over                     - Step over\n";
    std::cout << "  out                      - Step out\n";
    std::cout << "  regs                     - Show registers\n";
    std::cout << "  stack                    - Show call stack\n";
    std::cout << "  detach                   - Detach from process\n";
    std::cout << "  quit                     - Exit\n";
    std::cout << "\n";
}

int wmain(int argc, wchar_t* argv[]) {
    PrintHelp();
    
    // Enable debug privilege
    if (!DebugBackend::EnableDebugPrivilege()) {
        std::cout << "Warning: Could not enable debug privilege. May not be able to attach to all processes.\n";
    }
    
    auto session = DebugBackend::Instance().CreateSession();
    session->SetEventCallback(OnDebugEvent);
    
    std::wstring command;
    while (true) {
        std::cout << "> ";
        std::getline(std::wcin, command);
        
        if (command.empty()) continue;
        
        // Parse command
        size_t spacePos = command.find(' ');
        std::wstring cmd = (spacePos == std::wstring::npos) ? command : command.substr(0, spacePos);
        std::wstring args = (spacePos == std::wstring::npos) ? L"" : command.substr(spacePos + 1);
        
        if (cmd == L"launch" || cmd == L"run") {
            if (args.empty()) {
                std::cout << "Usage: launch <exepath> [args]\n";
                continue;
            }
            
            size_t argSpace = args.find(' ');
            std::wstring exe = (argSpace == std::wstring::npos) ? args : args.substr(0, argSpace);
            std::wstring exeArgs = (argSpace == std::wstring::npos) ? L"" : args.substr(argSpace + 1);
            
            std::cout << "Launching: " << Utils::WideToUtf8(exe) << "\n";
            if (session->LaunchProcess(exe.c_str(), exeArgs.empty() ? nullptr : exeArgs.c_str())) {
                std::cout << "Process launched. PID: " << session->GetProcessId() << "\n";
            } else {
                std::cout << "Failed to launch process. Error: " << DebugBackend::GetLastErrorString() << "\n";
            }
        }
        else if (cmd == L"attach") {
            if (args.empty()) {
                std::cout << "Usage: attach <pid>\n";
                continue;
            }
            
            uint32_t pid = std::stoul(args);
            std::cout << "Attaching to PID: " << pid << "\n";
            if (session->AttachProcess(pid)) {
                std::cout << "Attached successfully.\n";
            } else {
                std::cout << "Failed to attach. Error: " << DebugBackend::GetLastErrorString() << "\n";
            }
        }
        else if (cmd == L"break" || cmd == L"bp") {
            if (args.empty()) {
                std::cout << "Usage: break <address>\n";
                continue;
            }
            
            uint64_t addr = std::stoull(args, nullptr, 0);
            if (session->SetBreakpoint(addr)) {
                std::cout << "Breakpoint set at " << Utils::FormatAddress(addr) << "\n";
            } else {
                std::cout << "Failed to set breakpoint.\n";
            }
        }
        else if (cmd == L"go" || cmd == L"g" || cmd == L"continue") {
            if (session->ContinueExecution()) {
                std::cout << "Continuing...\n";
            } else {
                std::cout << "Failed to continue.\n";
            }
        }
        else if (cmd == L"step" || cmd == L"s") {
            if (session->StepInto()) {
                std::cout << "Stepping into...\n";
            } else {
                std::cout << "Failed to step.\n";
            }
        }
        else if (cmd == L"over" || cmd == L"n") {
            if (session->StepOver()) {
                std::cout << "Stepping over...\n";
            } else {
                std::cout << "Failed to step over.\n";
            }
        }
        else if (cmd == L"out") {
            if (session->StepOut()) {
                std::cout << "Stepping out...\n";
            } else {
                std::cout << "Failed to step out.\n";
            }
        }
        else if (cmd == L"regs" || cmd == L"r") {
            RegisterContext ctx;
            if (session->GetRegisters(ctx)) {
                PrintRegisters(ctx);
            } else {
                std::cout << "Failed to get registers.\n";
            }
        }
        else if (cmd == L"stack" || cmd == L"k") {
            auto stack = session->GetCallStack();
            if (!stack.empty()) {
                std::cout << "Call Stack:\n";
                for (size_t i = 0; i < stack.size(); i++) {
                    PrintStackFrame(stack[i], i);
                }
            } else {
                std::cout << "Failed to get call stack or stack is empty.\n";
            }
        }
        else if (cmd == L"detach") {
            if (session->DetachProcess()) {
                std::cout << "Detached successfully.\n";
            } else {
                std::cout << "Failed to detach.\n";
            }
        }
        else if (cmd == L"quit" || cmd == L"q" || cmd == L"exit") {
            break;
        }
        else if (cmd == L"help" || cmd == L"?") {
            PrintHelp();
        }
        else {
            std::cout << "Unknown command: " << Utils::WideToUtf8(cmd) << "\n";
        }
    }
    
    DebugBackend::Instance().DestroySession(session);
    return 0;
}
