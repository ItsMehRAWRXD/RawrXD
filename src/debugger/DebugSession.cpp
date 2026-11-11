/*===========================================================================
 * DebugSession.cpp
 * CDB-based debugger implementation
 *===========================================================================*/

#include "DebugSession.h"
#include "../ide/IDEDebuggerTypes.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Debugger {

/*===========================================================================
 * Constants
 *=========================================================================*/
constexpr wchar_t DebugSession::CDB_PATH[];
constexpr DWORD CDB_TIMEOUT_MS = 30000;
constexpr size_t PIPE_BUFFER_SIZE = 65536;

/*===========================================================================
 * Construction / Destruction
 *=========================================================================*/

DebugSession::DebugSession()
    : hCDBProcess_(NULL)
    , hCDBThread_(NULL)
    , hReadPipe_(NULL)
    , hWritePipe_(NULL)
    , hErrorPipe_(NULL)
    , stopReader_(false)
    , state_(DebugSessionState::Idle)
    , isActive_(false)
    , isRunning_(false)
    , processId_(0)
    , currentIP_(0)
    , currentLine_(0)
    , nextBpId_(1)
    , hCommandEvent_(NULL)
{
    InitializeCriticalSection(&bpLock_);
    InitializeCriticalSection(&commandLock_);
}

DebugSession::~DebugSession() {
    Shutdown();
    DeleteCriticalSection(&bpLock_);
    DeleteCriticalSection(&commandLock_);
}

/*===========================================================================
 * Initialization
 *=========================================================================*/

bool DebugSession::Initialize() {
    hCommandEvent_ = CreateEventW(NULL, FALSE, FALSE, NULL);
    return hCommandEvent_ != NULL;
}

void DebugSession::Shutdown() {
    stopReader_ = true;
    
    if (readerThread_.joinable()) {
        readerThread_.join();
    }
    
    StopCDB();
    
    if (hCommandEvent_) {
        CloseHandle(hCommandEvent_);
        hCommandEvent_ = NULL;
    }
}

/*===========================================================================
 * CDB Process Management
 *=========================================================================*/

bool DebugSession::StartCDB(const std::wstring& commandLine) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    
    // Create pipes for stdin/stdout/stderr
    HANDLE hChildRead = NULL, hChildWrite = NULL;
    HANDLE hChildErrorRead = NULL, hChildErrorWrite = NULL;
    
    if (!CreatePipe(&hChildRead, &hWritePipe_, &sa, PIPE_BUFFER_SIZE) ||
        !CreatePipe(&hReadPipe_, &hChildWrite, &sa, PIPE_BUFFER_SIZE) ||
        !CreatePipe(&hChildErrorRead, &hChildErrorWrite, &sa, PIPE_BUFFER_SIZE)) {
        return false;
    }
    
    // Ensure we don't inherit the write ends
    SetHandleInformation(hWritePipe_, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hReadPipe_, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrorPipe_, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hChildRead;
    si.hStdOutput = hChildWrite;
    si.hStdError = hChildErrorWrite;
    
    PROCESS_INFORMATION pi = {};
    
    std::wstring fullCmdLine = L"\"";
    fullCmdLine += CDB_PATH;
    fullCmdLine += L"\" ";
    fullCmdLine += commandLine;
    
    if (!CreateProcessW(NULL, &fullCmdLine[0], NULL, NULL, TRUE,
                       CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(hChildRead);
        CloseHandle(hChildWrite);
        CloseHandle(hChildErrorRead);
        CloseHandle(hChildErrorWrite);
        return false;
    }
    
    hCDBProcess_ = pi.hProcess;
    hCDBThread_ = pi.hThread;
    
    // Close child-side handles
    CloseHandle(hChildRead);
    CloseHandle(hChildWrite);
    CloseHandle(hChildErrorWrite);
    
    // Resume the process
    ResumeThread(hCDBThread_);
    
    // Start reader thread
    stopReader_ = false;
    readerThread_ = std::thread(&DebugSession::CDBReaderThread, this);
    
    return true;
}

void DebugSession::StopCDB() {
    if (hCDBProcess_) {
        TerminateProcess(hCDBProcess_, 0);
        WaitForSingleObject(hCDBProcess_, 5000);
        CloseHandle(hCDBProcess_);
        hCDBProcess_ = NULL;
    }
    
    if (hCDBThread_) {
        CloseHandle(hCDBThread_);
        hCDBThread_ = NULL;
    }
    
    if (hReadPipe_) {
        CloseHandle(hReadPipe_);
        hReadPipe_ = NULL;
    }
    
    if (hWritePipe_) {
        CloseHandle(hWritePipe_);
        hWritePipe_ = NULL;
    }
    
    if (hErrorPipe_) {
        CloseHandle(hErrorPipe_);
        hErrorPipe_ = NULL;
    }
}

/*===========================================================================
 * Session Control
 *=========================================================================*/

bool DebugSession::LaunchProcess(const std::wstring& executable,
                                  const std::wstring& arguments,
                                  const std::wstring& workingDir) {
    if (isActive_) {
        return false;
    }
    
    TransitionToState(DebugSessionState::Starting);
    
    std::wstring cmdLine = L"-G -g ";  // Ignore first chance exceptions, go
    cmdLine += L"\"" + executable + L"\" ";
    cmdLine += arguments;
    
    if (!StartCDB(cmdLine)) {
        TransitionToState(DebugSessionState::Error);
        return false;
    }
    
    // Wait for initial prompt
    if (!WaitForPrompt()) {
        StopCDB();
        TransitionToState(DebugSessionState::Error);
        return false;
    }
    
    isActive_ = true;
    isRunning_ = true;
    TransitionToState(DebugSessionState::Running);
    
    return true;
}

bool DebugSession::AttachToProcess(uint32_t pid) {
    if (isActive_) {
        return false;
    }
    
    TransitionToState(DebugSessionState::Starting);
    
    std::wstring cmdLine = L"-p " + std::to_wstring(pid) + L" -G -g";
    
    if (!StartCDB(cmdLine)) {
        TransitionToState(DebugSessionState::Error);
        return false;
    }
    
    if (!WaitForPrompt()) {
        StopCDB();
        TransitionToState(DebugSessionState::Error);
        return false;
    }
    
    isActive_ = true;
    isRunning_ = true;
    processId_ = pid;
    TransitionToState(DebugSessionState::Running);
    
    return true;
}

void DebugSession::Terminate() {
    if (!isActive_) return;
    
    SendCDBCommand("q");  // Quit command
    Sleep(100);
    
    StopCDB();
    
    isActive_ = false;
    isRunning_ = false;
    TransitionToState(DebugSessionState::Idle);
}

void DebugSession::Detach() {
    if (!isActive_) return;
    
    SendCDBCommand("qd");  // Quit and detach
    
    StopCDB();
    
    isActive_ = false;
    isRunning_ = false;
    TransitionToState(DebugSessionState::Idle);
}

/*===========================================================================
 * Execution Control
 *=========================================================================*/

bool DebugSession::ContinueExecution() {
    if (!isActive_ || isRunning_) return false;
    
    TransitionToState(DebugSessionState::Running);
    isRunning_ = true;
    
    return SendCDBCommand("g");  // Go
}

bool DebugSession::StepOver() {
    if (!isActive_ || isRunning_) return false;
    
    TransitionToState(DebugSessionState::Stepping);
    isRunning_ = true;
    
    return SendCDBCommand("p");  // Step over
}

bool DebugSession::StepInto() {
    if (!isActive_ || isRunning_) return false;
    
    TransitionToState(DebugSessionState::Stepping);
    isRunning_ = true;
    
    return SendCDBCommand("t");  // Step into
}

bool DebugSession::StepOut() {
    if (!isActive_ || isRunning_) return false;
    
    TransitionToState(DebugSessionState::Stepping);
    isRunning_ = true;
    
    return SendCDBCommand("gu");  // Go up (step out)
}

bool DebugSession::BreakExecution() {
    if (!isActive_ || !isRunning_) return false;
    
    // Send Ctrl+C to CDB
    if (hCDBProcess_) {
        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        return true;
    }
    
    return false;
}

/*===========================================================================
 * Breakpoints
 *=========================================================================*/

bool DebugSession::SetBreakpoint(const std::wstring& file, uint32_t line) {
    if (!isActive_) return false;
    
    EnterCriticalSection(&bpLock_);
    
    uint32_t bpId = nextBpId_++;
    Breakpoint bp;
    bp.id = bpId;
    bp.filePath = file;
    bp.lineNumber = line;
    bp.enabled = true;
    
    breakpoints_[bpId] = bp;
    
    LeaveCriticalSection(&bpLock_);
    
    // Set in CDB using line number
    std::string cmd = "bp `" + std::string(file.begin(), file.end()) + ":" + 
                      std::to_string(line) + "`";
    
    std::wstring output;
    return ExecuteCommand(std::wstring(cmd.begin(), cmd.end()), output);
}

bool DebugSession::SetBreakpointByAddress(uint64_t address) {
    if (!isActive_) return false;
    
    std::stringstream ss;
    ss << "bp 0x" << std::hex << address;
    
    std::wstring output;
    return ExecuteCommand(std::wstring(ss.str().begin(), ss.str().end()), output);
}

bool DebugSession::RemoveBreakpoint(uint32_t bpId) {
    if (!isActive_) return false;
    
    EnterCriticalSection(&bpLock_);
    auto it = breakpoints_.find(bpId);
    if (it == breakpoints_.end()) {
        LeaveCriticalSection(&bpLock_);
        return false;
    }
    breakpoints_.erase(it);
    LeaveCriticalSection(&bpLock_);
    
    std::string cmd = "bc " + std::to_string(bpId);
    std::wstring output;
    return ExecuteCommand(std::wstring(cmd.begin(), cmd.end()), output);
}

bool DebugSession::RemoveBreakpointAt(const std::wstring& file, uint32_t line) {
    EnterCriticalSection(&bpLock_);
    
    for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
        if (it->second.filePath == file && it->second.lineNumber == line) {
            uint32_t bpId = it->first;
            LeaveCriticalSection(&bpLock_);
            return RemoveBreakpoint(bpId);
        }
    }
    
    LeaveCriticalSection(&bpLock_);
    return false;
}

void DebugSession::ClearAllBreakpoints() {
    if (!isActive_) return;
    
    EnterCriticalSection(&bpLock_);
    breakpoints_.clear();
    LeaveCriticalSection(&bpLock_);
    
    std::wstring output;
    ExecuteCommand(L"bc *", output);  // Clear all breakpoints
}

std::vector<Breakpoint> DebugSession::GetBreakpoints() const {
    EnterCriticalSection(&const_cast<CRITICAL_SECTION&>(bpLock_));
    
    std::vector<Breakpoint> result;
    for (const auto& pair : breakpoints_) {
        result.push_back(pair.second);
    }
    
    LeaveCriticalSection(&const_cast<CRITICAL_SECTION&>(bpLock_));
    return result;
}

/*===========================================================================
 * Stack & Variables
 *=========================================================================*/

bool DebugSession::RefreshStackFrames() {
    if (!isActive_ || isRunning_) return false;
    
    std::wstring output;
    return ExecuteCommand(L"k", output);  // Stack trace
}

bool DebugSession::RefreshLocalVariables() {
    if (!isActive_ || isRunning_) return false;
    
    std::wstring output;
    return ExecuteCommand(L"dv", output);  // Display local variables
}

bool DebugSession::RefreshRegisters() {
    if (!isActive_ || isRunning_) return false;
    
    std::wstring output;
    return ExecuteCommand(L"r", output);  // Display registers
}

bool DebugSession::EvaluateExpression(const std::wstring& expr, std::wstring& result) {
    if (!isActive_ || isRunning_) return false;
    
    std::wstring cmd = L"? " + expr;
    return ExecuteCommand(cmd, result);
}

/*===========================================================================
 * State Queries
 *=========================================================================*/

bool DebugSession::IsActive() const {
    return isActive_;
}

bool DebugSession::IsRunning() const {
    return isRunning_;
}

DebugSessionState DebugSession::GetState() const {
    return state_.load();
}

uint32_t DebugSession::GetProcessId() const {
    return processId_;
}

uint64_t DebugSession::GetCurrentInstructionPointer() const {
    return currentIP_;
}

std::wstring DebugSession::GetCurrentFile() const {
    return currentFile_;
}

uint32_t DebugSession::GetCurrentLine() const {
    return currentLine_;
}

/*===========================================================================
 * Callbacks
 *=========================================================================*/

void DebugSession::SetEventCallback(DebugEventCallback callback) {
    eventCallback_ = callback;
}

void DebugSession::SetOutputCallback(std::function<void(const std::wstring&)> callback) {
    outputCallback_ = callback;
}

/*===========================================================================
 * Direct Command Execution
 *=========================================================================*/

bool DebugSession::ExecuteCommand(const std::wstring& command, std::wstring& output) {
    if (!isActive_ || !hWritePipe_) return false;
    
    EnterCriticalSection(&commandLock_);
    lastResponse_.clear();
    LeaveCriticalSection(&commandLock_);
    
    if (!SendCDBCommand(std::string(command.begin(), command.end()))) {
        return false;
    }
    
    // Wait for response
    DWORD waitResult = WaitForSingleObject(hCommandEvent_, CDB_TIMEOUT_MS);
    if (waitResult != WAIT_OBJECT_0) {
        return false;
    }
    
    EnterCriticalSection(&commandLock_);
    output = std::wstring(lastResponse_.begin(), lastResponse_.end());
    LeaveCriticalSection(&commandLock_);
    
    return true;
}

/*===========================================================================
 * CDB Communication
 *=========================================================================*/

bool DebugSession::SendCDBCommand(const std::string& command) {
    if (!hWritePipe_) return false;
    
    std::string cmd = command + "\n";
    DWORD written;
    return WriteFile(hWritePipe_, cmd.c_str(), (DWORD)cmd.length(), &written, NULL);
}

bool DebugSession::WaitForPrompt() {
    // Wait for CDB to show its prompt
    DWORD waitResult = WaitForSingleObject(hCommandEvent_, CDB_TIMEOUT_MS);
    return waitResult == WAIT_OBJECT_0;
}

void DebugSession::CDBReaderThread() {
    char buffer[PIPE_BUFFER_SIZE];
    std::string lineBuffer;
    
    while (!stopReader_ && hReadPipe_) {
        DWORD bytesRead;
        BOOL success = ReadFile(hReadPipe_, buffer, sizeof(buffer) - 1, 
                                &bytesRead, NULL);
        
        if (!success || bytesRead == 0) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                break;
            }
            Sleep(10);
            continue;
        }
        
        buffer[bytesRead] = '\0';
        lineBuffer += buffer;
        
        // Process complete lines
        size_t pos;
        while ((pos = lineBuffer.find('\n')) != std::string::npos) {
            std::string line = lineBuffer.substr(0, pos);
            lineBuffer.erase(0, pos + 1);
            
            // Remove carriage return
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            
            ProcessCDBOutput(line);
        }
    }
}

/*===========================================================================
 * CDB Output Parsing
 *=========================================================================*/

void DebugSession::ProcessCDBOutput(const std::string& line) {
    // Check for prompt
    if (line.find("0:000>") != std::string::npos ||
        line.find("1:000>") != std::string::npos) {
        
        EnterCriticalSection(&commandLock_);
        SetEvent(hCommandEvent_);
        LeaveCriticalSection(&commandLock_);
        
        isRunning_ = false;
        TransitionToState(DebugSessionState::Breakpoint);
        return;
    }
    
    // Check for breakpoint hit
    if (line.find("Breakpoint") != std::string::npos) {
        ParseBreakpointHit(line);
    }
    
    // Check for exception
    if (line.find("Exception") != std::string::npos ||
        line.find("First chance") != std::string::npos) {
        ParseException(line);
    }
    
    // Check for module load
    if (line.find("ModLoad:") != std::string::npos) {
        ParseModuleLoad(line);
    }
    
    // Accumulate for command response
    EnterCriticalSection(&commandLock_);
    lastResponse_ += line + "\n";
    LeaveCriticalSection(&commandLock_);
    
    // Forward to output callback
    if (outputCallback_) {
        outputCallback_(std::wstring(line.begin(), line.end()));
    }
}

void DebugSession::ParseBreakpointHit(const std::string& line) {
    // Example: "Breakpoint 0 hit"
    isRunning_ = false;
    TransitionToState(DebugSessionState::Breakpoint);
    
    Breakpoint bp = {};
    bp.id = 0;
    NotifyEvent(DebugEventType::Breakpoint, &bp);
}

void DebugSession::ParseException(const std::string& line) {
    isRunning_ = false;
    TransitionToState(DebugSessionState::Exception);
    
    std::wstring wline(line.begin(), line.end());
    NotifyEvent(DebugEventType::Exception, &wline);
}

void DebugSession::ParseModuleLoad(const std::string& line) {
    // Example: "ModLoad: 00007ff6`a1b20000 00007ff6`a1b30000   MyApp.exe"
    NotifyEvent(DebugEventType::ModuleLoad, nullptr);
}

/*===========================================================================
 * State Machine
 *=========================================================================*/

void DebugSession::TransitionToState(DebugSessionState newState) {
    DebugSessionState oldState = state_.exchange(newState);
    if (oldState != newState) {
        // State changed - could log here
    }
}

void DebugSession::NotifyEvent(DebugEventType event, const void* data) {
    if (eventCallback_) {
        eventCallback_(event, data, this);
    }
}

} // namespace Debugger
} // namespace RawrXD
