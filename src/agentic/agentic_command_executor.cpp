<<<<<<< HEAD
// agentic_command_executor.cpp — Qt-free Win32 process execution (C++20, no Qt)
// Uses header include/agentic/agentic_command_executor.h

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "agentic/agentic_command_executor.h"
#include <algorithm>
#include <cstdio>
#include <cctype>

AgenticCommandExecutor::AgenticCommandExecutor()
{
    m_autoApproveList = {
        "npm test", "cargo check", "pytest", "python -m pytest",
        "cargo build", "make", "cmake --build"
    };
}

AgenticCommandExecutor::~AgenticCommandExecutor()
{
    cancelCommand();
}

void AgenticCommandExecutor::setAutoApproveList(const std::vector<std::string>& commands)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_autoApproveList = commands;
}

CommandExecResult AgenticCommandExecutor::executeCommand(const std::string& command,
                                                         const std::vector<std::string>& arguments,
                                                         bool requireApproval)
{
    CommandExecResult res{};
    res.exitCode = -1;

    if (requireApproval && !isAutoApproved(command)) {
        if (onApproval && !onApproval(command)) {
            fprintf(stderr, "[AgenticCmdExec] Command rejected: %s\n", command.c_str());
            return res;
        }
    }

    std::string cmdline = command;
    for (const auto& arg : arguments) {
        cmdline += " ";
        cmdline += arg;
    }

    if (onStarted) onStarted(command);
    fprintf(stderr, "[AgenticCmdExec] Executing: %s\n", cmdline.c_str());

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hPipeRead = nullptr, hPipeWrite = nullptr;

    if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
        res.stdErr = "Failed to create output pipe";
        if (onFinished) onFinished(false, -1);
        return res;
    }

    SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hPipeWrite;
    si.hStdError  = hPipeWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    std::vector<char> cmdBuf(cmdline.begin(), cmdline.end());
    cmdBuf.push_back('\0');

    BOOL created = CreateProcessA(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    CloseHandle(hPipeWrite);

    if (!created) {
        res.stdErr = "CreateProcess failed, error " + std::to_string(GetLastError());
        CloseHandle(hPipeRead);
        if (onFinished) onFinished(false, -1);
        return res;
    }

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_processHandle = pi.hProcess;
    }

    auto readPipe = [](HANDLE h) -> std::string {
        std::string result;
        char buf[4096];
        DWORD bytesRead = 0;
        while (ReadFile(h, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            result.append(buf, bytesRead);
        }
        return result;
    };

    res.stdOut = readPipe(hPipeRead);
    res.stdErr.clear();

    CloseHandle(hPipeRead);

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    res.exitCode = static_cast<int>(exitCode);
    res.success  = (exitCode == 0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_processHandle = nullptr;
    }

    if (onOutput && !res.stdOut.empty()) onOutput(res.stdOut);

    {
        std::lock_guard<std::mutex> lk2(m_mutex);
        m_lastOutput = res.stdOut;
        if (!res.stdErr.empty()) {
            if (!m_lastOutput.empty()) m_lastOutput += "\n";
            m_lastOutput += res.stdErr;
        }
    }

    fprintf(stderr, "[AgenticCmdExec] Finished: exit=%d success=%d\n",
            res.exitCode, res.success ? 1 : 0);

    if (onFinished) onFinished(res.success, res.exitCode);
    return res;
}

std::string AgenticCommandExecutor::getOutput() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_lastOutput;
}

void AgenticCommandExecutor::cancelCommand()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    if (m_processHandle) {
        TerminateProcess(m_processHandle, 1);
        CloseHandle(m_processHandle);
        m_processHandle = nullptr;
        fprintf(stderr, "[AgenticCmdExec] Command cancelled\n");
    }
}

bool AgenticCommandExecutor::isAutoApproved(const std::string& command)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    std::string cmdLower = command;
    std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(),
                  [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    for (const auto& approved : m_autoApproveList) {
        std::string approvedLower = approved;
        std::transform(approvedLower.begin(), approvedLower.end(), approvedLower.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        if (cmdLower.find(approvedLower) != std::string::npos) {
            fprintf(stderr, "[AgenticCmdExec] Auto-approved: %s\n", command.c_str());
            return true;
        }
    }
    return false;
}
=======
#include "agentic/agentic_command_executor.h"
#include <iostream>
#include <thread>
#include <algorithm>

AgenticCommandExecutor::AgenticCommandExecutor() : m_isRunning(false) {
    // Default allowed commands
    m_autoApproveList = {
        "npm test", "cargo check", "pytest", "python -m pytest",
        "cargo build", "make", "cmake --build", "dir", "ls", "echo"
    };
}

AgenticCommandExecutor::~AgenticCommandExecutor() {
    cancelCommand();
}

void AgenticCommandExecutor::setAutoApproveList(const std::vector<std::string> &commands) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_autoApproveList = commands;
}

void AgenticCommandExecutor::executeCommand(const std::string &command, const std::vector<std::string> &arguments, bool requireApproval) {
    std::string fullCommand = command;
    for (const auto& arg : arguments) {
        fullCommand += " " + arg;
    }

    if (requireApproval && !isAutoApproved(fullCommand)) {
        bool approved = false;
        if (m_approvalCb) {
             approved = m_approvalCb(fullCommand);
        } else {
             // Default deny if no callback
             approved = false; 
        }
        
        if (!approved) {
            if (m_finishedCb) m_finishedCb(false, -1);
            return;
        }
    }

    runProcess(fullCommand);
}

void AgenticCommandExecutor::runProcess(std::string cmdLine) {
    SECURITY_ATTRIBUTES saAttr; 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL; 

    if ( ! CreatePipe(&m_hChildStd_OUT_Rd, &m_hChildStd_OUT_Wr, &saAttr, 0) ) 
        return; 

    if ( ! SetHandleInformation(m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
        return; 

    PROCESS_INFORMATION piProcInfo; 
    STARTUPINFOA siStartInfo;
    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
    siStartInfo.cb = sizeof(STARTUPINFO); 
    siStartInfo.hStdError = m_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = m_hChildStd_OUT_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create a mutable copy of the command line
    std::vector<char> cmd(cmdLine.begin(), cmdLine.end());
    cmd.push_back(0);

    // Create the child process. 
    BOOL bSuccess = CreateProcessA(NULL, 
        cmd.data(),     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        CREATE_NO_WINDOW,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 

    if ( ! bSuccess ) return;

    m_hProcess = piProcInfo.hProcess;
    CloseHandle(piProcInfo.hThread);
    CloseHandle(m_hChildStd_OUT_Wr); // Close write end, only child needs it

    m_isRunning = true;
    m_output.clear();

    // Start a thread to read output
    std::thread([this, piProcInfo]() {
        DWORD dwRead; 
        CHAR chBuf[4096]; 
        BOOL bSuccess = FALSE;

        for (;;) { 
            bSuccess = ReadFile( m_hChildStd_OUT_Rd, chBuf, 4096, &dwRead, NULL);
            if( ! bSuccess || dwRead == 0 ) break; 

            std::string s(chBuf, dwRead);
            appendOutput(s);
        } 
        
        WaitForSingleObject(piProcInfo.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
        
        CloseHandle(m_hChildStd_OUT_Rd);
        CloseHandle(piProcInfo.hProcess);
        
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_isRunning = false;
        }

        if (m_finishedCb) m_finishedCb(true, exitCode);

    }).detach();
}

void AgenticCommandExecutor::appendOutput(const std::string& str) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_output += str;
    if (m_outputCb) m_outputCb(str);
}

std::string AgenticCommandExecutor::getOutput() const {
    std::unique_lock<std::mutex> lock(m_mutex);
    return m_output;
}

void AgenticCommandExecutor::cancelCommand() {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_isRunning && m_hProcess) {
        TerminateProcess(m_hProcess, 1);
    }
}

void AgenticCommandExecutor::onOutputReceived(OutputCallback cb) { m_outputCb = cb; }
void AgenticCommandExecutor::onExecutionFinished(StatusCallback cb) { m_finishedCb = cb; }
void AgenticCommandExecutor::setApprovalCallback(ApprovalCallback cb) { m_approvalCb = cb; }

bool AgenticCommandExecutor::isAutoApproved(const std::string &command) {
    std::unique_lock<std::mutex> lock(m_mutex);
    // Rough contains check
    for (const auto& allowed : m_autoApproveList) {
        if (command.find(allowed) != std::string::npos) return true;
    }
    return false;
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
