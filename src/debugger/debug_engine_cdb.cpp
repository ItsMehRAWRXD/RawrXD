/**
 * @file debug_engine_cdb.cpp
 * @brief CDB (Windows Debugging Tools) Engine Implementation
 * @status PRODUCTION - Real CDB integration via pipes
 */

#include "debug_engine.h"
#include <windows.h>
#include <sstream>
#include <regex>
#include <thread>
#include <atomic>
#include <cstring>

namespace RawrXD::Debugger {

class CDBEngine : public IDebugEngine {
public:
    CDBEngine() : m_process(nullptr), m_thread(nullptr), m_running(false) {}
    
    ~CDBEngine() {
        Shutdown();
    }
    
    bool Initialize(const std::string& executable,
                  const std::string& workingDir,
                  const std::vector<std::string>& args) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Find CDB.exe
        std::string cdbPath = FindCDB();
        if (cdbPath.empty()) {
            OutputDebugStringA("CDB not found in PATH or Windows SDK\n");
            return false;
        }
        
        // Build command line
        std::stringstream cmd;
        cmd << "\"" << cdbPath << "\"";
        cmd << " -g";  // Ignore initial breakpoint
        cmd << " -G";  // Ignore final breakpoint
        cmd << " -lines";  // Enable line number info
        cmd << " -sflags \"0x8000\"";  // Enable source server
        cmd << " \"" << executable << "\"";
        
        for (const auto& arg : args) {
            cmd << " \"" << arg << "\"";
        }
        
        // Create pipes for communication
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        
        HANDLE hStdInRead, hStdInWrite;
        HANDLE hStdOutRead, hStdOutWrite;
        
        if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0) ||
            !CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
            return false;
        }
        
        SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
        
        // Start CDB process
        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdInput = hStdInRead;
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdOutWrite;
        si.wShowWindow = SW_HIDE;
        
        PROCESS_INFORMATION pi = {};
        
        std::string cmdLine = cmd.str();
        
        if (!CreateProcessA(nullptr, const_cast<char*>(cmdLine.c_str()),
                          nullptr, nullptr, TRUE,
                          CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                          nullptr, 
                          workingDir.empty() ? nullptr : workingDir.c_str(),
                          &si, &pi)) {
            CloseHandle(hStdInRead);
            CloseHandle(hStdInWrite);
            CloseHandle(hStdOutRead);
            CloseHandle(hStdOutWrite);
            return false;
        }
        
        m_process = pi.hProcess;
        m_thread = pi.hThread;
        m_hStdIn = hStdInWrite;
        m_hStdOut = hStdOutRead;
        m_running = true;
        m_nextBreakpointId = 1;
        
        // Close inherited handles
        CloseHandle(hStdInRead);
        CloseHandle(hStdOutWrite);
        
        // Resume the process
        ResumeThread(m_thread);
        
        // Start output reader thread
        m_readerThread = std::thread(&CDBEngine::ReaderThread, this);
        
        // Wait for initial prompt
        if (!WaitForPrompt(5000)) {
            Shutdown();
            return false;
        }
        
        // Enable source line debugging
        SendCommand(".lines");
        SendCommand("l+s");  // Source mode on
        SendCommand("l+l");  // Line numbers on
        
        return true;
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_running = false;
        
        if (m_readerThread.joinable()) {
            m_readerThread.join();
        }
        
        if (m_process) {
            TerminateProcess(m_process, 1);
            CloseHandle(m_process);
            m_process = nullptr;
        }
        
        if (m_thread) {
            CloseHandle(m_thread);
            m_thread = nullptr;
        }
        
        if (m_hStdIn) {
            CloseHandle(m_hStdIn);
            m_hStdIn = nullptr;
        }
        
        if (m_hStdOut) {
            CloseHandle(m_hStdOut);
            m_hStdOut = nullptr;
        }
    }
    
    bool IsRunning() const override {
        if (!m_process) return false;
        
        DWORD exitCode;
        if (!GetExitCodeProcess(m_process, &exitCode)) {
            return false;
        }
        return exitCode == STILL_ACTIVE;
    }
    
    bool Continue() override {
        return SendCommand("g");
    }
    
    bool StepInto() override {
        return SendCommand("t");
    }
    
    bool StepOver() override {
        return SendCommand("p");
    }
    
    bool StepOut() override {
        return SendCommand("gu");  // Go up
    }
    
    bool Pause() override {
        if (!m_process) return false;
        return DebugBreakProcess(m_process) != 0;
    }
    
    bool Stop() override {
        return SendCommand("q");
    }
    
    uint32_t SetBreakpoint(const std::string& file, uint32_t line,
                          const std::string& condition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        uint32_t id = m_nextBreakpointId++;
        
        Breakpoint bp;
        bp.id = id;
        bp.file = file;
        bp.line = line;
        bp.condition = condition;
        bp.hitCount = 0;
        bp.hitTarget = 0;
        bp.state = BreakpointState::Unresolved;
        bp.address = 0;
        
        // Set breakpoint using CDB syntax
        std::stringstream cmd;
        cmd << "bp `\"" << file << \":" << line << "`\"";
        
        if (!condition.empty()) {
            cmd << " \"" << condition << "\"";
        }
        
        std::string response = SendCommandAndWait(cmd.str());
        
        // Parse response for breakpoint number
        std::regex bpRegex(R"(breakpoint\s+(\d+)\s+at)");
        std::smatch match;
        if (std::regex_search(response, match, bpRegex)) {
            bp.state = BreakpointState::Resolved;
        }
        
        m_breakpoints[id] = bp;
        return id;
    }
    
    bool RemoveBreakpoint(uint32_t id) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_breakpoints.find(id);
        if (it == m_breakpoints.end()) return false;
        
        std::stringstream cmd;
        cmd << "bc " << id;
        SendCommand(cmd.str());
        
        m_breakpoints.erase(it);
        return true;
    }
    
    bool EnableBreakpoint(uint32_t id, bool enable) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_breakpoints.find(id);
        if (it == m_breakpoints.end()) return false;
        
        std::stringstream cmd;
        if (enable) {
            cmd << "be " << id;
            it->second.state = BreakpointState::Resolved;
        } else {
            cmd << "bd " << id;
            it->second.state = BreakpointState::Disabled;
        }
        
        return SendCommand(cmd.str());
    }
    
    std::vector<Breakpoint> GetBreakpoints() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        std::vector<Breakpoint> result;
        for (const auto& [id, bp] : m_breakpoints) {
            result.push_back(bp);
        }
        return result;
    }
    
    std::vector<StackFrame> GetStackTrace(uint32_t threadId) override {
        std::string response = SendCommandAndWait("k");
        
        std::vector<StackFrame> frames;
        std::istringstream stream(response);
        std::string line;
        
        // Parse CDB stack trace output
        std::regex frameRegex(R"(\s*(\d+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s+\[(.+):(\d+)\])");
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_match(line, match, frameRegex)) {
                StackFrame frame;
                frame.level = std::stoul(match[1]);
                frame.address = std::stoull(match[2], nullptr, 16);
                frame.function = match[4];
                frame.file = match[5];
                frame.line = std::stoul(match[6]);
                frames.push_back(frame);
            }
        }
        
        return frames;
    }
    
    Variable EvaluateExpression(const std::string& expr, uint32_t frameLevel) override {
        std::stringstream cmd;
        cmd << ".frame " << frameLevel << "; ?? " << expr;
        
        std::string response = SendCommandAndWait(cmd.str());
        
        Variable var;
        var.name = expr;
        
        // Parse CDB output: "type var = value"
        std::regex evalRegex(R"((\S+)\s+(\S+)\s*=\s*(.+))");
        std::smatch match;
        if (std::regex_search(response, match, evalRegex)) {
            var.type = match[1];
            var.value = match[3];
        } else {
            var.value = response;
        }
        
        return var;
    }
    
    std::vector<Variable> GetLocals(uint32_t frameLevel) override {
        std::stringstream cmd;
        cmd << ".frame " << frameLevel << "; dv";
        
        std::string response = SendCommandAndWait(cmd.str());
        
        std::vector<Variable> locals;
        std::istringstream stream(response);
        std::string line;
        
        // Parse: "type name = value"
        std::regex localRegex(R"(\s*(\S+)\s+(\S+)\s*=\s*(.*))");
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_match(line, match, localRegex)) {
                Variable var;
                var.type = match[1];
                var.name = match[2];
                var.value = match[3];
                var.hasChildren = (var.type.find("*") != std::string::npos ||
                                  var.type.find("struct") != std::string::npos);
                locals.push_back(var);
            }
        }
        
        return locals;
    }
    
    std::vector<ThreadInfo> GetThreads() override {
        std::string response = SendCommandAndWait("~");
        
        std::vector<ThreadInfo> threads;
        std::istringstream stream(response);
        std::string line;
        
        // Parse: ". 0 Id: ..."
        std::regex threadRegex(R"(~(\d+)\s+(\S+)\s+Id:\s+(\S+)\s+(.+))");
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_match(line, match, threadRegex)) {
                ThreadInfo thread;
                thread.id = std::stoul(match[1]);
                thread.state = match[2];
                thread.name = match[4];
                threads.push_back(thread);
            }
        }
        
        return threads;
    }
    
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) override {
        std::stringstream cmd;
        cmd << "db " << std::hex << address << " L" << std::dec << size;
        
        std::string response = SendCommandAndWait(cmd.str());
        
        std::vector<uint8_t> data;
        // Parse hex dump
        std::regex byteRegex(R"([0-9a-fA-F]{2})");
        auto begin = std::sregex_iterator(response.begin(), response.end(), byteRegex);
        auto end = std::sregex_iterator();
        
        for (auto it = begin; it != end && data.size() < size; ++it) {
            data.push_back(static_cast<uint8_t>(std::stoul(it->str(), nullptr, 16)));
        }
        
        return data;
    }
    
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data) override {
        std::stringstream cmd;
        cmd << "eb " << std::hex << address;
        for (auto b : data) {
            cmd << " " << std::hex << (int)b;
        }
        
        return SendCommand(cmd.str());
    }
    
    void SetEventCallback(std::function<void(const DebugEvent&)> callback) override {
        m_eventCallback = callback;
    }
    
    std::string Disassemble(uint64_t address, size_t count) override {
        std::stringstream cmd;
        cmd << "u " << std::hex << address << " L" << std::dec << count;
        return SendCommandAndWait(cmd.str());
    }

private:
    std::string FindCDB() {
        // Check common locations
        const char* paths[] = {
            "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe",
            "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe",
            "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\cdb.exe",
            "C:\\Program Files\\Debugging Tools for Windows (x64)\\cdb.exe",
            "C:\\Program Files\\Debugging Tools for Windows\\cdb.exe"
        };
        
        for (const auto& path : paths) {
            if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
                return path;
            }
        }
        
        // Try PATH
        char pathBuffer[MAX_PATH];
        if (SearchPathA(nullptr, "cdb.exe", nullptr, MAX_PATH, pathBuffer, nullptr)) {
            return pathBuffer;
        }
        
        return "";
    }
    
    bool SendCommand(const std::string& cmd) {
        if (!m_hStdIn) return false;
        
        std::string fullCmd = cmd + "\n";
        DWORD written;
        return WriteFile(m_hStdIn, fullCmd.c_str(), 
                        static_cast<DWORD>(fullCmd.length()), &written, nullptr) != 0;
    }
    
    std::string SendCommandAndWait(const std::string& cmd) {
        std::unique_lock<std::mutex> lock(m_outputMutex);
        m_lastOutput.clear();
        
        if (!SendCommand(cmd)) {
            return "";
        }
        
        // Wait for prompt
        m_outputCV.wait_for(lock, std::chrono::seconds(5), [this]() {
            return m_lastOutput.find("0:000>") != std::string::npos ||
                   m_lastOutput.find("1:000>") != std::string::npos;
        });
        
        return m_lastOutput;
    }
    
    bool WaitForPrompt(DWORD timeoutMs) {
        std::unique_lock<std::mutex> lock(m_outputMutex);
        return m_outputCV.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this]() {
            return m_lastOutput.find("0:000>") != std::string::npos ||
                   m_lastOutput.find("1:000>") != std::string::npos;
        });
    }
    
    void ReaderThread() {
        char buffer[4096];
        DWORD bytesRead;
        
        while (m_running && m_hStdOut) {
            if (ReadFile(m_hStdOut, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                
                {
                    std::lock_guard<std::mutex> lock(m_outputMutex);
                    m_lastOutput += buffer;
                }
                
                // Check for events
                ParseEvents(buffer);
                
                m_outputCV.notify_all();
            }
        }
    }
    
    void ParseEvents(const std::string& output) {
        if (!m_eventCallback) return;
        
        // Check for breakpoint hit
        if (output.find("Breakpoint ") != std::string::npos && 
            output.find("hit") != std::string::npos) {
            DebugEvent evt;
            evt.type = DebugEventType::BreakpointHit;
            evt.description = output;
            m_eventCallback(evt);
        }
        
        // Check for exception
        if (output.find("Exception ") != std::string::npos ||
            output.find("Access violation") != std::string::npos) {
            DebugEvent evt;
            evt.type = DebugEventType::Exception;
            evt.description = output;
            m_eventCallback(evt);
        }
        
        // Check for process exit
        if (output.find("exited") != std::string::npos) {
            DebugEvent evt;
            evt.type = DebugEventType::ProcessExited;
            evt.description = output;
            m_eventCallback(evt);
        }
    }
    
    HANDLE m_process;
    HANDLE m_thread;
    HANDLE m_hStdIn;
    HANDLE m_hStdOut;
    std::atomic<bool> m_running;
    std::thread m_readerThread;
    
    mutable std::mutex m_mutex;
    std::map<uint32_t, Breakpoint> m_breakpoints;
    uint32_t m_nextBreakpointId;
    
    std::mutex m_outputMutex;
    std::condition_variable m_outputCV;
    std::string m_lastOutput;
    
    std::function<void(const DebugEvent&)> m_eventCallback;
};

// Factory registration
std::unique_ptr<IDebugEngine> CreateCDBEngine() {
    return std::make_unique<CDBEngine>();
}

} // namespace RawrXD::Debugger
