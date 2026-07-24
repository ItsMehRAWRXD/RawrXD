// ============================================================================
// ExtensionIsolation.cpp - Extension Process Isolation Implementation
// ============================================================================

#include "ExtensionIsolation.hpp"
#include <cstring>
#include <iostream>
#include <thread>

namespace Sovereign {

ExtensionIsolation::ExtensionIsolation() = default;
ExtensionIsolation::~ExtensionIsolation() {
    Shutdown();
}

bool ExtensionIsolation::Initialize(const ExtensionIsolationConfig& config) {
    config_ = config;
    return true;
}

void ExtensionIsolation::Shutdown() {
    for (auto& [id, ext] : extensions_) {
        if (ext.processHandle) {
            TerminateProcess(ext.processHandle, 0);
            CloseHandle(ext.processHandle);
        }
    }
    extensions_.clear();
}

bool ExtensionIsolation::LaunchExtension(const std::string& id, const std::string& executable) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE stdinRead, stdinWrite;
    HANDLE stdoutRead, stdoutWrite;
    
    CreatePipe(&stdinRead, &stdinWrite, &sa, 0);
    CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0);
    
    STARTUPINFO si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdinRead;
    si.hStdOutput = stdoutWrite;
    si.hStdError = stdoutWrite;
    
    PROCESS_INFORMATION pi;
    std::string cmdLine = executable;
    
    if (CreateProcess(nullptr, &cmdLine[0], nullptr, nullptr, TRUE, 
                      CREATE_NO_WINDOW | (config_.enableProcessIsolation ? 0 : 0),
                      nullptr, nullptr, &si, &pi)) {
        ExtensionProcess ext;
        ext.id = id;
        ext.processHandle = pi.hProcess;
        ext.stdinPipe = stdinWrite;
        ext.stdoutPipe = stdoutRead;
        ext.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ext.restartCount = 0;
        ext.alive = true;
        
        extensions_[id] = ext;
        stats_.totalExtensions++;
        stats_.activeExtensions++;
        
        CloseHandle(pi.hThread);
        CloseHandle(stdinRead);
        CloseHandle(stdoutWrite);
        
        return true;
    }
    
    CloseHandle(stdinRead);
    CloseHandle(stdinWrite);
    CloseHandle(stdoutRead);
    CloseHandle(stdoutWrite);
    return false;
}

bool ExtensionIsolation::TerminateExtension(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    TerminateProcess(it->second.processHandle, 0);
    CloseHandle(it->second.processHandle);
    it->second.alive = false;
    stats_.activeExtensions--;
    
    return true;
}

bool ExtensionIsolation::IsExtensionAlive(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    DWORD exitCode;
    GetExitCodeProcess(it->second.processHandle, &exitCode);
    return exitCode == STILL_ACTIVE;
}

bool ExtensionIsolation::RestartExtension(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = extensions_.find(id);
    if (it == extensions_.end()) return false;
    
    if (it->second.restartCount >= config_.maxRestarts) return false;
    
    std::string executable;
    char filename[MAX_PATH];
    if (GetModuleFileNameEx(it->second.processHandle, nullptr, filename, MAX_PATH)) {
        executable = filename;
    }
    
    TerminateProcess(it->second.processHandle, 0);
    CloseHandle(it->second.processHandle);
    
    it->second.restartCount++;
    stats_.restarts++;
    
    // Relaunch
    return LaunchExtension(id, executable);
}

ExtensionIsolation::IsolationStats ExtensionIsolation::GetStats() const {
    return stats_;
}

} // namespace Sovereign
