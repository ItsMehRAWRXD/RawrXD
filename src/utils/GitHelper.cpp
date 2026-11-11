//=============================================================================
// RawrXD Git Helper Implementation
// Zero-dependency git integration using Windows CreateProcess
//=============================================================================
#include "GitHelper.hpp"
#include <windows.h>
#include <array>
#include <sstream>

namespace RawrXD {
namespace Utils {

//=============================================================================
// Private Helpers
//=============================================================================

std::string GitHelper::Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

std::string GitHelper::ExecuteGitCommand(const char* args) {
    // Security attributes for pipe inheritance
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return "";
    }
    
    // Ensure read handle is not inherited by child
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    
    // Setup startup info with redirected stdout
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;  // Redirect stderr too
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;  // Don't show console window
    
    PROCESS_INFORMATION pi = { 0 };
    
    // Build command line
    char cmdLine[512];
    snprintf(cmdLine, sizeof(cmdLine), "git %s", args);
    
    // Create process
    BOOL success = CreateProcessA(
        NULL,           // Application name (use command line)
        cmdLine,        // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        TRUE,           // Inherit handles
        CREATE_NO_WINDOW, // Don't create console window
        NULL,           // Environment
        NULL,           // Current directory (use parent's)
        &si,            // Startup info
        &pi             // Process info
    );
    
    if (!success) {
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return "";
    }
    
    // Close write end in parent (child has it now)
    CloseHandle(hWrite);
    
    // Read output
    std::string output;
    char buffer[256];
    DWORD bytesRead = 0;
    
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    // Cleanup
    WaitForSingleObject(pi.hProcess, 5000);  // Wait up to 5 seconds
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    
    return Trim(output);
}

//=============================================================================
// Public API
//=============================================================================

std::string GitHelper::GetCurrentBranch() {
    std::string result = ExecuteGitCommand("rev-parse --abbrev-ref HEAD");
    if (result.empty()) {
        return "master";  // Fallback
    }
    return result;
}

std::string GitHelper::GetShortCommitHash() {
    std::string result = ExecuteGitCommand("rev-parse --short HEAD");
    if (result.empty()) {
        return "0000000";
    }
    return result;
}

bool GitHelper::IsGitRepository() {
    std::string result = ExecuteGitCommand("rev-parse --git-dir");
    return !result.empty();
}

std::string GitHelper::GetRepositoryRoot() {
    std::string result = ExecuteGitCommand("rev-parse --show-toplevel");
    return result;
}

bool GitHelper::IsWorkingTreeDirty() {
    // git status --porcelain returns empty if clean
    std::string result = ExecuteGitCommand("status --porcelain");
    return !result.empty();
}

std::string GitHelper::GetRemoteStatus() {
    // Get ahead/behind count
    // Format: "+2-1" means 2 commits ahead, 1 behind
    
    std::string ahead = ExecuteGitCommand("rev-list --count HEAD@{upstream}..HEAD");
    std::string behind = ExecuteGitCommand("rev-list --count HEAD..HEAD@{upstream}");
    
    if (ahead.empty() && behind.empty()) {
        return "";  // No upstream or error
    }
    
    int aheadCount = 0, behindCount = 0;
    try {
        if (!ahead.empty()) aheadCount = std::stoi(ahead);
        if (!behind.empty()) behindCount = std::stoi(behind);
    } catch (...) {
        return "";
    }
    
    if (aheadCount == 0 && behindCount == 0) {
        return "";
    }
    
    std::stringstream ss;
    if (aheadCount > 0) ss << "+" << aheadCount;
    if (behindCount > 0) ss << "-" << behindCount;
    return ss.str();
}

} // namespace Utils
} // namespace RawrXD
